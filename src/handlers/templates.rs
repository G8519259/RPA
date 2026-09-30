//! P5 —— 订阅模板管理（§12）。
//!
//! - GET    /api/templates
//! - POST   /api/templates
//! - POST   /api/templates/validate
//! - GET    /api/templates/{id}
//! - PUT    /api/templates/{id}
//! - DELETE /api/templates/{id}
//! - POST   /api/templates/{id}/duplicate
//! - POST   /api/templates/{id}/preview

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{ApiResp, SubTemplate};
use crate::services::export::template::{preview_render, validate_template};
use crate::state::AppState;
use crate::util::client_ip;

fn validate_name(name: &str) -> AppResult<()> {
    let t = name.trim();
    if t.is_empty() || t.chars().count() > 100 {
        return Err(AppError::bad("名称不能为空且不超过 100 字符"));
    }
    Ok(())
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/templates")
            .route("", web::get().to(list))
            .route("", web::post().to(create))
            .route("/validate", web::post().to(validate))
            .route("/preview_raw", web::post().to(preview_raw))
            .route("/{id}", web::get().to(detail))
            .route("/{id}", web::put().to(update))
            .route("/{id}", web::delete().to(delete))
            .route("/{id}/duplicate", web::post().to(duplicate))
            .route("/{id}/preview", web::post().to(preview)),
    );
}

#[derive(Deserialize)]
pub struct TemplateUpsert {
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct ValidateReq {
    pub format: String,
    pub content: String,
}

#[derive(serde::Serialize, sqlx::FromRow)]
struct TemplateListItem {
    id: i64,
    name: String,
    description: Option<String>,
    format: String,
    is_builtin: i64,
    used_by: i64,
    created_at: String,
    updated_at: String,
}

async fn list(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    let items: Vec<TemplateListItem> = sqlx::query_as(
        r#"SELECT t.id, t.name, t.description, t.format, t.is_builtin,
                  (SELECT COUNT(*) FROM subscriptions s WHERE s.template_id = t.id) AS used_by,
                  t.created_at, t.updated_at
           FROM sub_templates t ORDER BY t.is_builtin DESC, t.id"#,
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(items)))
}

fn check_valid(format: &str, content: &str) -> AppResult<()> {
    let errs = validate_template(content, format);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(AppError::bad(format!("模板校验失败：\n{}", errs.join("\n"))))
    }
}

async fn create(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<TemplateUpsert>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let b = body.into_inner();
    validate_name(&b.name)?;
    check_valid(&b.format, &b.content)?;

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_templates WHERE name = ?")
        .bind(b.name.trim())
        .fetch_one(&state.pool)
        .await?;
    if n > 0 {
        return Err(AppError::bad("模板名称已存在"));
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO sub_templates (name, description, format, content, is_builtin)
         VALUES (?, ?, ?, ?, 0) RETURNING id",
    )
    .bind(b.name.trim())
    .bind(b.description.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(b.format.trim())
    .bind(b.content)
    .fetch_one(&state.pool)
    .await?;

    audit(
        &state.pool, Some(user.id), &user.username, "create_template",
        None, Some(id), None, serde_json::json!({"name": b.name}), &ip,
    )
    .await;
    let t = detail_one(&state.pool, id).await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(t)))
}

async fn validate(body: web::Json<ValidateReq>) -> AppResult<HttpResponse> {
    let errs = validate_template(&body.content, &body.format);
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "valid": errs.is_empty(),
        "errors": errs,
    }))))
}

async fn detail_one(pool: &sqlx::SqlitePool, id: i64) -> AppResult<SubTemplate> {
    let t: Option<SubTemplate> =
        sqlx::query_as("SELECT * FROM sub_templates WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    t.ok_or_else(|| AppError::not_found("模板不存在"))
}

async fn detail(state: web::Data<AppState>, path: web::Path<i64>) -> AppResult<HttpResponse> {
    let t = detail_one(&state.pool, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(t)))
}

async fn update(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<TemplateUpsert>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();
    let old = detail_one(&state.pool, id).await?;
    if old.is_builtin == 1 {
        return Err(AppError::bad("内置模板不可修改，可复制为新模板后编辑"));
    }
    validate_name(&b.name)?;
    check_valid(&b.format, &b.content)?;
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sub_templates WHERE name = ? AND id != ?")
            .bind(b.name.trim())
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    if n > 0 {
        return Err(AppError::bad("模板名称已存在"));
    }
    sqlx::query(
        "UPDATE sub_templates SET name = ?, description = ?, format = ?, content = ?,
         updated_at = datetime('now') WHERE id = ?",
    )
    .bind(b.name.trim())
    .bind(b.description.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(b.format.trim())
    .bind(&b.content)
    .bind(id)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool, Some(user.id), &user.username, "update_template",
        None, Some(id), None, serde_json::json!({"name": b.name}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(detail_one(&state.pool, id).await?)))
}

async fn delete(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let old = detail_one(&state.pool, id).await?;
    if old.is_builtin == 1 {
        return Err(AppError::bad("内置模板不可删除"));
    }
    let used: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM subscriptions WHERE template_id = ?",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    if !used.is_empty() {
        let names: Vec<String> = used.iter().map(|(_, n)| n.clone()).collect();
        return Err(AppError::bad(format!(
            "有 {} 个订阅正在使用该模板，无法删除：{}",
            used.len(),
            names.join("、")
        )));
    }
    sqlx::query("DELETE FROM sub_templates WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool, Some(user.id), &user.username, "delete_template",
        None, Some(id), None, serde_json::json!({"name": old.name}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"deleted": id}))))
}

async fn duplicate(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let old = detail_one(&state.pool, id).await?;
    let mut name = format!("{}（副本）", old.name);
    let mut i = 2;
    while sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sub_templates WHERE name = ?")
        .bind(&name)
        .fetch_one(&state.pool)
        .await?
        > 0
    {
        name = format!("{}（副本{i}）", old.name);
        i += 1;
    }
    let new_id: i64 = sqlx::query_scalar(
        "INSERT INTO sub_templates (name, description, format, content, is_builtin)
         VALUES (?, ?, ?, ?, 0) RETURNING id",
    )
    .bind(&name)
    .bind(old.description.as_deref())
    .bind(&old.format)
    .bind(&old.content)
    .fetch_one(&state.pool)
    .await?;
    audit(
        &state.pool, Some(user.id), &user.username, "duplicate_template",
        None, Some(new_id), None, serde_json::json!({"from": id, "name": name}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(detail_one(&state.pool, new_id).await?)))
}

async fn preview(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let t = detail_one(&state.pool, path.into_inner()).await?;
    let content = preview_render(&t.content, &t.format)?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "content": content }))))
}

async fn preview_raw(body: web::Json<ValidateReq>) -> AppResult<HttpResponse> {
    let content = preview_render(&body.content, &body.format)?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "content": content }))))
}
