//! P10 —— 服务器节点管理 API
//!
//! - GET    /api/nodes
//! - POST   /api/nodes（生成 api_token，返回 Worker 启动命令，仅此次可见）
//! - PUT    /api/nodes/{id}
//! - POST   /api/nodes/{id}/reset_token
//! - DELETE /api/nodes/{id}

use actix_web::{HttpRequest, HttpResponse, web};
use rand::TryRngCore;
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::ApiResp;
use crate::state::AppState;
use crate::util::client_ip;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/nodes")
            .route("", web::get().to(list))
            .route("", web::post().to(create))
            .route("/{id}", web::put().to(update))
            .route("/{id}", web::delete().to(delete))
            .route("/{id}/reset_token", web::post().to(reset_token)),
    );
}

fn gen_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut b).expect("OsRng 失败");
    hex::encode(b)
}

/// Worker 启动命令（token 仅在创建 / 重置时返回一次）
fn worker_cmd(master: &str, token: &str) -> String {
    format!("rust_proxy_admin --mode worker --master {master} --token {token}")
}

pub async fn list(
    state: web::Data<AppState>,
    req: HttpRequest,
    q: web::Query<crate::models::ListQuery>,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let page = q.page.unwrap_or(1).max(1);
    let ps = q.page_size.unwrap_or(20).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
        .fetch_one(&state.pool)
        .await?;
    let rows: Vec<serde_json::Value> = sqlx::query_as::<_, (
        i64, String, i64, Option<String>, Option<String>, i64, Option<String>, Option<String>,
        Option<String>, Option<String>, String,
    )>(
        "SELECT id, name, is_local, addr, public_host, enabled, meta, version,
                last_heartbeat_at, last_load, online_state
         FROM nodes ORDER BY id LIMIT ? OFFSET ?",
    )
    .bind(ps)
    .bind((page - 1) * ps)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(
        |(id, name, is_local, addr, public_host, enabled, meta, version, hb, load, ostate)| {
            serde_json::json!({
                "id": id, "name": name, "is_local": is_local, "addr": addr,
                "public_host": public_host, "enabled": enabled, "meta": meta,
                "version": version, "last_heartbeat_at": hb, "last_load": load,
                "online_state": ostate,
            })
        },
    )
    .collect();
    Ok(HttpResponse::Ok().json(ApiResp::ok(crate::models::Page { items: rows, total, page, page_size: ps })))
}

#[derive(Deserialize)]
pub struct CreateReq {
    pub name: String,
    pub public_host: Option<String>,
    pub meta: Option<String>,
    /// Master 公网地址，用于生成 Worker 启动命令中的 --master
    pub master_url: Option<String>,
}

pub async fn create(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CreateReq>,
) -> AppResult<HttpResponse> {

    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(AppError::bad("节点名称 1~64 字符"));
    }
    let token = gen_token();
    let r = sqlx::query(
        "INSERT INTO nodes (name, is_local, public_host, api_token, meta) VALUES (?, 0, ?, ?, ?)",
    )
    .bind(name)
    .bind(body.public_host.as_deref())
    .bind(&token)
    .bind(body.meta.as_deref())
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::bad("节点名称已存在")
        } else {
            AppError::from(e)
        }
    })?;
    let id = r.last_insert_rowid();
    let master_url = body.master_url.as_deref().unwrap_or("https://admin.example.com");
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "create",
        Some("node"),
        Some(id),
        None,
        serde_json::json!({ "name": name }),
        &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "id": id,
        "worker_cmd": worker_cmd(master_url, &token),
        "note": "token 仅显示这一次，请妥善保存；之后只能重置",
    }))))
}

#[derive(Deserialize)]
pub struct UpdateReq {
    pub name: Option<String>,
    pub public_host: Option<String>,
    pub meta: Option<String>,
    pub enabled: Option<i64>,
}

pub async fn update(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<UpdateReq>,
) -> AppResult<HttpResponse> {

    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let is_local: Option<i64> = sqlx::query_scalar("SELECT is_local FROM nodes WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    if is_local.is_none() {
        return Err(AppError::not_found("节点不存在"));
    }
    if let Some(n) = body.name.as_deref() {
        let n = n.trim();
        if n.is_empty() || n.len() > 64 {
            return Err(AppError::bad("节点名称 1~64 字符"));
        }
        sqlx::query("UPDATE nodes SET name = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(n)
            .bind(id)
            .execute(&state.pool)
            .await
            .map_err(|e| {
                if e.to_string().contains("UNIQUE") {
                    AppError::bad("节点名称已存在")
                } else {
                    AppError::from(e)
                }
            })?;
    }
    if let Some(h) = body.public_host.as_deref() {
        sqlx::query("UPDATE nodes SET public_host = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(h)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    if let Some(m) = body.meta.as_deref() {
        sqlx::query("UPDATE nodes SET meta = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(m)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    if let Some(e) = body.enabled {
        sqlx::query("UPDATE nodes SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(if e == 1 { 1 } else { 0 })
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "update",
        Some("node"),
        Some(id),
        None,
        serde_json::to_value(&serde_json::json!({ "req": "update" })).unwrap(),
        &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

#[derive(Deserialize)]
pub struct ResetTokenReq {
    pub master_url: Option<String>,
}

pub async fn reset_token(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<ResetTokenReq>,
) -> AppResult<HttpResponse> {

    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM nodes WHERE id = ? AND is_local = 0")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_none() {
        return Err(AppError::not_found("节点不存在或为本机节点"));
    }
    let token = gen_token();
    sqlx::query("UPDATE nodes SET api_token = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(&token)
        .bind(id)
        .execute(&state.pool)
        .await?;
    let master_url = body.master_url.as_deref().unwrap_or("https://admin.example.com");
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "reset_token",
        Some("node"),
        Some(id),
        None,
        serde_json::json!({}),
        &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "id": id,
        "worker_cmd": worker_cmd(master_url, &token),
        "note": "旧 token 已失效，Worker 需用新命令重启",
    }))))
}

pub async fn delete(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {

    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let is_local: Option<i64> = sqlx::query_scalar("SELECT is_local FROM nodes WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    match is_local {
        None => return Err(AppError::not_found("节点不存在")),
        Some(1) => return Err(AppError::bad("不能删除本机节点")),
        _ => {}
    }
    sqlx::query("DELETE FROM nodes WHERE id = ?").bind(id).execute(&state.pool).await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "delete",
        Some("node"),
        Some(id),
        None,
        serde_json::json!({}),
        &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}
