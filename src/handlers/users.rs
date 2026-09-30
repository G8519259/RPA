//! P13 —— 多用户管理（仅 admin 可操作）
//!
//! - GET    /api/users          用户列表
//! - POST   /api/users          新建用户 {username, password, role}
//! - PUT    /api/users/{id}     修改角色 / 重置密码（不能改自己的角色）
//! - DELETE /api/users/{id}     删除用户（不能删自己、不能删除最后一个 admin）

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{ApiResp, User};
use crate::util::{client_ip, hash_password};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/users")
            .route("", web::get().to(list))
            .route("", web::post().to(create))
            .route("/{id}", web::put().to(update))
            .route("/{id}", web::delete().to(delete)),
    );
}

fn require_admin(req: &HttpRequest) -> AppResult<crate::middleware::AuthUser> {
    let user = auth_user(req)?;
    if !user.is_admin() {
        return Err(AppError::forbidden("需要管理员权限"));
    }
    Ok(user)
}

async fn list(state: web::Data<crate::state::AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_admin(&req)?;
    let rows: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(&state.pool)
        .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(rows)))
}

#[derive(Deserialize)]
pub struct CreateBody {
    pub username: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "viewer".to_string()
}

fn check_role(role: &str) -> AppResult<()> {
    if !matches!(role, "admin" | "viewer") {
        return Err(AppError::bad("role 只能是 admin 或 viewer"));
    }
    Ok(())
}

fn check_password(pw: &str) -> AppResult<()> {
    if pw.chars().count() < 8 {
        return Err(AppError::bad("密码至少 8 位"));
    }
    Ok(())
}

async fn create(
    state: web::Data<crate::state::AppState>,
    req: HttpRequest,
    body: web::Json<CreateBody>,
) -> AppResult<HttpResponse> {
    let user = require_admin(&req)?;
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(AppError::bad("用户名不能为空且不超过 64 字符"));
    }
    check_password(&body.password)?;
    check_role(&body.role)?;
    let hash = hash_password(&body.password).map_err(|e| AppError::internal(e.to_string()))?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(username)
    .bind(&hash)
    .bind(&body.role)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::bad("用户名已存在")
        } else {
            e.into()
        }
    })?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "user_create",
        Some("users"),
        Some(id),
        None,
        serde_json::json!({"username": username, "role": body.role}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

#[derive(Deserialize)]
pub struct UpdateBody {
    pub role: Option<String>,
    pub password: Option<String>,
}

async fn update(
    state: web::Data<crate::state::AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<UpdateBody>,
) -> AppResult<HttpResponse> {
    let user = require_admin(&req)?;
    let id = path.into_inner();
    let target: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let target = target.ok_or_else(|| AppError::not_found("用户不存在"))?;

    if let Some(role) = &body.role {
        check_role(role)?;
        if id == user.id && role != "admin" {
            return Err(AppError::bad("不能把自己的角色降为 viewer"));
        }
        if target.role == "admin" && role == "viewer" {
            let admins: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                    .fetch_one(&state.pool)
                    .await?;
            if admins <= 1 {
                return Err(AppError::bad("不能降级最后一个管理员"));
            }
        }
        sqlx::query("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(role)
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    if let Some(pw) = &body.password {
        if !pw.is_empty() {
            check_password(pw)?;
            let hash = hash_password(pw).map_err(|e| AppError::internal(e.to_string()))?;
            sqlx::query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
                .bind(&hash)
                .bind(id)
                .execute(&state.pool)
                .await?;
            // 重置他人密码后使其会话失效
            if id != user.id {
                sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                    .bind(id)
                    .execute(&state.pool)
                    .await?;
            }
        }
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "user_update",
        Some("users"),
        Some(id),
        None,
        serde_json::json!({"username": target.username}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

async fn delete(
    state: web::Data<crate::state::AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = require_admin(&req)?;
    let id = path.into_inner();
    if id == user.id {
        return Err(AppError::bad("不能删除自己"));
    }
    let target: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let target = target.ok_or_else(|| AppError::not_found("用户不存在"))?;
    if target.role == "admin" {
        let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            .fetch_one(&state.pool)
            .await?;
        if admins <= 1 {
            return Err(AppError::bad("不能删除最后一个管理员"));
        }
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "user_delete",
        Some("users"),
        Some(id),
        None,
        serde_json::json!({"username": target.username}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}
