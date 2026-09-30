use crate::error::AppError;
use crate::models::User;
use crate::state::AppState;
use crate::util::TIME_FMT;
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web, Error, HttpMessage, HttpResponse,
};
use chrono::{Duration, Utc};

/// 请求中携带的已认证用户
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub csrf_token: String,
    pub session_id: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

fn is_public_path(path: &str) -> bool {
    path == "/health"
        || path == "/api/auth/login"
        || path == "/admin/login"
        || path.starts_with("/sub/")
        || path.starts_with("/internal/")
        || path.starts_with("/static/")
}

/// 统一认证 / CSRF 中间件
pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let path = req.path().to_string();
    let method = req.method().clone();

    // 公开路径直接放行（/internal/* 由各 handler 自行做 Bearer 校验）
    if is_public_path(&path) {
        return next.call(req).await;
    }

    let state = req
        .app_data::<web::Data<AppState>>()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("state missing"))?;
    let cfg = &state.cfg;

    // 取会话
    let sid = req
        .cookie("sid")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    let user: Option<AuthUser> = if sid.is_empty() {
        None
    } else {
        load_session(&state, &sid).await
    };

    let Some(user) = user else {
        // 未登录：页面重定向到登录页，API 返回 401
        if path.starts_with("/admin/") {
            let resp = HttpResponse::Found()
                .insert_header((header::LOCATION, "/admin/login"))
                .finish();
            return Ok(req.into_response(resp.map_into_boxed_body()));
        }
        let resp = HttpResponse::Unauthorized().json(serde_json::json!({
            "ok": false, "data": null, "error": "未登录或会话已过期"
        }));
        return Ok(req.into_response(resp.map_into_boxed_body()));
    };

    // 滑动续期
    touch_session(&state, &user.session_id, cfg.server.session_hours).await;

    // viewer 只读：写操作一律 403（admin 不受影响）
    let is_write = matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH");
    if is_write && !user.is_admin() {
        let allowed = path == "/api/auth/logout"
            || path == "/api/auth/logout_all"
            || path == "/api/auth/change_password";
        if !allowed {
            let resp = HttpResponse::Forbidden().json(serde_json::json!({
                "ok": false, "data": null, "error": "只读账户无权执行写操作"
            }));
            return Ok(req.into_response(resp.map_into_boxed_body()));
        }
    }

    // CSRF：/api/* 写操作要求 X-CSRF-Token（登录接口除外）
    if is_write && path.starts_with("/api/") && path != "/api/auth/login" {
        let token = req
            .headers()
            .get("X-CSRF-Token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if token != user.csrf_token {
            let resp = HttpResponse::Forbidden().json(serde_json::json!({
                "ok": false, "data": null, "error": "CSRF 校验失败"
            }));
            return Ok(req.into_response(resp.map_into_boxed_body()));
        }
    }

    req.extensions_mut().insert(user);
    next.call(req).await
}

async fn load_session(state: &AppState, sid: &str) -> Option<AuthUser> {
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT csrf_token, user_id, id FROM sessions WHERE id = ? AND expires_at > datetime('now')",
    )
    .bind(sid)
    .fetch_optional(&state.pool)
    .await
    .ok()?;
    let (csrf_token, user_id, session_id) = row?;
    let u: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await
        .ok()?;
    let u = u?;
    Some(AuthUser {
        id: u.id,
        username: u.username,
        role: u.role,
        csrf_token,
        session_id,
    })
}

async fn touch_session(state: &AppState, sid: &str, hours: i64) {
    let exp = (Utc::now() + Duration::hours(hours))
        .format(TIME_FMT)
        .to_string();
    let _ = sqlx::query("UPDATE sessions SET expires_at = ? WHERE id = ?")
        .bind(exp)
        .bind(sid)
        .execute(&state.pool)
        .await;
}

/// 从请求扩展中取当前用户（handler 内使用）
pub fn auth_user(req: &actix_web::HttpRequest) -> Result<AuthUser, AppError> {
    req.extensions()
        .get::<AuthUser>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized("未登录"))
}

/// 要求管理员权限
pub fn require_admin(user: &AuthUser) -> Result<(), AppError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(AppError::forbidden("需要管理员权限"))
    }
}

/// 登录失败计数（内存）
#[derive(Default)]
pub struct LoginGuard {
    pub fails: std::collections::HashMap<String, (u32, chrono::DateTime<Utc>)>,
}

impl LoginGuard {
    pub fn check(&self, ip: &str, max_fail: i64) -> Result<(), String> {
        if let Some((n, until)) = self.fails.get(ip) {
            if *n as i64 >= max_fail && Utc::now() < *until {
                let secs = (*until - Utc::now()).num_seconds().max(1);
                return Err(format!("登录失败次数过多，已锁定 {secs} 秒"));
            }
        }
        Ok(())
    }
    pub fn record_fail(&mut self, ip: &str, max_fail: i64, lock_minutes: i64) {
        let e = self.fails.entry(ip.to_string()).or_insert((0, Utc::now()));
        e.0 += 1;
        if e.0 as i64 >= max_fail {
            e.1 = Utc::now() + Duration::minutes(lock_minutes);
        }
    }
    pub fn record_ok(&mut self, ip: &str) {
        self.fails.remove(ip);
    }
}
