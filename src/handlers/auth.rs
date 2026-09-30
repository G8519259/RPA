use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{ApiResp, ChangePasswordReq, ChangeUsernameReq, LoginReq, User};
use crate::state::AppState;
use crate::util::{client_ip, hash_password, now_str, random_token, verify_password, TIME_FMT};
use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/login", web::post().to(login))
        .route("/logout", web::post().to(logout))
        .route("/logout_all", web::post().to(logout_all))
        .route("/me", web::get().to(me))
        .route("/change_password", web::post().to(change_password))
        .route("/change_username", web::post().to(change_username));
}

fn session_cookie(sid: &str, secure: bool, hours: i64) -> String {
    let mut c = format!(
        "sid={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        hours * 3600
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// POST /api/auth/login
async fn login(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<LoginReq>,
) -> AppResult<HttpResponse> {
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let (max_fail, lock_minutes) = (
        state.cfg.auth.login_max_fail,
        state.cfg.auth.login_lock_minutes,
    );

    // 锁定检查
    {
        let guard = state.login_guard.lock().await;
        if let Err(msg) = guard.check(&ip, max_fail) {
            return Err(AppError::forbidden(msg));
        }
    }

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(body.username.trim())
        .fetch_optional(&state.pool)
        .await?;

    let ok = user
        .as_ref()
        .map(|u| verify_password(&body.password, &u.password_hash))
        .unwrap_or(false);

    if !ok {
        {
            let mut guard = state.login_guard.lock().await;
            guard.record_fail(&ip, max_fail, lock_minutes);
        }
        audit(
            &state.pool,
            None,
            &body.username,
            "login_fail",
            Some("users"),
            None,
            None,
            serde_json::json!({"username": body.username}),
            &ip,
        )
        .await;
        // 达到阈值时触发告警事件
        let n = {
            let guard = state.login_guard.lock().await;
            guard.fails.get(&ip).map(|(n, _)| *n).unwrap_or(0)
        };
        if n as i64 >= max_fail {
            let base = state.cfg.server.public_base_url.clone();
            let _ = crate::services::alert::emit(
                &state.pool,
                crate::services::alert::AlertDraft::login_fail_burst(&ip, n as i64, lock_minutes, &base),
            )
            .await;
        }
        // 故意不区分用户名/密码错误
        return Err(AppError::unauthorized("用户名或密码错误"));
    }
    let user = user.unwrap();
    {
        let mut guard = state.login_guard.lock().await;
        guard.record_ok(&ip);
    }

    let sid = random_token(32);
    let csrf = random_token(32);
    let exp = (Utc::now() + Duration::hours(state.cfg.server.session_hours))
        .format(TIME_FMT)
        .to_string();
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, csrf_token, ip_addr, user_agent, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&sid)
    .bind(user.id)
    .bind(&csrf)
    .bind(&ip)
    .bind(&ua)
    .bind(&exp)
    .bind(now_str())
    .execute(&state.pool)
    .await?;

    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "login",
        Some("users"),
        Some(user.id),
        None,
        serde_json::json!({}),
        &ip,
    )
    .await;

    // 是否仍是默认密码 → 前端提示
    let is_default = verify_password("ChangeMe123!", &user.password_hash);
    Ok(HttpResponse::Ok()
        .insert_header((
            "Set-Cookie",
            session_cookie(&sid, state.cfg.server.cookie_secure, state.cfg.server.session_hours),
        ))
        .json(ApiResp::ok(serde_json::json!({
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "csrf_token": csrf,
            "is_default_password": is_default,
        }))))
}

/// POST /api/auth/logout
async fn logout(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(&user.session_id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "logout",
        None,
        None,
        None,
        serde_json::json!({}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok()
        .insert_header(("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"))
        .json(ApiResp::ok(serde_json::json!({}))))
}

/// POST /api/auth/logout_all
async fn logout_all(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "logout_all",
        None,
        None,
        None,
        serde_json::json!({}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok()
        .insert_header(("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"))
        .json(ApiResp::ok(serde_json::json!({}))))
}

/// GET /api/auth/me
async fn me(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let u: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
    let is_default = verify_password("ChangeMe123!", &u.password_hash);
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "csrf_token": user.csrf_token,
        "is_default_password": is_default,
    }))))
}

/// POST /api/auth/change_password
async fn change_password(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ChangePasswordReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    if body.new_password.len() < 8 {
        return Err(AppError::bad("新密码至少 8 位"));
    }
    let u: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
    if !verify_password(&body.old_password, &u.password_hash) {
        return Err(AppError::bad("旧密码不正确"));
    }
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(hash_password(&body.new_password).map_err(|e| AppError::internal(e.to_string()))?)
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    // 其他会话失效
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id != ?")
        .bind(user.id)
        .bind(&user.session_id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "change_password",
        Some("users"),
        Some(user.id),
        None,
        serde_json::json!({}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({}))))
}

/// POST /api/auth/change_username
async fn change_username(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ChangeUsernameReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let new_name = body.new_username.trim();
    if new_name.is_empty() || new_name.len() > 64 {
        return Err(AppError::bad("用户名不合法"));
    }
    let u: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
    if !verify_password(&body.password, &u.password_hash) {
        return Err(AppError::bad("密码不正确"));
    }
    let dup: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?")
        .bind(new_name)
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;
    if dup > 0 {
        return Err(AppError::bad("用户名已存在"));
    }
    sqlx::query("UPDATE users SET username = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(new_name)
        .bind(user.id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(user.id),
        new_name,
        "change_username",
        Some("users"),
        Some(user.id),
        None,
        serde_json::json!({"old": user.username, "new": new_name}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({}))))
}
