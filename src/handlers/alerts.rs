//! P12 —— 告警中心 API
//!
//! - GET / POST  /api/alerts/channels（渠道列表密钥脱敏 / 新建）
//! - PUT / DELETE /api/alerts/channels/{id}（修改 / 删除；被规则引用时自动从规则中移除）
//! - POST /api/alerts/channels/{id}/test（同步发送测试消息）
//! - GET / POST  /api/alerts/rules（规则列表 / 新建）
//! - PUT / DELETE /api/alerts/rules/{id}（修改 / 删除）
//! - POST /api/alerts/rules/{id}/toggle（启停）
//! - GET  /api/alerts/events（事件历史，status/event_type/from/to + 分页）
//! - POST /api/alerts/events/{id}/retry（手动重发失败事件）
//! - POST /api/alerts/events/cleanup（清理 N 天前事件 {"days":30}）

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{ApiResp, Page};
use crate::services::alert::crypto;
use crate::services::alert::{AlertChannel, AlertDraft, AlertEvent, AlertRule};
use crate::state::AppState;
use crate::util::client_ip;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/alerts")
            .route("/channels", web::get().to(list_channels))
            .route("/channels", web::post().to(create_channel))
            .route("/channels/{id}", web::put().to(update_channel))
            .route("/channels/{id}", web::delete().to(delete_channel))
            .route("/channels/{id}/test", web::post().to(test_channel))
            .route("/rules", web::get().to(list_rules))
            .route("/rules", web::post().to(create_rule))
            .route("/rules/{id}", web::put().to(update_rule))
            .route("/rules/{id}", web::delete().to(delete_rule))
            .route("/rules/{id}/toggle", web::post().to(toggle_rule))
            .route("/events", web::get().to(list_events))
            .route("/events/{id}/retry", web::post().to(retry_event))
            .route("/events/cleanup", web::post().to(cleanup_events)),
    );
}

// ============ 渠道 ============

fn channel_to_json(
    ch: &AlertChannel,
    secret_key: Option<&str>,
    is_viewer: bool,
) -> serde_json::Value {
    let raw: serde_json::Value = serde_json::from_str(&ch.config).unwrap_or(serde_json::Value::Null);
    let mut v = crypto::decrypt_config(&raw, secret_key);
    if is_viewer {
        // P13：viewer 连字段本身都不可见，直接删除
        crypto::strip_secrets(&mut v);
    } else {
        // admin：脱敏为 ******
        crypto::mask_config(&mut v);
    }
    serde_json::json!({
        "id": ch.id,
        "name": ch.name,
        "kind": ch.kind,
        "config": v,
        "enabled": ch.enabled,
        "created_at": ch.created_at,
        "updated_at": ch.updated_at,
    })
}

/// 前端回传 ****** 表示该字段不修改 → 用旧值替换
///（旧值可能是 enc:v1: 密文，原样保留即可，加密函数会跳过已加密的值）
fn merge_secret(old: &str, new_v: &mut serde_json::Value, keys: &[&str]) {
    let old_v: serde_json::Value = serde_json::from_str(old).unwrap_or_default();
    if let (Some(new_obj), Some(old_obj)) = (new_v.as_object_mut(), old_v.as_object()) {
        for k in keys {
            if new_obj.get(*k).and_then(|v| v.as_str()) == Some("******") {
                if let Some(old_val) = old_obj.get(*k) {
                    new_obj.insert(k.to_string(), old_val.clone());
                } else {
                    new_obj.remove(*k);
                }
            }
        }
    }
}

pub async fn list_channels(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let is_viewer = !user.is_admin();
    let sk = state.cfg.server.secret_key.as_deref();
    let rows: Vec<AlertChannel> =
        sqlx::query_as("SELECT * FROM alert_channels ORDER BY id")
            .fetch_all(&state.pool)
            .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(
        rows.iter()
            .map(|ch| channel_to_json(ch, sk, is_viewer))
            .collect::<Vec<_>>(),
    )))
}

#[derive(Deserialize)]
pub struct ChannelBody {
    pub name: String,
    pub kind: String,
    pub config: serde_json::Value,
    #[serde(default = "one")]
    pub enabled: i64,
}

fn one() -> i64 {
    1
}

fn validate_channel(kind: &str, cfg: &serde_json::Value) -> Result<(), AppError> {
    match kind {
        "telegram" => {
            if cfg.get("bot_token").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).is_none() {
                return Err(AppError::bad("telegram 需要 bot_token"));
            }
            if cfg.get("chat_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).is_none() {
                return Err(AppError::bad("telegram 需要 chat_id"));
            }
        }
        "webhook" => {
            if cfg.get("url").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).is_none() {
                return Err(AppError::bad("webhook 需要 url"));
            }
        }
        "email" => {
            for k in ["host", "from"] {
                if cfg.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).is_none() {
                    return Err(AppError::bad(format!("email 需要 {k}")));
                }
            }
            let has_to = cfg
                .get("to")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if !has_to {
                return Err(AppError::bad("email 需要至少一个收件人 to"));
            }
        }
        _ => return Err(AppError::bad("未知渠道类型（telegram / webhook / email）")),
    }
    Ok(())
}

pub async fn create_channel(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ChannelBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("名称不能为空"));
    }
    validate_channel(&body.kind, &body.config)?;
    // P13：写库前加密密钥字段（未配置 secret_key 则明文存储）
    let mut cfg = body.config.clone();
    crypto::encrypt_config(&mut cfg, state.cfg.server.secret_key.as_deref());
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO alert_channels (name, kind, config, enabled) VALUES (?, ?, ?, ?)
         RETURNING id",
    )
    .bind(name)
    .bind(&body.kind)
    .bind(cfg.to_string())
    .bind(body.enabled)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::bad("渠道名称已存在")
        } else {
            e.into()
        }
    })?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_channel_create",
        Some("alert_channels"),
        Some(id),
        None,
        serde_json::json!({"name": name, "kind": body.kind}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

pub async fn update_channel(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<ChannelBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let old: Option<AlertChannel> =
        sqlx::query_as("SELECT * FROM alert_channels WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let old = old.ok_or_else(|| AppError::not_found("渠道不存在"))?;
    let mut cfg = body.config.clone();
    let keys: &[&str] = match old.kind.as_str() {
        "telegram" => &["bot_token"],
        "webhook" => &["secret"],
        "email" => &["password"],
        _ => &[],
    };
    merge_secret(&old.config, &mut cfg, keys);
    validate_channel(&old.kind, &cfg)?;
    // P13：写库前加密密钥字段（已是 enc:v1: 的旧值会被跳过）
    crypto::encrypt_config(&mut cfg, state.cfg.server.secret_key.as_deref());
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("名称不能为空"));
    }
    sqlx::query(
        "UPDATE alert_channels SET name = ?, config = ?, enabled = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(name)
    .bind(cfg.to_string())
    .bind(body.enabled)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::bad("渠道名称已存在")
        } else {
            e.into()
        }
    })?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_channel_update",
        Some("alert_channels"),
        Some(id),
        None,
        serde_json::json!({"name": name}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

pub async fn delete_channel(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let mut tx = state.pool.begin().await?;
    let n = sqlx::query("DELETE FROM alert_channels WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("渠道不存在"));
    }
    // 被规则引用时自动从规则中移除
    let rules: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, channel_ids FROM alert_rules")
            .fetch_all(&mut *tx)
            .await?;
    for (rid, ids_json) in rules {
        let mut ids: Vec<i64> = serde_json::from_str(&ids_json).unwrap_or_default();
        if ids.iter().any(|x| *x == id) {
            ids.retain(|x| *x != id);
            sqlx::query(
                "UPDATE alert_rules SET channel_ids = ?, updated_at = datetime('now') WHERE id = ?",
            )
            .bind(serde_json::to_string(&ids).unwrap_or_default())
            .bind(rid)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_channel_delete",
        Some("alert_channels"),
        Some(id),
        None,
        serde_json::json!({}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

pub async fn test_channel(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let id = path.into_inner();
    let ch: Option<AlertChannel> = sqlx::query_as("SELECT * FROM alert_channels WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let ch = ch.ok_or_else(|| AppError::not_found("渠道不存在"))?;
    let base = &state.cfg.server.public_base_url;
    let draft = AlertDraft::test_channel(&ch.name, &ch.kind, base);
    // 同步发送，不经过规则与事件表，错误原样返回
    match crate::services::alert::dispatcher::send_draft_to_channel(
        &state.pool,
        &state.http,
        id,
        &draft,
        state.cfg.server.secret_key.as_deref(),
    )
    .await
    {
        Ok(()) => Ok(HttpResponse::Ok().json(ApiResp::ok(
            serde_json::json!({ "sent": true }),
        ))),
        Err(e) => Err(AppError::bad(format!("测试发送失败：{e}"))),
    }
}

// ============ 规则 ============

/// 事件类型中文名 + 默认参数（前端新建下拉用）
pub fn event_types() -> Vec<serde_json::Value> {
    vec![
        ("node_offline", "节点离线", r#"{"offline_secs":90}"#),
        ("node_online", "节点恢复", "{}"),
        ("sub_expiring", "订阅即将到期", r#"{"days_before":[7,3,1]}"#),
        ("sub_expired", "订阅已过期", "{}"),
        ("entry_expiring", "条目即将到期", r#"{"days_before":[7,3,1]}"#),
        ("entry_expired", "条目已到期", "{}"),
        ("quota_warn", "配额预警", r#"{"percent":[80,95]}"#),
        ("quota_exceeded", "配额用尽", "{}"),
        ("runtime_error", "条目运行异常", "{}"),
        ("login_fail_burst", "登录失败激增", r#"{"threshold":5}"#),
        ("sub_ip_limit", "订阅触发 IP 限制", "{}"),
    ]
    .into_iter()
    .map(|(t, zh, params)| serde_json::json!({"event_type": t, "name": zh, "default_params": params}))
    .collect()
}

pub async fn list_rules(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let rows: Vec<AlertRule> =
        sqlx::query_as("SELECT * FROM alert_rules ORDER BY id")
            .fetch_all(&state.pool)
            .await?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let channels: Vec<i64> = serde_json::from_str(&r.channel_ids).unwrap_or_default();
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "event_type": r.event_type,
                "params": serde_json::from_str::<serde_json::Value>(&r.params).unwrap_or_default(),
                "channel_ids": channels,
                "cooldown_secs": r.cooldown_secs,
                "enabled": r.enabled,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "items": items,
        "event_types": event_types(),
    }))))
}

#[derive(Deserialize)]
pub struct RuleBody {
    pub name: String,
    pub event_type: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub channel_ids: Vec<i64>,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: i64,
    #[serde(default = "one")]
    pub enabled: i64,
}

fn default_cooldown() -> i64 {
    3600
}

pub async fn create_rule(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<RuleBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("名称不能为空"));
    }
    if !event_types()
        .iter()
        .any(|e| e["event_type"] == body.event_type)
    {
        return Err(AppError::bad("未知事件类型"));
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO alert_rules (name, event_type, params, channel_ids, cooldown_secs, enabled)
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(&body.event_type)
    .bind(body.params.to_string())
    .bind(serde_json::to_string(&body.channel_ids).unwrap_or_default())
    .bind(body.cooldown_secs.max(0))
    .bind(body.enabled)
    .fetch_one(&state.pool)
    .await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_rule_create",
        Some("alert_rules"),
        Some(id),
        None,
        serde_json::json!({"name": name, "event_type": body.event_type}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

pub async fn update_rule(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<RuleBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("名称不能为空"));
    }
    let n = sqlx::query(
        "UPDATE alert_rules SET name = ?, params = ?, channel_ids = ?, cooldown_secs = ?,
                enabled = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(name)
    .bind(body.params.to_string())
    .bind(serde_json::to_string(&body.channel_ids).unwrap_or_default())
    .bind(body.cooldown_secs.max(0))
    .bind(body.enabled)
    .bind(id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("规则不存在"));
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_rule_update",
        Some("alert_rules"),
        Some(id),
        None,
        serde_json::json!({"name": name}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

pub async fn delete_rule(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let n = sqlx::query("DELETE FROM alert_rules WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("规则不存在"));
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_rule_delete",
        Some("alert_rules"),
        Some(id),
        None,
        serde_json::json!({}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

pub async fn toggle_rule(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let cur: Option<i64> = sqlx::query_scalar("SELECT enabled FROM alert_rules WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .flatten();
    let cur = cur.ok_or_else(|| AppError::not_found("规则不存在"))?;
    let next = if cur == 1 { 0 } else { 1 };
    sqlx::query("UPDATE alert_rules SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(next)
        .bind(id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_rule_toggle",
        Some("alert_rules"),
        Some(id),
        None,
        serde_json::json!({"enabled": next}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(
        serde_json::json!({ "enabled": next }),
    )))
}

// ============ 事件历史 ============

#[derive(Deserialize)]
pub struct EventQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    pub status: Option<String>,
    pub event_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    20
}

pub async fn list_events(
    state: web::Data<AppState>,
    req: HttpRequest,
    q: web::Query<EventQuery>,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let page = q.page.max(1);
    let ps = q.page_size.clamp(1, 100);
    let mut cond = String::from("WHERE 1=1");
    let mut bind_vals: Vec<String> = Vec::new();
    if let Some(s) = &q.status {
        if ["pending", "sent", "failed"].contains(&s.as_str()) {
            cond.push_str(" AND status = ?");
            bind_vals.push(s.clone());
        }
    }
    if let Some(t) = &q.event_type {
        if !t.is_empty() {
            cond.push_str(" AND event_type = ?");
            bind_vals.push(t.clone());
        }
    }
    if let Some(f) = &q.from {
        if !f.is_empty() {
            cond.push_str(" AND created_at >= ?");
            bind_vals.push(f.clone());
        }
    }
    if let Some(t) = &q.to {
        if !t.is_empty() {
            cond.push_str(" AND created_at <= ?");
            bind_vals.push(t.clone());
        }
    }
    let total_sql = format!("SELECT COUNT(*) FROM alert_events {cond}");
    let list_sql = format!("SELECT * FROM alert_events {cond} ORDER BY id DESC LIMIT ? OFFSET ?");
    let mut total_q = sqlx::query_scalar::<_, i64>(&total_sql);
    let mut list_q = sqlx::query_as::<_, AlertEvent>(&list_sql);
    for v in &bind_vals {
        total_q = total_q.bind(v);
        list_q = list_q.bind(v);
    }
    let total = total_q.fetch_one(&state.pool).await?;
    let items = list_q
        .bind(ps)
        .bind((page - 1) * ps)
        .fetch_all(&state.pool)
        .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(Page {
        items,
        total,
        page,
        page_size: ps,
    })))
}

pub async fn retry_event(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let n = sqlx::query(
        "UPDATE alert_events SET status = 'pending', attempts = 0,
                next_retry_at = NULL, last_error = NULL
         WHERE id = ? AND status = 'failed'",
    )
    .bind(id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("失败事件不存在（仅失败事件可重试）"));
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_event_retry",
        Some("alert_events"),
        Some(id),
        None,
        serde_json::json!({}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "id": id }))))
}

#[derive(Deserialize)]
pub struct CleanupBody {
    #[serde(default = "default_days")]
    pub days: i64,
}

fn default_days() -> i64 {
    30
}

pub async fn cleanup_events(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CleanupBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let days = body.days.clamp(1, 3650);
    let n = sqlx::query("DELETE FROM alert_events WHERE created_at <= datetime('now', ?)")
        .bind(format!("-{days} days"))
        .execute(&state.pool)
        .await?
        .rows_affected();
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "alert_events_cleanup",
        Some("alert_events"),
        None,
        None,
        serde_json::json!({"days": days, "deleted": n}),
        &client_ip(&req, &state.cfg.server.trusted_proxies),
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(
        serde_json::json!({ "deleted": n }),
    )))
}
