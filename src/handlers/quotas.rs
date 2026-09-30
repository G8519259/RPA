//! P11 —— 配额 HTTP 接口
//!
//! - GET /api/entries/{etype}/{id}/quota        查看配额与用量
//! - PUT /api/entries/{etype}/{id}/quota        设置/取消配额
//! - POST /api/entries/{etype}/{id}/quota/reset 重置用量
//! - PUT /api/entries/{etype}/{id}/expiry       设置到期时间（preset 或自定义；不传为永久）
//! - GET /api/quotas                            配额总览（按使用率排序，支持超限/接近超限过滤）
//!
//! 批量接口在 entries_common（POST /api/entries/batch_set_quota）。

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::handlers::entries_common::{get_entry, upsert_quota};
use crate::middleware::auth_user;
use crate::models::{ApiResp, QuotaRow};
use crate::services::lifecycle;
use crate::state::AppState;
use crate::util::{calc_expires, client_ip, table_of};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

pub fn routes(cfg: &mut web::ServiceConfig) {
    // 注意：/api/entries/* 的路由必须注册在同一个 scope 内（见 entries_routes），
    // actix 同前缀的第二个 scope 不会被匹配到。
    cfg.route("/api/quotas", web::get().to(overview));
}

/// 挂到 /api/entries scope 下的路由（由 entries_common::entries_routes 注册）
pub fn entry_quota_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/{etype}/{id}/quota", web::get().to(get_quota))
        .route("/{etype}/{id}/quota", web::put().to(set_quota))
        .route("/{etype}/{id}/quota/reset", web::post().to(reset_quota))
        .route("/{etype}/{id}/expiry", web::put().to(set_expiry));
}

#[derive(Deserialize)]
struct EntryPath {
    etype: String,
    id: i64,
}

fn check_etype(t: &str) -> AppResult<&str> {
    table_of(t)?; // 校验类型合法
    if !matches!(t, "proxy" | "forward" | "tunnel") {
        return Err(AppError::bad("未知的条目类型"));
    }
    Ok(t)
}

/// GET /api/entries/{etype}/{id}/quota —— 查看配额与用量
pub async fn get_quota(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<EntryPath>,
) -> AppResult<HttpResponse> {
    auth_user(&req)?;
    let p = path.into_inner();
    check_etype(&p.etype)?;
    get_entry(&state.pool, &p.etype, p.id).await?; // 404 校验
    let q: Option<QuotaRow> =
        sqlx::query_as("SELECT * FROM entry_quotas WHERE entry_type = ? AND entry_id = ?")
            .bind(&p.etype)
            .bind(p.id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "quota": q.map(|q| serde_json::to_value(q).unwrap_or(serde_json::Value::Null))
            .unwrap_or(serde_json::Value::Null),
    }))))
}

#[derive(Deserialize)]
struct SetQuotaReq {
    quota_bytes: i64,
    #[serde(default = "d_total")]
    period: String,
    reset_day: Option<i64>,
}
fn d_total() -> String {
    "total".into()
}

/// PUT /api/entries/{etype}/{id}/quota —— 设置/取消配额（quota_bytes=0 取消）
pub async fn set_quota(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<EntryPath>,
    body: web::Json<SetQuotaReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let p = path.into_inner();
    check_etype(&p.etype)?;
    get_entry(&state.pool, &p.etype, p.id).await?;
    let recovered = upsert_quota(
        &state.pool,
        &p.etype,
        p.id,
        body.quota_bytes,
        &body.period,
        body.reset_day,
        Some(&user),
        &ip,
    )
    .await?;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "recovered": recovered,
    }))))
}

/// POST /api/entries/{etype}/{id}/quota/reset —— 手动重置用量
pub async fn reset_quota(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<EntryPath>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let p = path.into_inner();
    check_etype(&p.etype)?;
    get_entry(&state.pool, &p.etype, p.id).await?;
    let recovered = lifecycle::reset_quota_usage(&state.pool, &p.etype, p.id).await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "reset_quota",
        Some(&p.etype),
        Some(p.id),
        None,
        serde_json::json!({"recovered": recovered}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "recovered": recovered,
    }))))
}

#[derive(Deserialize)]
struct SetExpiryReq {
    expire_preset: Option<String>,
    expires_at: Option<String>,
}

/// PUT /api/entries/{etype}/{id}/expiry —— 设置到期时间；不传 expires_at 且 preset=permanent 为永久
pub async fn set_expiry(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<EntryPath>,
    body: web::Json<SetExpiryReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let p = path.into_inner();
    let t = check_etype(&p.etype)?;
    let table = table_of(t)?;
    let mut preset = body.expire_preset.as_deref().unwrap_or("permanent");
    // 显式传了 expires_at 但没传 preset → 按 custom 处理，避免静默忽略
    if body.expires_at.is_some() && preset == "permanent" {
        preset = "custom";
    }
    let expires = calc_expires(preset, body.expires_at.as_deref())?;
    // 到期延到未来 → 自动恢复因 expired 停用的
    let n = sqlx::query(&format!(
        "UPDATE {table} SET expires_at = ?, updated_at = datetime('now'),
                enabled = CASE WHEN disabled_reason = 'expired' AND (? IS NULL OR ? > datetime('now'))
                               THEN 1 ELSE enabled END,
                disabled_reason = CASE WHEN disabled_reason = 'expired' AND (? IS NULL OR ? > datetime('now'))
                               THEN NULL ELSE disabled_reason END
         WHERE id = ?"
    ))
    .bind(&expires)
    .bind(&expires)
    .bind(&expires)
    .bind(&expires)
    .bind(&expires)
    .bind(p.id)
    .execute(&state.pool)
    .await?;
    if n.rows_affected() == 0 {
        return Err(AppError::not_found("条目不存在"));
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "set_expiry",
        Some(t),
        Some(p.id),
        None,
        serde_json::json!({"expires_at": expires}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "expires_at": expires,
    }))))
}

#[derive(Deserialize)]
struct OverviewQuery {
    /// exceeded | near | all（默认 all）
    filter: Option<String>,
}

/// GET /api/quotas —— 配额总览：按使用率排序；filter=exceeded 只看超限，near 只看接近超限（≥80%）
pub async fn overview(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<OverviewQuery>,
) -> AppResult<HttpResponse> {
    auth_user(&req)?;
    let filter = query.filter.as_deref().unwrap_or("all");
    let rows: Vec<QuotaRow> =
        sqlx::query_as("SELECT * FROM entry_quotas WHERE quota_bytes > 0")
            .fetch_all(&state.pool)
            .await?;
    let mut items: Vec<serde_json::Value> = Vec::new();
    for q in rows {
        let table = table_of(&q.entry_type)?;
        let info: Option<(String, i64, Option<String>, i64)> = sqlx::query_as(&format!(
            "SELECT name, enabled, disabled_reason, node_id FROM {table} WHERE id = ?"
        ))
        .bind(q.entry_id)
        .fetch_optional(&state.pool)
        .await?;
        let (name, enabled, disabled_reason, node_id) =
            info.unwrap_or(("（已删除）".into(), 0, None, 1));
        let pct = q.used_bytes * 100 / q.quota_bytes.max(1);
        items.push(serde_json::json!({
            "entry_type": q.entry_type, "entry_id": q.entry_id, "name": name,
            "enabled": enabled, "disabled_reason": disabled_reason, "node_id": node_id,
            "quota_bytes": q.quota_bytes, "used_bytes": q.used_bytes, "pct": pct,
            "period": q.period, "reset_day": q.reset_day, "period_start": q.period_start,
            "status": q.status, "exceeded_at": q.exceeded_at, "warn_level": q.warn_level,
        }));
    }
    // 按使用率降序
    items.sort_by(|a, b| b["pct"].as_i64().unwrap_or(0).cmp(&a["pct"].as_i64().unwrap_or(0)));
    let filtered: Vec<serde_json::Value> = items
        .into_iter()
        .filter(|v| match filter {
            "exceeded" => v["status"] == "exceeded",
            "near" => v["status"] != "exceeded" && v["pct"].as_i64().unwrap_or(0) >= 80,
            _ => true,
        })
        .collect();
    let exceeded = filtered.iter().filter(|v| v["status"] == "exceeded").count();
    let near = filtered
        .iter()
        .filter(|v| v["status"] != "exceeded" && v["pct"].as_i64().unwrap_or(0) >= 80)
        .count();
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "items": filtered,
        "summary": {"total": filtered.len(), "exceeded": exceeded, "near": near},
    }))))
}
