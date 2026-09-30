//! 订阅管理（文档 §6.9 / §9）：CRUD、范围配置、条目/规则管理、导出预览、token 轮换。

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{EntryRef, SubRuleInput, Subscription, SubscriptionUpsert};
use crate::services::export::{render_subscription, resolve_entries, validate_format};
use crate::state::AppState;
use crate::util::{calc_expires, client_ip, random_token, table_of};

/// P13：viewer 不可见订阅链接 → token 置空
fn hide_token_for_viewer(sub: &mut Subscription, is_viewer: bool) {
    if is_viewer {
        sub.token = String::new();
    }
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/subscriptions")
            .route("", web::get().to(list))
            .route("", web::post().to(create))
            .route("/batch_delete", web::post().to(batch_delete))
            .route("/resolve_preview", web::post().to(resolve_preview))
            .route("/{id}", web::get().to(detail))
            .route("/{id}", web::put().to(update))
            .route("/{id}", web::delete().to(delete))
            .route("/{id}/toggle", web::post().to(toggle))
            .route("/{id}/rotate_token", web::post().to(rotate_token))
            .route("/{id}/extend", web::post().to(extend))
            .route("/{id}/entries", web::get().to(entries_list))
            .route("/{id}/entries", web::post().to(entries_append))
            .route("/{id}/entries", web::put().to(entries_replace))
            .route("/{id}/entries/remove", web::post().to(entries_remove))
            .route("/{id}/resolved", web::get().to(resolved))
            .route("/{id}/stats", web::get().to(stats))
            .route("/{id}/preview", web::get().to(preview)),
    );
}

#[derive(Deserialize)]
struct ListQ {
    page: Option<i64>,
    page_size: Option<i64>,
    q: Option<String>,
    enabled: Option<i64>,
}

async fn list(
    state: web::Data<AppState>,
    req: HttpRequest,
    q: web::Query<ListQ>,
) -> AppResult<HttpResponse> {
    let is_viewer = !auth_user(&req)?.is_admin();
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 200);
    let offset = (page - 1) * page_size;
    let mut cond = "1=1".to_string();
    if let Some(en) = q.enabled {
        cond.push_str(&format!(" AND enabled = {en}"));
    }
    let like = q.q.as_deref().map(|k| format!("%{}%", k.trim()));
    let mut list_sql = format!("SELECT * FROM subscriptions WHERE {cond}");
    let mut count_sql = format!("SELECT COUNT(*) FROM subscriptions WHERE {cond}");
    if like.is_some() {
        list_sql.push_str(" AND name LIKE ?");
        count_sql.push_str(" AND name LIKE ?");
    }
    list_sql.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");
    let mut lq = sqlx::query_as::<_, Subscription>(&list_sql);
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(kw) = &like {
        lq = lq.bind(kw);
        cq = cq.bind(kw);
    }
    let mut rows = lq.bind(page_size).bind(offset).fetch_all(&state.pool).await?;
    if is_viewer {
        for r in &mut rows {
            hide_token_for_viewer(r, true);
        }
    }
    let total = cq.fetch_one(&state.pool).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": rows, "total": total, "page": page, "page_size": page_size,
    })))
}

fn validate_upsert(b: &SubscriptionUpsert) -> AppResult<()> {
    if b.name.trim().is_empty() || b.name.chars().count() > 100 {
        return Err(AppError::bad("名称不能为空且不超过 100 字符"));
    }
    if !matches!(b.scope.as_str(), "single" | "custom" | "all" | "rule") {
        return Err(AppError::bad("scope 只能是 single/custom/all/rule"));
    }
    validate_format(&b.default_format)?;
    if let Some(tid) = b.template_id {
        if tid <= 0 {
            return Err(AppError::bad("template_id 非法"));
        }
    }
    if let Some(m) = b.max_ips {
        if m < 0 {
            return Err(AppError::bad("max_ips 不能为负数"));
        }
    }
    for e in &b.entries {
        table_of(&e.entry_type)?;
    }
    for r in &b.rules {
        if !matches!(r.kind.as_str(), "group" | "tag" | "node" | "type") {
            return Err(AppError::bad(format!("规则 kind 非法：{}", r.kind)));
        }
        if !matches!(r.mode.as_str(), "include" | "exclude") {
            return Err(AppError::bad(format!("规则 mode 非法：{}", r.mode)));
        }
    }
    Ok(())
}

async fn write_entries_rules(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    sub_id: i64,
    entries: &[EntryRef],
    rules: &[SubRuleInput],
) -> AppResult<()> {
    for (i, e) in entries.iter().enumerate() {
        // 条目存在性校验
        let table = table_of(&e.entry_type)?;
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id = ?"))
            .bind(e.entry_id)
            .fetch_one(&mut **tx)
            .await?;
        if n == 0 {
            return Err(AppError::bad(format!(
                "条目不存在：{} #{}",
                e.entry_type, e.entry_id
            )));
        }
        sqlx::query(
            "INSERT INTO subscription_entries (subscription_id, entry_type, entry_id, sort_order)
             VALUES (?, ?, ?, ?)",
        )
        .bind(sub_id)
        .bind(&e.entry_type)
        .bind(e.entry_id)
        .bind(i as i64)
        .execute(&mut **tx)
        .await?;
    }
    for r in rules {
        sqlx::query(
            "INSERT INTO subscription_rules (subscription_id, kind, value, mode)
             VALUES (?, ?, ?, ?)",
        )
        .bind(sub_id)
        .bind(&r.kind)
        .bind(&r.value)
        .bind(&r.mode)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn create(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<SubscriptionUpsert>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let b = body.into_inner();
    validate_upsert(&b)?;
    let expires = calc_expires(&b.expire_preset, b.expires_at.as_deref())?;
    let token = random_token(32);

    let mut tx = state.pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO subscriptions
           (user_id, token, name, description, scope, default_format, template_id,
            enabled, expires_at, max_ips)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(Some(user.id))
    .bind(&token)
    .bind(b.name.trim())
    .bind(b.description.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(&b.scope)
    .bind(&b.default_format)
    .bind(b.template_id)
    .bind(b.enabled.unwrap_or(true) as i64)
    .bind(&expires)
    .bind(b.max_ips)
    .fetch_one(&mut *tx)
    .await?;
    write_entries_rules(&mut tx, id, &b.entries, &b.rules).await?;
    tx.commit().await?;

    audit(
        &state.pool, Some(user.id), &user.username, "create_subscription",
        Some("subscription"), Some(id), None,
        serde_json::json!({"name": b.name, "scope": b.scope}), &ip,
    )
    .await;
    let sub = get_sub(&state.pool, id).await?;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(sub)))
}

async fn get_sub(pool: &sqlx::SqlitePool, id: i64) -> AppResult<Subscription> {
    sqlx::query_as("SELECT * FROM subscriptions WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("订阅不存在"))
}

async fn detail(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let is_viewer = !auth_user(&req)?.is_admin();
    let id = path.into_inner();
    let mut sub = get_sub(&state.pool, id).await?;
    hide_token_for_viewer(&mut sub, is_viewer);
    let entries: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT entry_type, entry_id, sort_order FROM subscription_entries
         WHERE subscription_id = ? ORDER BY sort_order, id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let rules: Vec<crate::models::SubRule> =
        sqlx::query_as("SELECT * FROM subscription_rules WHERE subscription_id = ? ORDER BY id")
            .bind(id)
            .fetch_all(&state.pool)
            .await?;
    let resolved = resolve_entries(&state.pool, &sub).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "subscription": sub,
        "entries": entries.iter().map(|(t, i, so)| serde_json::json!({
            "entry_type": t, "entry_id": i, "sort_order": so,
        })).collect::<Vec<_>>(),
        "rules": rules,
        "resolved_count": resolved.len(),
    })))
}

async fn update(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<SubscriptionUpsert>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();
    let cur = get_sub(&state.pool, id).await?;
    validate_upsert(&b)?;
    let expires = calc_expires(&b.expire_preset, b.expires_at.as_deref())?;

    // 若因 expired 被停用且新到期在未来，则自动恢复
    let now = now_str();
    let mut enabled = b.enabled.unwrap_or(cur.enabled == 1) as i64;
    let mut reason: Option<String> = cur.disabled_reason.clone();
    if cur.enabled == 0 && cur.disabled_reason.as_deref() == Some("expired") {
        let future = expires.as_deref().map(|e| e > now.as_str()).unwrap_or(true);
        if future {
            enabled = 1;
            reason = None;
        }
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE subscriptions SET name = ?, description = ?, scope = ?, default_format = ?,
                template_id = ?, enabled = ?, disabled_reason = ?, expires_at = ?, max_ips = ?,
                updated_at = datetime('now') WHERE id = ?",
    )
    .bind(b.name.trim())
    .bind(b.description.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(&b.scope)
    .bind(&b.default_format)
    .bind(b.template_id)
    .bind(enabled)
    .bind(&reason)
    .bind(&expires)
    .bind(b.max_ips)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM subscription_entries WHERE subscription_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM subscription_rules WHERE subscription_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    write_entries_rules(&mut tx, id, &b.entries, &b.rules).await?;
    tx.commit().await?;

    audit(
        &state.pool, Some(user.id), &user.username, "update_subscription",
        Some("subscription"), Some(id), None,
        serde_json::json!({"name": b.name}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(
        get_sub(&state.pool, id).await?,
    )))
}

async fn delete(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let sub = get_sub(&state.pool, id).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM subscription_entries WHERE subscription_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM subscription_rules WHERE subscription_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM subscriptions WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "delete_subscription",
        Some("subscription"), Some(id), None,
        serde_json::json!({"name": sub.name}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({"deleted": 1}))))
}

#[derive(Deserialize)]
struct IdsReq {
    ids: Vec<i64>,
}

async fn batch_delete(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<IdsReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    if body.ids.is_empty() {
        return Err(AppError::bad("ids 不能为空"));
    }
    let mut tx = state.pool.begin().await?;
    let mut n = 0u64;
    for chunk in body.ids.chunks(500) {
        let ph = vec!["?"; chunk.len()].join(",");
        let sql = format!("DELETE FROM subscription_entries WHERE subscription_id IN ({ph})");
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(&mut *tx).await?;
        let sql = format!("DELETE FROM subscription_rules WHERE subscription_id IN ({ph})");
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(&mut *tx).await?;
        let sql = format!("DELETE FROM subscriptions WHERE id IN ({ph})");
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        n += q.execute(&mut *tx).await?.rows_affected();
    }
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "batch_delete_subscription",
        Some("subscription"), None, None,
        serde_json::json!({"ids": body.ids, "deleted": n}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({"deleted": n}))))
}

#[derive(Deserialize)]
struct ToggleReq {
    enabled: bool,
}

async fn toggle(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<ToggleReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let sub = get_sub(&state.pool, id).await?;
    if body.enabled {
        sqlx::query(
            "UPDATE subscriptions SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id).execute(&state.pool).await?;
    } else {
        sqlx::query(
            "UPDATE subscriptions SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id).execute(&state.pool).await?;
    }
    audit(
        &state.pool, Some(user.id), &user.username,
        if body.enabled { "enable_subscription" } else { "disable_subscription" },
        Some("subscription"), Some(id), None,
        serde_json::json!({"name": sub.name}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(
        get_sub(&state.pool, id).await?,
    )))
}

/// 重置 token（旧链接立即失效）
async fn rotate_token(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let sub = get_sub(&state.pool, id).await?;
    let token = random_token(32);
    sqlx::query("UPDATE subscriptions SET token = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(&token)
        .bind(id)
        .execute(&state.pool)
        .await?;
    audit(
        &state.pool, Some(user.id), &user.username, "rotate_sub_token",
        Some("subscription"), Some(id), None,
        serde_json::json!({"name": sub.name}), &ip,
    )
    .await;
    let base = state.cfg.server.public_base_url.trim_end_matches('/');
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({
        "token": token, "url": format!("{base}/sub/{token}"),
    }))))
}

#[derive(Deserialize)]
struct ExtendReq {
    days: i64,
}

/// 续期：在 max(当前到期, 现在) 上累加；永久订阅返回提示
async fn extend(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<ExtendReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    if body.days <= 0 || body.days > 3650 {
        return Err(AppError::bad("days 须在 1~3650 之间"));
    }
    let sub = get_sub(&state.pool, id).await?;
    if sub.expires_at.is_none() {
        return Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({
            "message": "永久订阅无需续期",
        }))));
    }
    let now = now_str();
    let base = sub.expires_at.as_deref().unwrap().max(now.as_str());
    let new_exp = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S")
        .map_err(|_| AppError::internal("expires_at 格式错误"))?
        + chrono::Duration::days(body.days);
    let new_exp = new_exp.format("%Y-%m-%d %H:%M:%S").to_string();
    // 续期后若曾因过期停用，自动恢复
    let (enabled, reason) =
        if sub.enabled == 0 && sub.disabled_reason.as_deref() == Some("expired") {
            (1i64, None)
        } else {
            (sub.enabled, sub.disabled_reason.clone())
        };
    sqlx::query(
        "UPDATE subscriptions SET expires_at = ?, enabled = ?, disabled_reason = ?,
                updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&new_exp)
    .bind(enabled)
    .bind(&reason)
    .bind(id)
    .execute(&state.pool)
    .await?;
    audit(
        &state.pool, Some(user.id), &user.username, "extend_subscription",
        Some("subscription"), Some(id), None,
        serde_json::json!({"name": sub.name, "days": body.days, "expires_at": new_exp}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({
        "expires_at": new_exp,
    }))))
}

// ============ 手工勾选条目管理 ============

async fn entry_detail_json(
    pool: &sqlx::SqlitePool,
    e: &EntryRef,
) -> AppResult<serde_json::Value> {
    let table = table_of(&e.entry_type)?;
    let row: Option<(String, i64, i64)> = sqlx::query_as(&format!(
        "SELECT name, node_id, enabled FROM {table} WHERE id = ?"
    ))
    .bind(e.entry_id)
    .fetch_optional(pool)
    .await?;
    match row {
        Some((name, node_id, enabled)) => Ok(serde_json::json!({
            "entry_type": e.entry_type, "entry_id": e.entry_id,
            "name": name, "node_id": node_id, "enabled": enabled,
        })),
        None => Ok(serde_json::json!({
            "entry_type": e.entry_type, "entry_id": e.entry_id, "missing": true,
        })),
    }
}

async fn entries_list(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let id = path.into_inner();
    get_sub(&state.pool, id).await?;
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT entry_type, entry_id, sort_order FROM subscription_entries
         WHERE subscription_id = ? ORDER BY sort_order, id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let mut out = Vec::new();
    for (et, eid, _so) in rows {
        out.push(entry_detail_json(&state.pool, &EntryRef { entry_type: et, entry_id: eid }).await?);
    }
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(out)))
}

#[derive(Deserialize)]
struct EntriesBody {
    entries: Vec<EntryRef>,
}

async fn entries_append(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<EntriesBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    get_sub(&state.pool, id).await?;
    let mut tx = state.pool.begin().await?;
    let max_so: Option<i64> =
        sqlx::query_scalar("SELECT MAX(sort_order) FROM subscription_entries WHERE subscription_id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let mut so = max_so.unwrap_or(-1) + 1;
    for e in &body.entries {
        table_of(&e.entry_type)?;
        sqlx::query(
            "INSERT OR IGNORE INTO subscription_entries
               (subscription_id, entry_type, entry_id, sort_order) VALUES (?, ?, ?, ?)",
        )
        .bind(id)
        .bind(&e.entry_type)
        .bind(e.entry_id)
        .bind(so)
        .execute(&mut *tx)
        .await?;
        so += 1;
    }
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "sub_entries_append",
        Some("subscription"), Some(id), None,
        serde_json::json!({"count": body.entries.len()}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({"ok": true}))))
}

async fn entries_replace(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<EntriesBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    get_sub(&state.pool, id).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM subscription_entries WHERE subscription_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    write_entries_rules(&mut tx, id, &body.entries, &[]).await?;
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "sub_entries_replace",
        Some("subscription"), Some(id), None,
        serde_json::json!({"count": body.entries.len()}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({"ok": true}))))
}

async fn entries_remove(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<EntriesBody>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    get_sub(&state.pool, id).await?;
    let mut tx = state.pool.begin().await?;
    for e in &body.entries {
        table_of(&e.entry_type)?;
        sqlx::query(
            "DELETE FROM subscription_entries
             WHERE subscription_id = ? AND entry_type = ? AND entry_id = ?",
        )
        .bind(id)
        .bind(&e.entry_type)
        .bind(e.entry_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "sub_entries_remove",
        Some("subscription"), Some(id), None,
        serde_json::json!({"count": body.entries.len()}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({"ok": true}))))
}

/// 当前实际命中的条目（scope=rule 时用于"命中 N 个"实时预览）
async fn resolved(state: web::Data<AppState>, path: web::Path<i64>) -> AppResult<HttpResponse> {
    let id = path.into_inner();
    let sub = get_sub(&state.pool, id).await?;
    let refs = resolve_entries(&state.pool, &sub).await?;
    let mut out = Vec::new();
    for r in &refs {
        out.push(entry_detail_json(&state.pool, r).await?);
    }
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({
        "count": out.len(), "items": out,
    }))))
}

#[derive(Deserialize)]
struct PreviewDraft {
    scope: String,
    entries: Option<Vec<EntryRef>>,
    rules: Option<Vec<SubRuleInput>>,
}

/// 用未保存的草稿（scope + entries + rules）计算命中的条目
async fn resolve_preview(
    state: web::Data<AppState>,
    body: web::Json<PreviewDraft>,
) -> AppResult<HttpResponse> {
    let b = body.into_inner();
    if !matches!(b.scope.as_str(), "single" | "custom" | "all" | "rule") {
        return Err(AppError::bad("scope 非法"));
    }
    // 用一个真实的临时订阅行做解析，算完即删
    let tmp_token = random_token(16);
    let mut tx = state.pool.begin().await?;
    let tmp_id: i64 = sqlx::query_scalar(
        "INSERT INTO subscriptions (token, name, scope, default_format, enabled)
         VALUES (?, '__preview__', ?, 'clash', 1) RETURNING id",
    )
    .bind(&tmp_token)
    .bind(&b.scope)
    .fetch_one(&mut *tx)
    .await?;
    let entries = b.entries.unwrap_or_default();
    let rules = b.rules.unwrap_or_default();
    for (i, e) in entries.iter().enumerate() {
        table_of(&e.entry_type)?;
        sqlx::query(
            "INSERT INTO subscription_entries (subscription_id, entry_type, entry_id, sort_order)
             VALUES (?, ?, ?, ?)",
        )
        .bind(tmp_id)
        .bind(&e.entry_type)
        .bind(e.entry_id)
        .bind(i as i64)
        .execute(&mut *tx)
        .await?;
    }
    for r in &rules {
        if !matches!(r.kind.as_str(), "group" | "tag" | "node" | "type") {
            return Err(AppError::bad("规则 kind 非法"));
        }
        if !matches!(r.mode.as_str(), "include" | "exclude") {
            return Err(AppError::bad("规则 mode 非法"));
        }
        sqlx::query(
            "INSERT INTO subscription_rules (subscription_id, kind, value, mode) VALUES (?, ?, ?, ?)",
        )
        .bind(tmp_id)
        .bind(&r.kind)
        .bind(&r.value)
        .bind(&r.mode)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let fake = Subscription {
        id: tmp_id,
        user_id: None,
        token: tmp_token,
        name: "__preview__".into(),
        description: None,
        scope: b.scope.clone(),
        default_format: "clash".into(),
        template_id: None,
        enabled: 1,
        disabled_reason: None,
        expires_at: None,
        max_ips: None,
        access_count: 0,
        last_access_at: None,
        created_at: String::new(),
        updated_at: String::new(),
    };
    let refs = resolve_entries(&state.pool, &fake).await?;
    // 清理临时行
    let _ = sqlx::query("DELETE FROM subscription_entries WHERE subscription_id = ?")
        .bind(tmp_id).execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM subscription_rules WHERE subscription_id = ?")
        .bind(tmp_id).execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM subscriptions WHERE id = ?")
        .bind(tmp_id).execute(&state.pool).await;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({
        "count": refs.len(), "items": refs,
    }))))
}

/// 访问次数、最近访问、近 7 天趋势、不同 IP 数
async fn stats(state: web::Data<AppState>, path: web::Path<i64>) -> AppResult<HttpResponse> {
    let id = path.into_inner();
    let sub = get_sub(&state.pool, id).await?;
    let trend: Vec<(String, i64)> = sqlx::query_as(
        "SELECT date(accessed_at) AS d, COUNT(*) FROM subscription_logs
         WHERE subscription_id = ? AND accessed_at > datetime('now','-7 days')
         GROUP BY d ORDER BY d",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let distinct_ips: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT client_ip) FROM subscription_logs
         WHERE subscription_id = ? AND accessed_at > datetime('now','-1 day')",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    Ok(HttpResponse::Ok().json(crate::models::ApiResp::ok(serde_json::json!({
        "access_count": sub.access_count,
        "last_access_at": sub.last_access_at,
        "distinct_ips_24h": distinct_ips,
        "trend_7d": trend.iter().map(|(d, c)| serde_json::json!({"date": d, "count": c})).collect::<Vec<_>>(),
    }))))
}

#[derive(Deserialize)]
struct PreviewQ {
    format: Option<String>,
}

/// 后台预览导出内容（不计访问）
async fn preview(
    state: web::Data<AppState>,
    path: web::Path<i64>,
    q: web::Query<PreviewQ>,
) -> AppResult<HttpResponse> {
    let id = path.into_inner();
    let sub = get_sub(&state.pool, id).await?;
    let format = q.format.clone().unwrap_or_else(|| sub.default_format.clone());
    let r = render_subscription(&state.pool, &sub, &format).await?;
    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(r.content))
}

fn now_str() -> String {
    chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S").to_string()
}
