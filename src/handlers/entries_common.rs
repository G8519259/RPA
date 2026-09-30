use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{ApiResp, EntryRef, ListQuery, Page};
use crate::state::AppState;
use crate::util::{calc_expires, client_ip, random_token, table_of};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

// ============ 条目删除：统一清理多态关联（10.5） ============
pub async fn delete_entries_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entry_type: &str,
    ids: &[i64],
) -> AppResult<u64> {
    let table = table_of(entry_type)?;
    let mut total = 0;
    for chunk in ids.chunks(500) {
        let ph = vec!["?"; chunk.len()].join(",");

        for cleanup in [
            format!("DELETE FROM subscription_entries WHERE entry_type = ? AND entry_id IN ({ph})"),
            format!("DELETE FROM entry_tags          WHERE entry_type = ? AND entry_id IN ({ph})"),
            format!("DELETE FROM entry_quotas        WHERE entry_type = ? AND entry_id IN ({ph})"),
        ] {
            let mut q = sqlx::query(&cleanup).bind(entry_type);
            for id in chunk {
                q = q.bind(id);
            }
            q.execute(&mut **tx).await?;
        }

        let sql = format!("DELETE FROM {table} WHERE id IN ({ph})");
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        total += q.execute(&mut **tx).await?.rows_affected();
    }
    Ok(total)
}

/// 条目被多少个订阅引用（删除前提示用）
pub async fn count_sub_refs(
    pool: &sqlx::SqlitePool,
    entry_type: &str,
    entry_id: i64,
) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT subscription_id) FROM subscription_entries
         WHERE entry_type = ? AND entry_id = ?",
    )
    .bind(entry_type)
    .bind(entry_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
}

// ============ 列表查询 ============
pub async fn list_entries(
    pool: &sqlx::SqlitePool,
    entry_type: &str,
    q: &ListQuery,
) -> AppResult<Page<serde_json::Value>> {
    let table = table_of(entry_type)?;
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 200);

    let mut conds: Vec<String> = vec!["1=1".into()];
    // 搜索字段按类型不同
    let search_cols: &[&str] = match entry_type {
        "proxy" => &["name", "upstream_addr", "listen_addr", "remark"],
        "forward" => &["name", "target_ip", "listen_ip", "remark"],
        _ => &["name", "local_addr", "remote_addr", "remark"],
    };
    if let Some(s) = q.q.as_deref().filter(|s| !s.trim().is_empty()) {
        let like = format!("%{}%", s.trim().replace('%', "").replace('_', ""));
        let or = search_cols
            .iter()
            .map(|c| format!("{table}.{c} LIKE ?"))
            .collect::<Vec<_>>()
            .join(" OR ");
        conds.push(format!("({or})"));
        let _ = like;
    }
    if let Some(nid) = q.node_id {
        conds.push(format!("{table}.node_id = {nid}"));
    }
    if let Some(en) = q.enabled {
        conds.push(format!("{table}.enabled = {en}"));
    }
    if let Some(sid) = q.source_import_id {
        conds.push(format!("{table}.source_import_id = {sid}"));
    }
    if let Some(gid) = q.group_id {
        conds.push(format!("{table}.group_id = {gid}"));
    }
    if q.no_group == Some(1) {
        conds.push(format!("{table}.group_id IS NULL"));
    }
    if let Some(dr) = q.disabled_reason.as_deref().filter(|s| !s.is_empty()) {
        conds.push(format!(
            "{table}.disabled_reason = '{}'",
            dr.replace('\'', "")
        ));
    }
    if let Some(days) = q.expiring_days {
        conds.push(format!(
            "{table}.expires_at IS NOT NULL AND {table}.expires_at <= datetime('now','+{days} days') AND {table}.enabled = 1"
        ));
    }
    if let Some(tag_ids) = q.tag_id.as_deref().filter(|s| !s.trim().is_empty()) {
        let ids: Vec<i64> = tag_ids
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if !ids.is_empty() {
            let ph = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
            conds.push(format!(
                "EXISTS (SELECT 1 FROM entry_tags et WHERE et.entry_type = '{entry_type}'
                 AND et.entry_id = {table}.id AND et.tag_id IN ({ph}))"
            ));
        }
    }
    let where_sql = conds.join(" AND ");

    // q 搜索的 LIKE 参数
    let like_param: Option<String> = q.q.as_deref().filter(|s| !s.trim().is_empty()).map(|s| {
        format!("%{}%", s.trim().replace('%', "").replace('_', ""))
    });
    let n_like = search_cols.len();

    let count_sql = format!("SELECT COUNT(*) FROM {table} WHERE {where_sql}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(lp) = &like_param {
        for _ in 0..n_like {
            cq = cq.bind(lp);
        }
    }
    let total: i64 = cq.fetch_one(pool).await?;

    let offset = (page - 1) * page_size;
    let list_sql = format!("SELECT * FROM {table} WHERE {where_sql} ORDER BY id DESC LIMIT {page_size} OFFSET {offset}");
    let mut lq = sqlx::query(&list_sql);
    if let Some(lp) = &like_param {
        for _ in 0..n_like {
            lq = lq.bind(lp);
        }
    }
    let rows = lq.fetch_all(pool).await?;

    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        items.push(enrich_entry(pool, entry_type, &r).await?);
    }
    Ok(Page {
        items,
        total,
        page,
        page_size,
    })
}

fn row_to_json(row: &sqlx::sqlite::SqliteRow) -> serde_json::Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let v = match col.type_info().name() {
            "INTEGER" | "INT" => row
                .try_get::<i64, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            "REAL" | "FLOAT" | "DOUBLE" => row
                .try_get::<f64, _>(name)
                .map(|f| serde_json::json!(f))
                .unwrap_or(serde_json::Value::Null),
            _ => row
                .try_get::<String, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        };
        map.insert(name.to_string(), v);
    }
    serde_json::Value::Object(map)
}

/// 列表/详情行附加 group / tags / quota / node_name
pub async fn enrich_entry(
    pool: &sqlx::SqlitePool,
    entry_type: &str,
    row: &sqlx::sqlite::SqliteRow,
) -> AppResult<serde_json::Value> {
    use sqlx::Row;
    let mut v = row_to_json(row);
    let id: i64 = row.try_get("id").unwrap_or(0);
    let node_id: i64 = row.try_get("node_id").unwrap_or(0);
    let group_id: Option<i64> = row.try_get("group_id").ok();

    let node_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM nodes WHERE id = ?")
            .bind(node_id)
            .fetch_optional(pool)
            .await?;
    v["node_name"] = node_name.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);

    if let Some(gid) = group_id {
        let g: Option<(i64, String, String)> =
            sqlx::query_as("SELECT id, name, color FROM entry_groups WHERE id = ?")
                .bind(gid)
                .fetch_optional(pool)
                .await?;
        v["group"] = g
            .map(|(id, name, color)| serde_json::json!({"id": id, "name": name, "color": color}))
            .unwrap_or(serde_json::Value::Null);
    } else {
        v["group"] = serde_json::Value::Null;
    }

    let tags: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT t.id, t.name, t.color FROM tags t
         JOIN entry_tags et ON et.tag_id = t.id
         WHERE et.entry_type = ? AND et.entry_id = ? ORDER BY t.name",
    )
    .bind(entry_type)
    .bind(id)
    .fetch_all(pool)
    .await?;
    v["tags"] = tags
        .into_iter()
        .map(|(id, name, color)| serde_json::json!({"id": id, "name": name, "color": color}))
        .collect();

    let quota: Option<serde_json::Value> = sqlx::query_as::<_, crate::models::QuotaRow>(
        "SELECT * FROM entry_quotas WHERE entry_type = ? AND entry_id = ?",
    )
    .bind(entry_type)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(|q| serde_json::to_value(q).unwrap_or(serde_json::Value::Null));
    v["quota"] = quota.unwrap_or(serde_json::Value::Null);
    Ok(v)
}

pub async fn get_entry(
    pool: &sqlx::SqlitePool,
    entry_type: &str,
    id: i64,
) -> AppResult<serde_json::Value> {
    let table = table_of(entry_type)?;
    let row = sqlx::query(&format!("SELECT * FROM {table} WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("条目不存在"))?;
    let mut v = enrich_entry(pool, entry_type, &row).await?;
    v["sub_refs"] = serde_json::json!(count_sub_refs(pool, entry_type, id).await);
    Ok(v)
}

// ============ 标签设置 ============
pub async fn set_entry_tags(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entry_type: &str,
    entry_id: i64,
    tag_ids: &[i64],
) -> AppResult<()> {
    sqlx::query("DELETE FROM entry_tags WHERE entry_type = ? AND entry_id = ?")
        .bind(entry_type)
        .bind(entry_id)
        .execute(&mut **tx)
        .await?;
    for tid in tag_ids {
        sqlx::query(
            "INSERT OR IGNORE INTO entry_tags (entry_type, entry_id, tag_id) VALUES (?, ?, ?)",
        )
        .bind(entry_type)
        .bind(entry_id)
        .bind(tid)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}


/// 修改 expires_at 到未来（或永久）且当前 disabled_reason='expired' → 自动恢复（§13.2）
pub async fn recover_expired_if_future(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entry_type: &str,
    entry_id: i64,
    expires: Option<&str>,
) -> AppResult<()> {
    let table = table_of(entry_type)?;
    sqlx::query(&format!(
        "UPDATE {table} SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now')
         WHERE id = ? AND disabled_reason = 'expired' AND (? IS NULL OR ? > datetime('now'))"
    ))
    .bind(entry_id)
    .bind(expires)
    .bind(expires)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// ============ 配额是否可计量 ============

pub async fn quota_measurable(
    pool: &sqlx::SqlitePool,
    entry_type: &str,
    entry_id: i64,
) -> AppResult<bool> {
    let table = table_of(entry_type)?;
    match entry_type {
        "proxy" => {
            let la: Option<String> =
                sqlx::query_scalar(&format!("SELECT listen_addr FROM {table} WHERE id = ?"))
                    .bind(entry_id)
                    .fetch_optional(pool)
                    .await?
                    .unwrap_or(None);
            Ok(la.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false))
        }
        "forward" | "tunnel" => Ok(true),
        _ => Ok(false),
    }
}

/// 设置配额；quota_bytes=0 表示取消。返回是否触发了自动恢复。
pub async fn upsert_quota(
    pool: &sqlx::SqlitePool,
    entry_type: &str,
    entry_id: i64,
    quota_bytes: i64,
    period: &str,
    reset_day: Option<i64>,
    actor: Option<&crate::middleware::AuthUser>,
    ip: &str,
) -> AppResult<bool> {
    if !quota_measurable(pool, entry_type, entry_id).await? {
        return Err(AppError::bad("该条目流量不经过本系统，无法设置配额"));
    }
    if quota_bytes < 0 || quota_bytes > 1024_i64.pow(5) {
        return Err(AppError::bad("配额必须在 0 ~ 1PB 之间"));
    }
    if !matches!(period, "total" | "monthly") {
        return Err(AppError::bad("period 只能是 total 或 monthly"));
    }
    let rd = reset_day.unwrap_or(1).clamp(1, 28);
    let table = table_of(entry_type)?;
    let mut tx = pool.begin().await?;
    let mut recovered = false;

    if quota_bytes == 0 {
        sqlx::query("DELETE FROM entry_quotas WHERE entry_type = ? AND entry_id = ?")
            .bind(entry_type)
            .bind(entry_id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query(
            "INSERT INTO entry_quotas
               (entry_type, entry_id, quota_bytes, period, reset_day, period_start)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(entry_type, entry_id) DO UPDATE SET
               quota_bytes = excluded.quota_bytes, period = excluded.period,
               reset_day = excluded.reset_day, updated_at = datetime('now')",
        )
        .bind(entry_type)
        .bind(entry_id)
        .bind(quota_bytes)
        .bind(period)
        .bind(rd)
        .execute(&mut *tx)
        .await?;

        // 调大配额 → 若当前超限且已用量小于新配额，恢复条目
        let q: Option<crate::models::QuotaRow> = sqlx::query_as(
            "SELECT * FROM entry_quotas WHERE entry_type = ? AND entry_id = ?",
        )
        .bind(entry_type)
        .bind(entry_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(q) = q {
            if q.status == "exceeded" && q.used_bytes < quota_bytes {
                sqlx::query(
                    "UPDATE entry_quotas SET status = 'ok', exceeded_at = NULL, warn_level = 0,
                            updated_at = datetime('now') WHERE id = ?",
                )
                .bind(q.id)
                .execute(&mut *tx)
                .await?;
                let n = sqlx::query(&format!(
                    "UPDATE {table} SET enabled = 1, disabled_reason = NULL,
                            updated_at = datetime('now')
                     WHERE id = ? AND disabled_reason = 'quota'"
                ))
                .bind(entry_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                recovered = n > 0;
            }
        }
    }
    // 条目 updated_at 刷新，Worker 感知配置变化
    sqlx::query(&format!(
        "UPDATE {table} SET updated_at = datetime('now') WHERE id = ?"
    ))
    .bind(entry_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    if let Some(a) = actor {
        audit(
            pool,
            Some(a.id),
            &a.username,
            "set_quota",
            Some(entry_type),
            Some(entry_id),
            None,
            serde_json::json!({"quota_bytes": quota_bytes, "period": period, "recovered": recovered}),
            ip,
        )
        .await;
    }
    Ok(recovered)
}

// ============ 跨类型批量操作 ============
#[derive(Deserialize)]
pub struct BatchItems {
    pub items: Vec<EntryRef>,
}

#[derive(Deserialize)]
pub struct BatchSetGroup {
    pub items: Vec<EntryRef>,
    pub group_id: Option<i64>,
}

#[derive(Deserialize)]
pub struct BatchTags {
    pub items: Vec<EntryRef>,
    pub tag_ids: Vec<i64>,
}

#[derive(Deserialize)]
pub struct BatchSetExpiry {
    pub items: Vec<EntryRef>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Deserialize)]
pub struct BatchSetQuota {
    pub items: Vec<EntryRef>,
    pub quota_bytes: i64,
    pub period: String,
    pub reset_day: Option<i64>,
}

pub fn entries_routes(cfg: &mut web::ServiceConfig) {
    super::quotas::entry_quota_routes(cfg);
    cfg.route("/batch_set_group", web::post().to(batch_set_group))
        .route("/batch_add_tags", web::post().to(batch_add_tags))
        .route("/batch_remove_tags", web::post().to(batch_remove_tags))
        .route("/batch_set_expiry", web::post().to(batch_set_expiry))
        .route("/batch_set_quota", web::post().to(batch_set_quota))
        .route("/{etype}/{id}/quick_subscription", web::post().to(quick_subscription));
}

fn group_items(items: &[EntryRef]) -> AppResult<std::collections::HashMap<String, Vec<i64>>> {
    let mut m: std::collections::HashMap<String, Vec<i64>> = Default::default();
    for it in items {
        if !matches!(it.entry_type.as_str(), "proxy" | "forward" | "tunnel") {
            return Err(AppError::bad("未知条目类型"));
        }
        m.entry(it.entry_type.clone()).or_default().push(it.entry_id);
    }
    Ok(m)
}

async fn batch_set_group(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchSetGroup>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let grouped = group_items(&body.items)?;
    let mut tx = state.pool.begin().await?;
    let mut n = 0;
    for (t, ids) in &grouped {
        let table = table_of(t)?;
        for chunk in ids.chunks(500) {
            let ph = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "UPDATE {table} SET group_id = ?, updated_at = datetime('now') WHERE id IN ({ph})"
            );
            let mut q = sqlx::query(&sql).bind(body.group_id);
            for id in chunk {
                q = q.bind(id);
            }
            n += q.execute(&mut *tx).await?.rows_affected();
        }
    }
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_set_group",
        Some("entries"),
        None,
        None,
        serde_json::json!({"count": n, "group_id": body.group_id}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"updated": n}))))
}

async fn batch_add_tags(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchTags>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let mut tx = state.pool.begin().await?;
    let mut n = 0i64;
    for it in &body.items {
        if !matches!(it.entry_type.as_str(), "proxy" | "forward" | "tunnel") {
            return Err(AppError::bad("未知条目类型"));
        }
        for tid in &body.tag_ids {
            let r = sqlx::query(
                "INSERT OR IGNORE INTO entry_tags (entry_type, entry_id, tag_id) VALUES (?, ?, ?)",
            )
            .bind(&it.entry_type)
            .bind(it.entry_id)
            .bind(tid)
            .execute(&mut *tx)
            .await?;
            n += r.rows_affected() as i64;
        }
        let table = table_of(&it.entry_type)?;
        sqlx::query(&format!("UPDATE {table} SET updated_at = datetime('now') WHERE id = ?"))
            .bind(it.entry_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_add_tags",
        Some("entries"),
        None,
        None,
        serde_json::json!({"added": n, "tag_ids": body.tag_ids}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"added": n}))))
}

async fn batch_remove_tags(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchTags>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let mut tx = state.pool.begin().await?;
    let mut n = 0i64;
    for it in &body.items {
        if !matches!(it.entry_type.as_str(), "proxy" | "forward" | "tunnel") {
            return Err(AppError::bad("未知条目类型"));
        }
        for tid in &body.tag_ids {
            let r = sqlx::query(
                "DELETE FROM entry_tags WHERE entry_type = ? AND entry_id = ? AND tag_id = ?",
            )
            .bind(&it.entry_type)
            .bind(it.entry_id)
            .bind(tid)
            .execute(&mut *tx)
            .await?;
            n += r.rows_affected() as i64;
        }
        let table = table_of(&it.entry_type)?;
        sqlx::query(&format!("UPDATE {table} SET updated_at = datetime('now') WHERE id = ?"))
            .bind(it.entry_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_remove_tags",
        Some("entries"),
        None,
        None,
        serde_json::json!({"removed": n, "tag_ids": body.tag_ids}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"removed": n}))))
}

async fn batch_set_expiry(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchSetExpiry>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let preset = body.expire_preset.as_deref().unwrap_or("permanent");
    let expires = calc_expires(preset, body.expires_at.as_deref())?;
    let grouped = group_items(&body.items)?;
    let mut tx = state.pool.begin().await?;
    let mut n = 0u64;
    for (t, ids) in &grouped {
        let table = table_of(t)?;
        for chunk in ids.chunks(500) {
            let ph = vec!["?"; chunk.len()].join(",");
            // 到期延到未来 → 自动恢复因 expired 停用的
            let sql = format!(
                "UPDATE {table} SET expires_at = ?, updated_at = datetime('now'),
                    enabled = CASE WHEN disabled_reason = 'expired' AND (? IS NULL OR ? > datetime('now'))
                                   THEN 1 ELSE enabled END,
                    disabled_reason = CASE WHEN disabled_reason = 'expired' AND (? IS NULL OR ? > datetime('now'))
                                   THEN NULL ELSE disabled_reason END
                 WHERE id IN ({ph})"
            );
            let mut q = sqlx::query(&sql).bind(&expires)
            .bind(&expires)
            .bind(&expires)
            .bind(&expires)
            .bind(&expires);
            for id in chunk {
                q = q.bind(id);
            }
            n += q.execute(&mut *tx).await?.rows_affected();
        }
    }
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_set_expiry",
        Some("entries"),
        None,
        None,
        serde_json::json!({"count": n, "expires_at": expires}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"updated": n}))))
}

async fn batch_set_quota(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchSetQuota>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let mut ok = 0;
    let mut skipped: Vec<serde_json::Value> = vec![];
    for it in &body.items {
        match upsert_quota(
            &state.pool,
            &it.entry_type,
            it.entry_id,
            body.quota_bytes,
            &body.period,
            body.reset_day,
            None,
            &ip,
        )
        .await
        {
            Ok(_) => ok += 1,
            Err(e) => skipped.push(serde_json::json!({
                "entry_type": it.entry_type, "entry_id": it.entry_id, "reason": e.to_string()
            })),
        }
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_set_quota",
        Some("entries"),
        None,
        None,
        serde_json::json!({"ok": ok, "skipped": skipped.len(), "quota_bytes": body.quota_bytes}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"ok": ok, "skipped": skipped}))))
}

/// POST /api/entries/{type}/{id}/quick_subscription — 一键为单个条目生成订阅
async fn quick_subscription(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(String, i64)>,
    body: web::Json<serde_json::Value>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let (etype, eid) = path.into_inner();
    table_of(&etype)?;
    // 条目存在性
    get_entry(&state.pool, &etype, eid).await?;

    let preset = body.get("expire_preset").and_then(|v| v.as_str()).unwrap_or("permanent");
    let expires = calc_expires(preset, body.get("expires_at").and_then(|v| v.as_str()))?;
    let name: String = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("单条目订阅-{eid}"));

    let token = random_token(32);
    let mut tx = state.pool.begin().await?;
    let sub_id: i64 = sqlx::query_scalar(
        "INSERT INTO subscriptions
           (user_id, token, name, scope, default_format, expires_at, enabled)
         VALUES (?, ?, ?, 'single', 'clash', ?, 1) RETURNING id",
    )
    .bind(user.id)
    .bind(&token)
    .bind(&name)
    .bind(&expires)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO subscription_entries (subscription_id, entry_type, entry_id, sort_order)
         VALUES (?, ?, ?, 0)",
    )
    .bind(sub_id)
    .bind(&etype)
    .bind(eid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "quick_subscription",
        Some("subscriptions"),
        Some(sub_id),
        None,
        serde_json::json!({"entry_type": etype, "entry_id": eid}),
        &ip,
    )
    .await;

    let base = state.cfg.server.public_base_url.trim_end_matches('/');
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "id": sub_id,
        "token": token,
        "url": format!("{base}/sub/{token}"),
    }))))
}
