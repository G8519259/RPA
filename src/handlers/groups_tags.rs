use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::{ApiResp, EntryGroup, Tag};
use crate::state::AppState;
use crate::util::{client_ip, table_of};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

pub fn group_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(list_groups))
        .route("", web::post().to(create_group))
        .route("/reorder", web::post().to(reorder_groups))
        .route("/{id}", web::put().to(update_group))
        .route("/{id}", web::delete().to(delete_group))
        .route("/{id}/merge", web::post().to(merge_group));
}

pub fn tag_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(list_tags))
        .route("", web::post().to(create_tag))
        .route("/merge", web::post().to(merge_tags))
        .route("/{id}", web::put().to(update_tag))
        .route("/{id}", web::delete().to(delete_tag));
}

fn validate_name(name: &str) -> AppResult<()> {
    let t = name.trim();
    if t.is_empty() || t.chars().count() > 60 {
        return Err(AppError::bad("名称不能为空且不超过 60 字符"));
    }
    Ok(())
}

fn validate_color(color: &str) -> AppResult<()> {
    let t = color.trim();
    let ok = t.len() == 7 && t.starts_with('#') && t[1..].chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err(AppError::bad("颜色必须是 #RRGGBB 格式"));
    }
    Ok(())
}

// ============ 分组 ============

#[derive(Deserialize)]
pub struct GroupCreate {
    pub name: String,
    pub color: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct GroupUpdate {
    pub name: Option<String>,
    pub color: Option<String>,
    pub description: Option<Option<String>>,
}

#[derive(Deserialize)]
pub struct ReorderReq {
    pub ordered_ids: Vec<i64>,
}

#[derive(Deserialize)]
pub struct MergeGroupReq {
    pub source_ids: Vec<i64>,
}

/// 分组列表，附带三类条目数量
async fn list_groups(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    let groups: Vec<EntryGroup> =
        sqlx::query_as("SELECT * FROM entry_groups ORDER BY sort_order, id")
            .fetch_all(&state.pool)
            .await?;
    let mut items = Vec::with_capacity(groups.len());
    for g in groups {
        let mut counts = serde_json::json!({"proxy": 0, "forward": 0, "tunnel": 0});
        for et in ["proxy", "forward", "tunnel"] {
            let table = table_of(et)?;
            let n: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE group_id = ?"
            ))
            .bind(g.id)
            .fetch_one(&state.pool)
            .await?;
            counts[et] = serde_json::json!(n);
        }
        let mut v = serde_json::to_value(&g).unwrap_or_default();
        v["entry_counts"] = counts;
        items.push(v);
    }
    Ok(HttpResponse::Ok().json(ApiResp::ok(items)))
}

async fn create_group(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<GroupCreate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    validate_name(&body.name)?;
    let color = body.color.as_deref().unwrap_or("#3b82f6");
    validate_color(color)?;
    let max_order: Option<i64> =
        sqlx::query_scalar("SELECT MAX(sort_order) FROM entry_groups")
            .fetch_one(&state.pool)
            .await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO entry_groups (name, color, description, sort_order)
         VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(body.name.trim())
    .bind(color)
    .bind(body.description.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(max_order.unwrap_or(0) + 1)
    .fetch_one(&state.pool)
    .await?;
    audit(
        &state.pool, Some(user.id), &user.username, "create_group",
        Some("entry_groups"), Some(id), None,
        serde_json::json!({"name": body.name}), &ip,
    )
    .await;
    let g: EntryGroup = sqlx::query_as("SELECT * FROM entry_groups WHERE id = ?")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(g)))
}

async fn update_group(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<GroupUpdate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();
    if let Some(n) = b.name.as_deref() { validate_name(n)?; }
    if let Some(c) = b.color.as_deref() { validate_color(c)?; }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entry_groups WHERE id = ?")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    if n == 0 {
        return Err(AppError::not_found("分组不存在"));
    }
    if let Some(v) = b.name.as_deref() {
        sqlx::query("UPDATE entry_groups SET name = ? WHERE id = ?").bind(v.trim()).bind(id).execute(&state.pool).await?;
    }
    if let Some(v) = b.color.as_deref() {
        sqlx::query("UPDATE entry_groups SET color = ? WHERE id = ?").bind(v).bind(id).execute(&state.pool).await?;
    }
    if let Some(v) = b.description {
        sqlx::query("UPDATE entry_groups SET description = ? WHERE id = ?")
            .bind(v.as_deref().map(str::trim).filter(|s| !s.is_empty()))
            .bind(id)
            .execute(&state.pool)
            .await?;
    }
    audit(
        &state.pool, Some(user.id), &user.username, "update_group",
        Some("entry_groups"), Some(id), None, serde_json::json!({}), &ip,
    )
    .await;
    let g: EntryGroup = sqlx::query_as("SELECT * FROM entry_groups WHERE id = ?")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(g)))
}

/// 删除分组：该组条目 group_id 置空
async fn delete_group(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let mut tx = state.pool.begin().await?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entry_groups WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if n == 0 {
        return Err(AppError::not_found("分组不存在"));
    }
    for et in ["proxy", "forward", "tunnel"] {
        let table = table_of(et)?;
        sqlx::query(&format!("UPDATE {table} SET group_id = NULL, updated_at = datetime('now') WHERE group_id = ?"))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM entry_groups WHERE id = ?").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "delete_group",
        Some("entry_groups"), Some(id), None, serde_json::json!({}), &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"deleted": 1}))))
}

async fn reorder_groups(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ReorderReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let mut tx = state.pool.begin().await?;
    for (i, gid) in body.ordered_ids.iter().enumerate() {
        sqlx::query("UPDATE entry_groups SET sort_order = ? WHERE id = ?")
            .bind(i as i64)
            .bind(gid)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "reorder_groups",
        Some("entry_groups"), None, None,
        serde_json::json!({"ordered_ids": body.ordered_ids}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"ok": true}))))
}

/// 合并分组：源分组条目全部迁入目标分组，删除源分组
async fn merge_group(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<MergeGroupReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let target = path.into_inner();
    let sources: Vec<i64> = body.source_ids.iter().copied().filter(|s| *s != target).collect();
    if sources.is_empty() {
        return Err(AppError::bad("source_ids 不能为空"));
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entry_groups WHERE id = ?")
        .bind(target)
        .fetch_one(&state.pool)
        .await?;
    if n == 0 {
        return Err(AppError::not_found("目标分组不存在"));
    }
    let mut tx = state.pool.begin().await?;
    let mut moved = 0u64;
    for et in ["proxy", "forward", "tunnel"] {
        let table = table_of(et)?;
        for chunk in sources.chunks(500) {
            let ph = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "UPDATE {table} SET group_id = ?, updated_at = datetime('now') WHERE group_id IN ({ph})"
            );
            let mut q = sqlx::query(&sql).bind(target);
            for s in chunk {
                q = q.bind(s);
            }
            moved += q.execute(&mut *tx).await?.rows_affected();
        }
    }
    for chunk in sources.chunks(500) {
        let ph = vec!["?"; chunk.len()].join(",");
        let sql = format!("DELETE FROM entry_groups WHERE id IN ({ph})");
        let mut q = sqlx::query(&sql);
        for s in chunk {
            q = q.bind(s);
        }
        q.execute(&mut *tx).await?;
    }
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "merge_group",
        Some("entry_groups"), Some(target), None,
        serde_json::json!({"source_ids": sources, "moved": moved}), &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"moved": moved}))))
}

// ============ 标签 ============

#[derive(Deserialize)]
pub struct TagCreate {
    pub name: String,
    pub color: Option<String>,
}

#[derive(Deserialize)]
pub struct TagUpdate {
    pub name: Option<String>,
    pub color: Option<String>,
}

#[derive(Deserialize)]
pub struct MergeTagsReq {
    pub source_ids: Vec<i64>,
    pub target_id: i64,
}

async fn list_tags(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    let tags: Vec<Tag> = sqlx::query_as("SELECT * FROM tags ORDER BY name")
        .fetch_all(&state.pool)
        .await?;
    let mut items = Vec::with_capacity(tags.len());
    for t in tags {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entry_tags WHERE tag_id = ?")
            .bind(t.id)
            .fetch_one(&state.pool)
            .await?;
        let mut v = serde_json::to_value(&t).unwrap_or_default();
        v["usage_count"] = serde_json::json!(n);
        items.push(v);
    }
    Ok(HttpResponse::Ok().json(ApiResp::ok(items)))
}

async fn create_tag(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<TagCreate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    validate_name(&body.name)?;
    let color = body.color.as_deref().unwrap_or("#3b82f6");
    validate_color(color)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO tags (name, color) VALUES (?, ?) RETURNING id",
    )
    .bind(body.name.trim())
    .bind(color)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::bad("标签名已存在")
        } else {
            AppError::from(e)
        }
    })?;
    audit(
        &state.pool, Some(user.id), &user.username, "create_tag",
        Some("tags"), Some(id), None, serde_json::json!({"name": body.name}), &ip,
    )
    .await;
    let t: Tag = sqlx::query_as("SELECT * FROM tags WHERE id = ?")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(t)))
}

async fn update_tag(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<TagUpdate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();
    if let Some(n) = b.name.as_deref() { validate_name(n)?; }
    if let Some(c) = b.color.as_deref() { validate_color(c)?; }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tags WHERE id = ?")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    if n == 0 {
        return Err(AppError::not_found("标签不存在"));
    }
    if let Some(v) = b.name.as_deref() {
        sqlx::query("UPDATE tags SET name = ? WHERE id = ?").bind(v.trim()).bind(id).execute(&state.pool).await.map_err(|e| {
            if e.to_string().contains("UNIQUE") { AppError::bad("标签名已存在") } else { AppError::from(e) }
        })?;
    }
    if let Some(v) = b.color.as_deref() {
        sqlx::query("UPDATE tags SET color = ? WHERE id = ?").bind(v).bind(id).execute(&state.pool).await?;
    }
    audit(
        &state.pool, Some(user.id), &user.username, "update_tag",
        Some("tags"), Some(id), None, serde_json::json!({}), &ip,
    )
    .await;
    let t: Tag = sqlx::query_as("SELECT * FROM tags WHERE id = ?")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(t)))
}

/// 删除标签：级联清理 entry_tags
async fn delete_tag(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let mut tx = state.pool.begin().await?;
    let r = sqlx::query("DELETE FROM tags WHERE id = ?").bind(id).execute(&mut *tx).await?;
    if r.rows_affected() == 0 {
        return Err(AppError::not_found("标签不存在"));
    }
    sqlx::query("DELETE FROM entry_tags WHERE tag_id = ?").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "delete_tag",
        Some("tags"), Some(id), None, serde_json::json!({}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"deleted": 1}))))
}

/// 合并标签：源标签的关联全部迁到目标标签，删除源标签
async fn merge_tags(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<MergeTagsReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let sources: Vec<i64> = body.source_ids.iter().copied().filter(|s| *s != body.target_id).collect();
    if sources.is_empty() {
        return Err(AppError::bad("source_ids 不能为空"));
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tags WHERE id = ?")
        .bind(body.target_id)
        .fetch_one(&state.pool)
        .await?;
    if n == 0 {
        return Err(AppError::not_found("目标标签不存在"));
    }
    let mut tx = state.pool.begin().await?;
    let mut moved = 0u64;
    for chunk in sources.chunks(500) {
        let ph = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "UPDATE OR IGNORE entry_tags SET tag_id = ? WHERE tag_id IN ({ph})"
        );
        let mut q = sqlx::query(&sql).bind(body.target_id);
        for s in chunk {
            q = q.bind(s);
        }
        moved += q.execute(&mut *tx).await?.rows_affected();
        // 残留的重复行删除
        let sql2 = format!("DELETE FROM entry_tags WHERE tag_id IN ({ph})");
        let mut q2 = sqlx::query(&sql2);
        for s in chunk {
            q2 = q2.bind(s);
        }
        q2.execute(&mut *tx).await?;
        let sql3 = format!("DELETE FROM tags WHERE id IN ({ph})");
        let mut q3 = sqlx::query(&sql3);
        for s in chunk {
            q3 = q3.bind(s);
        }
        q3.execute(&mut *tx).await?;
    }
    tx.commit().await?;
    audit(
        &state.pool, Some(user.id), &user.username, "merge_tags",
        Some("tags"), Some(body.target_id), None,
        serde_json::json!({"source_ids": sources, "moved": moved}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"moved": moved}))))
}
