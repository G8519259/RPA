use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::handlers::entries_common::{delete_entries_tx, get_entry, list_entries, set_entry_tags};
use crate::middleware::auth_user;
use crate::models::{ApiResp, ListQuery};
use crate::state::AppState;
use crate::util::{calc_expires, client_ip};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

const ET: &str = "forward";

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(list))
        .route("", web::post().to(create))
        .route("/{id}", web::get().to(detail))
        .route("/{id}", web::put().to(update))
        .route("/{id}", web::delete().to(delete))
        .route("/{id}/toggle", web::post().to(toggle))
        .route("/batch_delete", web::post().to(batch_delete))
        .route("/batch_toggle", web::post().to(batch_toggle))
        .route("/batch_move", web::post().to(batch_move));
}

#[derive(Deserialize)]
pub struct ForwardCreate {
    pub node_id: i64,
    pub name: String,
    pub protocol: Option<String>,
    pub listen_ip: Option<String>,
    pub listen_port: i64,
    pub target_ip: String,
    pub target_port: i64,
    pub remark: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub group_id: Option<i64>,
    pub enabled: Option<bool>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<String>,
    pub tag_ids: Option<Vec<i64>>,
}

#[derive(Deserialize)]
pub struct ForwardUpdate {
    pub node_id: Option<i64>,
    pub name: Option<String>,
    pub protocol: Option<String>,
    pub listen_ip: Option<Option<String>>,
    pub listen_port: Option<i64>,
    pub target_ip: Option<String>,
    pub target_port: Option<i64>,
    pub remark: Option<Option<String>>,
    pub export_host: Option<Option<String>>,
    pub export_port: Option<Option<i64>>,
    pub extra: Option<Option<String>>,
    pub group_id: Option<Option<i64>>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<Option<String>>,
    pub tag_ids: Option<Vec<i64>>,
}

#[derive(Deserialize)]
pub struct ToggleReq {
    pub enabled: bool,
}
#[derive(Deserialize)]
pub struct IdsReq {
    pub ids: Vec<i64>,
}
#[derive(Deserialize)]
pub struct BatchToggleReq {
    pub ids: Vec<i64>,
    pub enabled: bool,
}
#[derive(Deserialize)]
pub struct BatchMoveReq {
    pub ids: Vec<i64>,
    pub node_id: i64,
}

fn validate_port(p: i64, what: &str) -> AppResult<()> {
    if !(1..=65535).contains(&p) {
        return Err(AppError::bad(format!("{what} 必须在 1-65535 之间")));
    }
    Ok(())
}

fn validate_name(name: &str) -> AppResult<()> {
    let t = name.trim();
    if t.is_empty() || t.chars().count() > 100 {
        return Err(AppError::bad("名称不能为空且不超过 100 字符"));
    }
    Ok(())
}

fn validate_ip(ip: &str, what: &str) -> AppResult<()> {
    let t = ip.trim();
    if t.is_empty() || t.len() > 64 {
        return Err(AppError::bad(format!("{what} 格式不正确")));
    }
    Ok(())
}

async fn node_exists(pool: &sqlx::SqlitePool, node_id: i64) -> AppResult<()> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE id = ?")
        .bind(node_id)
        .fetch_one(pool)
        .await?;
    if n == 0 {
        return Err(AppError::bad("节点不存在"));
    }
    Ok(())
}

fn protos_overlap(a: &str, b: &str) -> bool {
    a == b || a == "both" || b == "both"
}

/// 同节点 + 同监听 IP + 同端口 + 协议重叠 → 冲突
async fn check_port_conflict(
    pool: &sqlx::SqlitePool,
    node_id: i64,
    listen_ip: &str,
    listen_port: i64,
    proto: &str,
    exclude_id: Option<i64>,
) -> AppResult<()> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, protocol, listen_ip FROM port_forwards
         WHERE node_id = ? AND listen_port = ? AND enabled = 1",
    )
    .bind(node_id)
    .bind(listen_port)
    .fetch_all(pool)
    .await?;
    for (id, p, lip) in rows {
        if Some(id) == exclude_id {
            continue;
        }
        // IP 重叠：完全相同，或任一方是通配地址（0.0.0.0 / ::）
        let wild = |s: &str| s == "0.0.0.0" || s == "::";
        if lip != listen_ip && !wild(&lip) && !wild(listen_ip) {
            continue;
        }
        if protos_overlap(&p, proto) {
            return Err(AppError::bad(format!(
                "端口冲突：同节点上已存在启用的转发条目 #{id} 占用 {lip}:{listen_port}"
            )));
        }
    }
    Ok(())
}

async fn list(
    state: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> AppResult<HttpResponse> {
    let page = list_entries(&state.pool, ET, &query).await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(page)))
}

async fn create(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ForwardCreate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let b = body.into_inner();
    validate_name(&b.name)?;
    validate_port(b.listen_port, "监听端口")?;
    validate_port(b.target_port, "目标端口")?;
    validate_ip(&b.target_ip, "目标 IP")?;
    let proto = b.protocol.unwrap_or_else(|| "tcp".into());
    if !matches!(proto.as_str(), "tcp" | "udp" | "both") {
        return Err(AppError::bad("protocol 只能是 tcp/udp/both"));
    }
    let lip = b.listen_ip.unwrap_or_else(|| "0.0.0.0".into());
    validate_ip(&lip, "监听 IP")?;
    node_exists(&state.pool, b.node_id).await?;
    check_port_conflict(&state.pool, b.node_id, &lip, b.listen_port, &proto, None).await?;
    let expires = calc_expires(
        b.expire_preset.as_deref().unwrap_or("permanent"),
        b.expires_at.as_deref(),
    )?;

    let mut tx = state.pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO port_forwards
           (node_id, name, protocol, listen_ip, listen_port, target_ip, target_port,
            export_host, export_port, extra, remark, group_id, enabled, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(b.node_id)
    .bind(b.name.trim())
    .bind(&proto)
    .bind(&lip)
    .bind(b.listen_port)
    .bind(b.target_ip.trim())
    .bind(b.target_port)
    .bind(b.export_host.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(b.export_port)
    .bind(b.extra.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(b.remark.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(b.group_id)
    .bind(b.enabled.unwrap_or(true) as i64)
    .bind(&expires)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(tags) = b.tag_ids.as_deref() {
        set_entry_tags(&mut tx, ET, id, tags).await?;
    }
    tx.commit().await?;

    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "create_forward",
        Some(ET),
        Some(id),
        None,
        serde_json::json!({"name": b.name}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(get_entry(&state.pool, ET, id).await?)))
}

async fn detail(state: web::Data<AppState>, path: web::Path<i64>) -> AppResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(ApiResp::ok(get_entry(&state.pool, ET, path.into_inner()).await?)))
}

async fn update(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<ForwardUpdate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();

    let cur = get_entry(&state.pool, ET, id).await?;
    let cur_node = cur["node_id"].as_i64().unwrap_or(1);
    let cur_ip = cur["listen_ip"].as_str().unwrap_or("0.0.0.0").to_string();
    let cur_port = cur["listen_port"].as_i64().unwrap_or(0);
    let cur_proto = cur["protocol"].as_str().unwrap_or("tcp").to_string();

    if let Some(n) = b.name.as_deref() { validate_name(n)?; }
    if let Some(p) = b.listen_port { validate_port(p, "监听端口")?; }
    if let Some(p) = b.target_port { validate_port(p, "目标端口")?; }
    if let Some(t) = b.target_ip.as_deref() { validate_ip(t, "目标 IP")?; }
    if let Some(Some(li)) = b.listen_ip.as_ref() { validate_ip(li, "监听 IP")?; }
    if let Some(p) = b.protocol.as_deref() {
        if !matches!(p, "tcp" | "udp" | "both") {
            return Err(AppError::bad("protocol 只能是 tcp/udp/both"));
        }
    }
    if let Some(nid) = b.node_id { node_exists(&state.pool, nid).await?; }

    // 端口冲突检查（用更新后的值）
    let new_node = b.node_id.unwrap_or(cur_node);
    let new_ip = b.listen_ip.as_ref().and_then(|o| o.as_deref()).map(|s| s.to_string()).unwrap_or(cur_ip.clone());
    let new_port = b.listen_port.unwrap_or(cur_port);
    let new_proto = b.protocol.as_deref().unwrap_or(&cur_proto);
    check_port_conflict(&state.pool, new_node, &new_ip, new_port, new_proto, Some(id)).await?;

    let expires: Option<Option<String>> = match (&b.expire_preset, &b.expires_at) {
        (None, None) => None,
        (preset, ea) => Some(calc_expires(
            preset.as_deref().unwrap_or("permanent"),
            ea.as_ref().and_then(|o| o.as_deref()),
        )?),
    };

    let mut tx = state.pool.begin().await?;
    macro_rules! set {
        ($col:literal, $val:expr) => {
            sqlx::query(concat!("UPDATE port_forwards SET ", $col, " = ? WHERE id = ?"))
                .bind($val)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        };
    }
    if let Some(v) = b.node_id { set!("node_id", v); }
    if let Some(v) = b.name.as_deref() { set!("name", v.trim()); }
    if let Some(v) = b.protocol.as_deref() { set!("protocol", v); }
    if let Some(v) = b.listen_ip.as_ref() { set!("listen_ip", v.clone().unwrap_or(cur_ip)); }
    if let Some(v) = b.listen_port { set!("listen_port", v); }
    if let Some(v) = b.target_ip.as_deref() { set!("target_ip", v.trim()); }
    if let Some(v) = b.target_port { set!("target_port", v); }
    if let Some(v) = b.remark.as_ref() { set!("remark", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.export_host.as_ref() { set!("export_host", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.export_port { set!("export_port", v); }
    if let Some(v) = b.extra.as_ref() { set!("extra", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.group_id { set!("group_id", v); }
    if let Some(v) = expires {
        let exp: Option<String> = v.clone();
        set!("expires_at", v);
        super::entries_common::recover_expired_if_future(&mut tx, ET, id, exp.as_deref()).await?;
    }
    sqlx::query("UPDATE port_forwards SET updated_at = datetime('now') WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if let Some(tags) = b.tag_ids.as_deref() {
        set_entry_tags(&mut tx, ET, id, tags).await?;
    }
    tx.commit().await?;

    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "update_forward",
        Some(ET),
        Some(id),
        None,
        serde_json::json!({}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(get_entry(&state.pool, ET, id).await?)))
}

async fn delete(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    get_entry(&state.pool, ET, id).await?;
    let mut tx = state.pool.begin().await?;
    let n = delete_entries_tx(&mut tx, ET, &[id]).await?;
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "delete_forward",
        Some(ET),
        Some(id),
        None,
        serde_json::json!({}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"deleted": n}))))
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
    let cur = get_entry(&state.pool, ET, id).await?;
    if body.enabled {
        // 启用前再检查端口冲突
        check_port_conflict(
            &state.pool,
            cur["node_id"].as_i64().unwrap_or(1),
            cur["listen_ip"].as_str().unwrap_or("0.0.0.0"),
            cur["listen_port"].as_i64().unwrap_or(0),
            cur["protocol"].as_str().unwrap_or("tcp"),
            Some(id),
        )
        .await?;
        sqlx::query(
            "UPDATE port_forwards SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE port_forwards SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&state.pool)
        .await?;
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        if body.enabled { "enable_forward" } else { "disable_forward" },
        Some(ET),
        Some(id),
        None,
        serde_json::json!({}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(get_entry(&state.pool, ET, id).await?)))
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
    let n = delete_entries_tx(&mut tx, ET, &body.ids).await?;
    tx.commit().await?;
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_delete_forward",
        Some(ET),
        None,
        None,
        serde_json::json!({"ids": body.ids, "deleted": n}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"deleted": n}))))
}

async fn batch_toggle(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchToggleReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    if body.ids.is_empty() {
        return Err(AppError::bad("ids 不能为空"));
    }
    let mut n = 0u64;
    for chunk in body.ids.chunks(500) {
        let ph = vec!["?"; chunk.len()].join(",");
        let sql = if body.enabled {
            format!("UPDATE port_forwards SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id IN ({ph})")
        } else {
            format!("UPDATE port_forwards SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id IN ({ph})")
        };
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        n += q.execute(&state.pool).await?.rows_affected();
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_toggle_forward",
        Some(ET),
        None,
        None,
        serde_json::json!({"ids": body.ids, "enabled": body.enabled, "updated": n}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"updated": n}))))
}

async fn batch_move(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<BatchMoveReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    if body.ids.is_empty() {
        return Err(AppError::bad("ids 不能为空"));
    }
    node_exists(&state.pool, body.node_id).await?;
    let mut n = 0u64;
    for chunk in body.ids.chunks(500) {
        let ph = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "UPDATE port_forwards SET node_id = ?, updated_at = datetime('now') WHERE id IN ({ph})"
        );
        let mut q = sqlx::query(&sql).bind(body.node_id);
        for id in chunk {
            q = q.bind(id);
        }
        n += q.execute(&state.pool).await?.rows_affected();
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "batch_move_forward",
        Some(ET),
        None,
        None,
        serde_json::json!({"ids": body.ids, "node_id": body.node_id, "updated": n}),
        &ip,
    )
    .await;
    crate::services::runtime::on_entries_changed(&state).await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({"updated": n}))))
}
