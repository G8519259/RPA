use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::handlers::entries_common::{delete_entries_tx, get_entry, list_entries, set_entry_tags};
use crate::middleware::auth_user;
use crate::models::{ApiResp, ListQuery};
use crate::state::AppState;
use crate::util::{calc_expires, client_ip};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

const ET: &str = "proxy";

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
pub struct ProxyCreate {
    pub node_id: i64,
    pub name: String,
    pub upstream_type: Option<String>,
    pub upstream_addr: String,
    pub listen_addr: Option<String>,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub remark: Option<String>,
    pub group_id: Option<i64>,
    pub enabled: Option<bool>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<String>,
    pub tag_ids: Option<Vec<i64>>,
}

#[derive(Deserialize)]
pub struct ProxyUpdate {
    pub node_id: Option<i64>,
    pub name: Option<String>,
    pub upstream_type: Option<String>,
    pub upstream_addr: Option<String>,
    pub listen_addr: Option<Option<String>>,
    pub auth_user: Option<Option<String>>,
    pub auth_pass: Option<Option<String>>,
    pub export_host: Option<Option<String>>,
    pub export_port: Option<Option<i64>>,
    pub extra: Option<Option<String>>,
    pub remark: Option<Option<String>>,
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

fn validate_name(name: &str) -> AppResult<()> {
    let t = name.trim();
    if t.is_empty() || t.chars().count() > 100 {
        return Err(AppError::bad("名称不能为空且不超过 100 字符"));
    }
    Ok(())
}

fn validate_addr(addr: &str) -> AppResult<()> {
    let t = addr.trim();
    if t.is_empty() || t.len() > 255 {
        return Err(AppError::bad("地址不能为空且不超过 255 字符"));
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
    body: web::Json<ProxyCreate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let b = body.into_inner();
    validate_name(&b.name)?;
    let proto = b.upstream_type.unwrap_or_else(|| "http".into());
    if !matches!(proto.as_str(), "direct" | "http" | "https" | "socks5" | "ss" | "vmess" | "vless" | "trojan" | "hysteria2" | "tuic") {
        return Err(AppError::bad("upstream_type 不支持"));
    }
    if proto != "direct" {
        validate_addr(&b.upstream_addr)?;
    }
    if let Some(la) = b.listen_addr.as_deref() {
        validate_addr(la)?;
    }
    node_exists(&state.pool, b.node_id).await?;
    let expires = calc_expires(
        b.expire_preset.as_deref().unwrap_or("permanent"),
        b.expires_at.as_deref(),
    )?;

    let mut tx = state.pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO proxy_rules
           (node_id, name, upstream_type, upstream_addr, listen_addr,
            auth_user, auth_pass, export_host, export_port, extra,
            remark, group_id, enabled, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(b.node_id)
    .bind(b.name.trim())
    .bind(&proto)
    .bind(b.upstream_addr.trim())
    .bind(b.listen_addr.as_deref().map(str::trim))
    .bind(b.auth_user.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(b.auth_pass.as_deref().filter(|s| !s.is_empty()))
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
        "create_proxy",
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
    let v = get_entry(&state.pool, ET, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(v)))
}

async fn update(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    body: web::Json<ProxyUpdate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();

    get_entry(&state.pool, ET, id).await?;
    if let Some(n) = b.name.as_deref() {
        validate_name(n)?;
    }
    if let Some(a) = b.upstream_addr.as_deref() {
        validate_addr(a)?;
    }
    if let Some(Some(la)) = b.listen_addr.as_ref() {
        validate_addr(la)?;
    }
    if let Some(nid) = b.node_id {
        node_exists(&state.pool, nid).await?;
    }
    if let Some(p) = b.upstream_type.as_deref() {
        if !matches!(p, "http" | "https" | "socks5" | "ss" | "vmess" | "vless" | "trojan" | "hysteria2" | "tuic") {
            return Err(AppError::bad("upstream_type 不支持"));
        }
    }
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
            sqlx::query(concat!("UPDATE proxy_rules SET ", $col, " = ? WHERE id = ?"))
                .bind($val)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        };
    }
    if let Some(v) = b.node_id { set!("node_id", v); }
    if let Some(v) = b.name.as_deref() { set!("name", v.trim()); }
    if let Some(v) = b.upstream_type.as_deref() { set!("upstream_type", v); }
    if let Some(v) = b.upstream_addr.as_deref() { set!("upstream_addr", v.trim()); }
    if let Some(v) = b.listen_addr.as_ref() { set!("listen_addr", v.as_deref().map(str::trim)); }
    if let Some(v) = b.auth_user.as_ref() { set!("auth_user", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.auth_pass.as_ref() { set!("auth_pass", v.as_deref().filter(|s| !s.is_empty())); }
    if let Some(v) = b.export_host.as_ref() { set!("export_host", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.export_port { set!("export_port", v); }
    if let Some(v) = b.extra.as_ref() { set!("extra", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.remark.as_ref() { set!("remark", v.as_deref().map(str::trim).filter(|s| !s.is_empty())); }
    if let Some(v) = b.group_id { set!("group_id", v); }
    if let Some(v) = expires {
        let exp: Option<String> = v.clone();
        set!("expires_at", v);
        super::entries_common::recover_expired_if_future(&mut tx, ET, id, exp.as_deref()).await?;
    }
    sqlx::query("UPDATE proxy_rules SET updated_at = datetime('now') WHERE id = ?")
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
        "update_proxy",
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
        "delete_proxy",
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
    get_entry(&state.pool, ET, id).await?;
    if body.enabled {
        sqlx::query(
            "UPDATE proxy_rules SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE proxy_rules SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&state.pool)
        .await?;
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        if body.enabled { "enable_proxy" } else { "disable_proxy" },
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
        "batch_delete_proxy",
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
            format!("UPDATE proxy_rules SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id IN ({ph})")
        } else {
            format!("UPDATE proxy_rules SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id IN ({ph})")
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
        "batch_toggle_proxy",
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
            "UPDATE proxy_rules SET node_id = ?, updated_at = datetime('now') WHERE id IN ({ph})"
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
        "batch_move_proxy",
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
