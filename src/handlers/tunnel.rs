use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::handlers::entries_common::{delete_entries_tx, get_entry, list_entries, set_entry_tags};
use crate::middleware::auth_user;
use crate::models::{ApiResp, ListQuery};
use crate::state::AppState;
use crate::util::{calc_expires, client_ip};
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

const ET: &str = "tunnel";

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
pub struct TunnelCreate {
    pub node_id: i64,
    pub name: String,
    pub tunnel_type: Option<String>,
    pub local_addr: String,
    pub remote_addr: String,
    pub token: Option<String>,
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
pub struct TunnelUpdate {
    pub node_id: Option<i64>,
    pub name: Option<String>,
    pub tunnel_type: Option<String>,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub token: Option<Option<String>>,
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

fn validate_addr(addr: &str, what: &str) -> AppResult<()> {
    let t = addr.trim();
    if t.is_empty() || t.len() > 255 {
        return Err(AppError::bad(format!("{what} 不能为空且不超过 255 字符")));
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
    body: web::Json<TunnelCreate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let b = body.into_inner();
    validate_name(&b.name)?;
    validate_addr(&b.local_addr, "本地地址")?;
    validate_addr(&b.remote_addr, "远端地址")?;
    let mode = b.tunnel_type.unwrap_or_else(|| "tcp".into());
    if !matches!(mode.as_str(), "tcp" | "ws" | "wss" | "reverse") {
        return Err(AppError::bad("tunnel_type 只能是 tcp/ws/wss/reverse"));
    }
    node_exists(&state.pool, b.node_id).await?;
    let expires = calc_expires(
        b.expire_preset.as_deref().unwrap_or("permanent"),
        b.expires_at.as_deref(),
    )?;

    let mut tx = state.pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO tunnels
           (node_id, name, tunnel_type, local_addr, remote_addr, token,
            export_host, export_port, extra,
            remark, group_id, enabled, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(b.node_id)
    .bind(b.name.trim())
    .bind(&mode)
    .bind(b.local_addr.trim())
    .bind(b.remote_addr.trim())
    .bind(b.token.as_deref().map(str::trim).filter(|s| !s.is_empty()))
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
        "create_tunnel",
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
    body: web::Json<TunnelUpdate>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let id = path.into_inner();
    let b = body.into_inner();

    get_entry(&state.pool, ET, id).await?;
    if let Some(n) = b.name.as_deref() { validate_name(n)?; }
    if let Some(a) = b.local_addr.as_deref() { validate_addr(a, "本地地址")?; }
    if let Some(a) = b.remote_addr.as_deref() { validate_addr(a, "远端地址")?; }
    if let Some(m) = b.tunnel_type.as_deref() {
        if !matches!(m, "tcp" | "ws") {
            return Err(AppError::bad("tunnel_type 只能是 tcp/ws/wss/reverse"));
        }
    }
    if let Some(nid) = b.node_id { node_exists(&state.pool, nid).await?; }
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
            sqlx::query(concat!("UPDATE tunnels SET ", $col, " = ? WHERE id = ?"))
                .bind($val)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        };
    }
    if let Some(v) = b.node_id { set!("node_id", v); }
    if let Some(v) = b.name.as_deref() { set!("name", v.trim()); }
    if let Some(v) = b.tunnel_type.as_deref() { set!("tunnel_type", v); }
    if let Some(v) = b.local_addr.as_deref() { set!("local_addr", v.trim()); }
    if let Some(v) = b.remote_addr.as_deref() { set!("remote_addr", v.trim()); }



    if let Some(v) = b.token.as_ref() { set!("token", v.as_deref().filter(|s| !s.is_empty())); }

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
    sqlx::query("UPDATE tunnels SET updated_at = datetime('now') WHERE id = ?")
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
        "update_tunnel",
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
        "delete_tunnel",
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
            "UPDATE tunnels SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE tunnels SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&state.pool)
        .await?;
    }
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        if body.enabled { "enable_tunnel" } else { "disable_tunnel" },
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
        "batch_delete_tunnel",
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
            format!("UPDATE tunnels SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now') WHERE id IN ({ph})")
        } else {
            format!("UPDATE tunnels SET enabled = 0, disabled_reason = 'manual', updated_at = datetime('now') WHERE id IN ({ph})")
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
        "batch_toggle_tunnel",
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
            "UPDATE tunnels SET node_id = ?, updated_at = datetime('now') WHERE id IN ({ph})"
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
        "batch_move_tunnel",
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
