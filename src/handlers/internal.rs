//! P10 —— Master 内部接口（Worker 用 Bearer token 认证）
//!
//! - POST /internal/node/heartbeat
//! - GET  /internal/node/config（If-None-Match → 304）
//! - POST /internal/node/logs/access
//! - POST /internal/node/stats/flush
//! - POST /internal/node/metrics
//! - POST /internal/node/runtime_status

use actix_web::{HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::models::ApiResp;
use crate::services::runtime::load_desired_for;
use crate::state::AppState;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/internal/node")
            .route("/heartbeat", web::post().to(heartbeat))
            .route("/config", web::get().to(config))
            .route("/logs/access", web::post().to(logs_access))
            .route("/stats/flush", web::post().to(stats_flush))
            .route("/metrics", web::post().to(metrics))
            .route("/runtime_status", web::post().to(runtime_status)),
    );
}

struct NodeIdent {
    id: i64,
    name: String,
}

/// Bearer token → 节点身份（注意不要在日志里打印 token）
async fn auth_node(state: &AppState, req: &HttpRequest) -> AppResult<NodeIdent> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::unauthorized("缺少 Bearer token"))?;
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM nodes WHERE api_token = ? AND enabled = 1")
            .bind(token)
            .fetch_optional(&state.pool)
            .await?;
    match row {
        Some((id, name)) => Ok(NodeIdent { id, name }),
        None => Err(AppError::unauthorized("无效的节点 token")),
    }
}

// ============ 心跳 ============

#[derive(Deserialize)]
pub struct HeartbeatReq {
    pub version: Option<String>,
    pub load: Option<HeartbeatLoad>,
}

#[derive(Deserialize, Serialize)]
pub struct HeartbeatLoad {
    pub cpu: Option<f64>,
    pub mem: Option<f64>,
    pub conns: Option<i64>,
}

/// Worker 每 10 秒心跳；Master 更新心跳时间/负载/版本
pub async fn heartbeat(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<HeartbeatReq>,
) -> AppResult<HttpResponse> {
    let node = auth_node(&state, &req).await?;
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let load_json = body
        .load
        .as_ref()
        .map(|l| serde_json::to_string(l).unwrap_or_default());
    sqlx::query(
        "UPDATE nodes SET last_heartbeat_at = ?, last_load = COALESCE(?, last_load),
         version = COALESCE(?, version), online_state = 'online', updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(&now)
    .bind(load_json)
    .bind(body.version.as_deref())
    .bind(node.id)
    .execute(&state.pool)
    .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "node_id": node.id }))))
}

// ============ 配置下发 ============

/// config_version：三张条目表 MAX(updated_at) + 条目数 + 启用数的哈希
async fn config_version(pool: &sqlx::SqlitePool, node_id: i64) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    for table in ["proxy_rules", "port_forwards", "tunnels"] {
        let row: Option<(Option<String>, i64, i64)> = sqlx::query_as(&format!(
            "SELECT MAX(updated_at), COUNT(*), SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END)
             FROM {table} WHERE node_id = ?"
        ))
        .bind(node_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
        if let Some((max_upd, cnt, en)) = row {
            max_upd.hash(&mut h);
            cnt.hash(&mut h);
            en.hash(&mut h);
        }
    }
    format!("{:x}", h.finish())
}

/// Worker 每 15 秒拉取本节点全部启用条目；无变化返回 304
pub async fn config(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> AppResult<HttpResponse> {
    let node = auth_node(&state, &req).await?;
    let ver = config_version(&state.pool, node.id).await;
    if let Some(inm) = req
        .headers()
        .get("If-None-Match")
        .and_then(|v| v.to_str().ok())
    {
        if inm.trim().trim_matches('"') == ver {
            return Ok(HttpResponse::NotModified().finish());
        }
    }
    let desired = load_desired_for(&state.pool, node.id).await;
    let entries: Vec<_> = desired.into_values().collect();
    Ok(HttpResponse::Ok()
        .insert_header(("ETag", format!("\"{ver}\"")))
        .json(ApiResp::ok(serde_json::json!({
            "config_version": ver,
            "entries": entries,
        }))))
}

// ============ 访问日志上报 ============

#[derive(Deserialize)]
pub struct AccessBatch {
    pub items: Vec<AccessItem>,
}

#[derive(Deserialize)]
pub struct AccessItem {
    pub rule_type: String,
    pub rule_id: i64,
    pub client_ip: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub status: Option<String>,
}

pub async fn logs_access(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<AccessBatch>,
) -> AppResult<HttpResponse> {
    let node = auth_node(&state, &req).await?;
    if body.items.len() > 5000 {
        return Err(AppError::bad("单次上报最多 5000 条"));
    }
    let mut tx = state.pool.begin().await?;
    for it in &body.items {
        sqlx::query(
            "INSERT INTO access_logs (node_id, rule_type, rule_id, client_ip, started_at, ended_at, bytes_up, bytes_down, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(node.id)
        .bind(&it.rule_type)
        .bind(it.rule_id)
        .bind(it.client_ip.as_deref().unwrap_or(""))
        .bind(&it.started_at)
        .bind(it.ended_at.as_deref())
        .bind(it.bytes_up)
        .bind(it.bytes_down)
        .bind(it.status.as_deref().unwrap_or("ok"))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "received": body.items.len() }))))
}

// ============ 统计增量上报 ============

#[derive(Deserialize)]
pub struct StatsFlush {
    pub items: Vec<StatsDelta>,
}

#[derive(Deserialize)]
pub struct StatsDelta {
    pub rule_type: String,
    pub rule_id: i64,
    pub connections: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
}

/// 小时统计增量累加入库；同一事务内对每个条目调用 add_usage 累计配额用量
pub async fn stats_flush(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<StatsFlush>,
) -> AppResult<HttpResponse> {
    let node = auth_node(&state, &req).await?;
    if body.items.len() > 2000 {
        return Err(AppError::bad("单次上报最多 2000 条"));
    }
    // stat_time 取当前小时（Worker 侧 10 秒批量，落在当前小时）
    let stat_time = chrono::Local::now().format("%Y-%m-%dT%H").to_string();
    let mut tx = state.pool.begin().await?;
    for it in &body.items {
        sqlx::query(
            "INSERT INTO stats_hourly (stat_time, node_id, rule_type, rule_id, total_connections, total_bytes_up, total_bytes_down)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (stat_time, node_id, rule_type, rule_id) DO UPDATE SET
               total_connections = stats_hourly.total_connections + excluded.total_connections,
               total_bytes_up = stats_hourly.total_bytes_up + excluded.total_bytes_up,
               total_bytes_down = stats_hourly.total_bytes_down + excluded.total_bytes_down",
        )
        .bind(&stat_time)
        .bind(node.id)
        .bind(&it.rule_type)
        .bind(it.rule_id)
        .bind(it.connections)
        .bind(it.bytes_up)
        .bind(it.bytes_down)
        .execute(&mut *tx)
        .await?;
        crate::services::quota::add_usage(&mut tx, &it.rule_type, it.rule_id, it.bytes_up, it.bytes_down)
            .await?;
    }
    tx.commit().await?;
    // 精度：flush 完立刻检查本次涉及条目的配额，把"超限→停用"延迟压到约 10 秒
    let tz_offset = state.cfg.time.timezone_offset_hours;
    let base_url = state.cfg.server.public_base_url.clone();
    {
        use std::collections::HashSet;
        let mut seen: HashSet<(String, i64)> = HashSet::new();
        for it in &body.items {
            if seen.insert((it.rule_type.clone(), it.rule_id)) {
                if let Err(e) =
                    crate::services::lifecycle::check_quota_now(&state.pool, &it.rule_type, it.rule_id, tz_offset, &base_url)
                        .await
                {
                    tracing::warn!("check_quota_now 失败 {}/{}: {e}", it.rule_type, it.rule_id);
                }
            }
        }
    }
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "received": body.items.len() }))))
}

// ============ 指标上报 ============

#[derive(Deserialize)]
pub struct MetricsReport {
    pub cpu: Option<f64>,
    pub mem: Option<f64>,
    pub conns: Option<i64>,
    pub net_up_bps: Option<i64>,
    pub net_down_bps: Option<i64>,
}

pub async fn metrics(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<MetricsReport>,
) -> AppResult<HttpResponse> {
    let node = auth_node(&state, &req).await?;
    let at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query(
        "INSERT INTO metrics_snapshots (node_id, collected_at, cpu, mem, conns, net_up_bps, net_down_bps)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(node.id)
    .bind(&at)
    .bind(body.cpu)
    .bind(body.mem)
    .bind(body.conns)
    .bind(body.net_up_bps)
    .bind(body.net_down_bps)
    .execute(&state.pool)
    .await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "ok": true }))))
}

// ============ 运行状态上报 ============

#[derive(Deserialize)]
pub struct RuntimeStatusBatch {
    pub items: Vec<RuntimeStatusItem>,
}

#[derive(Deserialize)]
pub struct RuntimeStatusItem {
    pub entry_type: String,
    pub entry_id: i64,
    pub status: String,
    pub conns: i64,
}

pub async fn runtime_status(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<RuntimeStatusBatch>,
) -> AppResult<HttpResponse> {
    let node = auth_node(&state, &req).await?;
    let node_name = node.name.clone();
    let base_url = state.cfg.server.public_base_url.clone();
    let mut tx = state.pool.begin().await?;
    let mut new_errors: Vec<(String, i64, String)> = Vec::new(); // (entry_type, entry_id, status)
    for it in &body.items {
        // P12：非 error → error:<原因> 的翻转才告警（冷却在 emit 内按 1 小时规则）
        let prev: Option<String> = sqlx::query_scalar(
            "SELECT status FROM node_entry_status
              WHERE node_id = ? AND entry_type = ? AND entry_id = ?",
        )
        .bind(node.id)
        .bind(&it.entry_type)
        .bind(it.entry_id)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();
        sqlx::query(
            "INSERT INTO node_entry_status (node_id, entry_type, entry_id, status, conns, updated_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT (node_id, entry_type, entry_id) DO UPDATE SET
               status = excluded.status, conns = excluded.conns, updated_at = datetime('now')",
        )
        .bind(node.id)
        .bind(&it.entry_type)
        .bind(it.entry_id)
        .bind(&it.status)
        .bind(it.conns)
        .execute(&mut *tx)
        .await?;
        if it.status.starts_with("error:")
            && !prev.as_deref().unwrap_or("").starts_with("error:")
        {
            new_errors.push((it.entry_type.clone(), it.entry_id, it.status.clone()));
        }
    }
    tx.commit().await?;
    // 事务外发告警；条目名尽量从本地库查
    for (entry_type, entry_id, status) in new_errors {
        let table = match entry_type.as_str() {
            "proxy" => "proxy_rules",
            "forward" => "port_forwards",
            "tunnel" => "tunnels",
            _ => continue,
        };
        let name: Option<String> = sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE id = ?"))
            .bind(entry_id)
            .fetch_optional(&state.pool)
            .await?
            .flatten();
        let reason = status.strip_prefix("error:").unwrap_or(&status);
        let _ = crate::services::alert::emit(
            &state.pool,
            crate::services::alert::AlertDraft::runtime_error(
                &entry_type,
                entry_id,
                name.as_deref().unwrap_or("未知条目"),
                reason,
                Some(&node_name),
                &base_url,
            ),
        )
        .await;
    }
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "received": body.items.len() }))))
}
