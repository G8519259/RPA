//! P9 —— 监控 API：节点状态、条目实时状态、节点指标序列

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;

use crate::error::AppResult;
use crate::middleware::auth_user;
use crate::models::ApiResp;
use crate::state::AppState;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/monitor")
            .route("/nodes", web::get().to(nodes))
            .route("/rules", web::get().to(rules))
            .route("/nodes/{id}/metrics", web::get().to(node_metrics)),
    );
}

fn is_online(is_local: i64, last_hb: Option<&str>, timeout: i64) -> bool {
    if is_local == 1 {
        return true;
    }
    match last_hb {
        Some(s) if !s.is_empty() => {
            // last_heartbeat_at 是 "YYYY-MM-DD HH:MM:SS" 本地时间
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                let hb = dt.and_local_timezone(chrono::Local).single();
                if let Some(hb) = hb {
                    return (chrono::Local::now() - hb).num_seconds() <= timeout;
                }
            }
            false
        }
        _ => false,
    }
}

/// GET /api/monitor/nodes —— 各节点在线状态、CPU/内存/连接数、最近心跳
pub async fn nodes(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let pool = &state.pool;
    let timeout = state.cfg.nodes.heartbeat_timeout_secs;
    let rows: Vec<(i64, String, i64, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT id, name, is_local, addr, version, last_heartbeat_at FROM nodes ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
    // 本机实时连接数
    let local_conns: i64 = state
        .runtime
        .status_snapshot()
        .await
        .iter()
        .map(|s| s["conns"].as_u64().unwrap_or(0) as i64)
        .sum();
    let mut items = Vec::new();
    for (id, name, is_local, addr, version, last_hb) in rows {
        let online = is_online(is_local, last_hb.as_deref(), timeout);
        // 最近一条指标快照
        let m: Option<(Option<f64>, Option<f64>, Option<i64>, Option<i64>, Option<i64>, String)> =
            sqlx::query_as(
                "SELECT cpu, mem, conns, net_up_bps, net_down_bps, collected_at
                 FROM metrics_snapshots WHERE node_id = ? ORDER BY collected_at DESC LIMIT 1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?;
        let (cpu, mem, conns, up_bps, down_bps, at) = m
            .map(|(a, b, c, d, e, f)| (a, b, c, d, e, Some(f)))
            .unwrap_or((None, None, None, None, None, None));
        items.push(serde_json::json!({
            "id": id, "name": name, "is_local": is_local, "addr": addr, "version": version,
            "online": online, "last_heartbeat_at": last_hb,
            "cpu": cpu, "mem": mem,
            "conns": if is_local == 1 { Some(local_conns) } else { conns },
            "net_up_bps": up_bps, "net_down_bps": down_bps,
            "metrics_at": at,
        }));
    }
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "items": items }))))
}

/// GET /api/monitor/rules —— 各条目实时连接数、近 1 分钟速率、运行状态
pub async fn rules(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let pool = &state.pool;
    let snap = state.runtime.status_snapshot().await;
    let mut rt: std::collections::HashMap<(String, i64), &serde_json::Value> =
        std::collections::HashMap::new();
    for s in &snap {
        let et = s["entry_type"].as_str().unwrap_or("").to_string();
        let id = s["entry_id"].as_i64().unwrap_or(0);
        rt.insert((et, id), s);
    }
    // 近 1 分钟的流量（按 node + rule 聚合）
    let minute_ago = (chrono::Local::now() - chrono::Duration::seconds(60))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let recent: Vec<(i64, String, i64, Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT node_id, rule_type, rule_id, COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0)
         FROM access_logs WHERE started_at >= ? GROUP BY node_id, rule_type, rule_id",
    )
    .bind(&minute_ago)
    .fetch_all(pool)
    .await?;
    let mut recent_map = std::collections::HashMap::new();
    for (nid, t, id, c, up, down) in recent {
        recent_map.insert(
            (nid, t, id),
            (c.unwrap_or(0), up.unwrap_or(0), down.unwrap_or(0)),
        );
    }
    let mut items = Vec::new();
    // 所有节点（本机用 runtime 快照，Worker 节点用上报的 node_entry_status）
    let nodes: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM nodes WHERE enabled = 1 ORDER BY id")
            .fetch_all(pool)
            .await?;
    // Worker 节点上报的运行状态
    let wstat: Vec<(i64, String, i64, String, i64, String)> = sqlx::query_as(
        "SELECT node_id, entry_type, entry_id, status, conns, updated_at FROM node_entry_status",
    )
    .fetch_all(pool)
    .await?;
    let mut wmap = std::collections::HashMap::new();
    for (nid, et, eid, st, c, upd) in wstat {
        wmap.insert((nid, et, eid), (st, c, upd));
    }
    for (nid, nname) in nodes {
        for (table, etype) in [
            ("proxy_rules", "proxy"),
            ("port_forwards", "forward"),
            ("tunnels", "tunnel"),
        ] {
            let rows: Vec<(i64, String, i64)> = sqlx::query_as(&format!(
                "SELECT id, name, enabled FROM {table} WHERE node_id = ? ORDER BY id"
            ))
            .bind(nid)
            .fetch_all(pool)
            .await?;
            for (id, name, enabled) in rows {
                let key = (etype.to_string(), id);
                let (status, conns, status_at): (String, i64, Option<String>) = if nid == 1 {
                    let s = rt.get(&key);
                    (
                        s.map(|x| x["status"].as_str().unwrap_or("?").to_string())
                            .unwrap_or_else(|| "stopped".into()),
                        s.map(|x| x["conns"].as_u64().unwrap_or(0)).unwrap_or(0) as i64,
                        None,
                    )
                } else {
                    match wmap.get(&(nid, etype.to_string(), id)) {
                        Some((st, c, upd)) => (st.clone(), *c, Some(upd.clone())),
                        None => ("unknown".into(), 0, None),
                    }
                };
                let (rc, rup, rdown) = recent_map
                    .get(&(nid, etype.to_string(), id))
                    .copied()
                    .unwrap_or((0, 0, 0));
                items.push(serde_json::json!({
                    "node_id": nid, "node_name": nname,
                    "entry_type": etype, "entry_id": id, "name": name, "enabled": enabled,
                    "runtime_status": status, "conns": conns, "status_at": status_at,
                    "last_minute": { "connections": rc, "bytes_up": rup, "bytes_down": rdown,
                        "up_bps": rup / 60, "down_bps": rdown / 60 },
                }));
            }
        }
    }
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "items": items }))))
}

#[derive(Deserialize)]
pub struct MetricsQuery {
    pub minutes: Option<i64>,
}

/// GET /api/monitor/nodes/{id}/metrics —— 最近 N 分钟指标序列（默认 30）
pub async fn node_metrics(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    q: web::Query<MetricsQuery>,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let minutes = q.minutes.unwrap_or(30).clamp(1, 1440);
    let cutoff = (chrono::Local::now() - chrono::Duration::minutes(minutes))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let rows: Vec<(String, Option<f64>, Option<f64>, Option<i64>, Option<i64>, Option<i64>)> =
        sqlx::query_as(
            "SELECT collected_at, cpu, mem, conns, net_up_bps, net_down_bps
             FROM metrics_snapshots WHERE node_id = ? AND collected_at >= ?
             ORDER BY collected_at",
        )
        .bind(path.into_inner())
        .bind(&cutoff)
        .fetch_all(&state.pool)
        .await?;
    let items: Vec<_> = rows
        .into_iter()
        .map(|(at, cpu, mem, conns, up, down)| {
            serde_json::json!({
                "at": at, "cpu": cpu, "mem": mem, "conns": conns,
                "net_up_bps": up, "net_down_bps": down,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "items": items }))))
}
