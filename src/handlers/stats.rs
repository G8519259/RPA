//! P9 —— 统计 API：按小时/天序列、总览

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;

use crate::error::AppResult;
use crate::middleware::auth_user;
use crate::models::ApiResp;
use crate::state::AppState;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/stats")
            .route("/hourly", web::get().to(hourly))
            .route("/daily", web::get().to(daily))
            .route("/overview", web::get().to(overview)),
    );
}

#[derive(Deserialize)]
pub struct StatsQuery {
    pub from: Option<String>, // "2026-09-01" 或 "2026-09-01T00"
    pub to: Option<String>,
    pub node_id: Option<i64>,
    pub rule_type: Option<String>,
    pub rule_id: Option<i64>,
}

async fn series(
    pool: &sqlx::SqlitePool,
    table: &str,
    time_col: &str,
    q: &StatsQuery,
) -> AppResult<Vec<serde_json::Value>> {
    // 动态 WHERE：收集条件后拼接（无条件时不加 WHERE）
    let mut qb = sqlx::QueryBuilder::new(format!(
        "SELECT {time_col} AS t, SUM(total_connections) AS c, SUM(total_bytes_up) AS up, SUM(total_bytes_down) AS down FROM {table}"
    ));
    let mut has_where = false;
    macro_rules! cond {
        ($frag:expr, $val:expr) => {{
            if !has_where {
                qb.push(" WHERE ");
                has_where = true;
            } else {
                qb.push(" AND ");
            }
            qb.push($frag);
            qb.push_bind($val);
        }};
    }
    if let Some(from) = q.from.as_deref().filter(|s| !s.is_empty()) {
        cond!(format!("{time_col} >= "), from);
    }
    if let Some(to) = q.to.as_deref().filter(|s| !s.is_empty()) {
        cond!(format!("{time_col} <= "), to);
    }
    if let Some(nid) = q.node_id {
        cond!("node_id = ", nid);
    }
    if let Some(rt) = q.rule_type.as_deref().filter(|s| !s.is_empty()) {
        cond!("rule_type = ", rt);
    }
    if let Some(rid) = q.rule_id {
        cond!("rule_id = ", rid);
    }
    qb.push(format!(" GROUP BY {time_col} ORDER BY {time_col}"));
    let rows: Vec<(String, Option<i64>, Option<i64>, Option<i64>)> =
        qb.build_query_as().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|(t, c, up, down)| {
            serde_json::json!({
                "time": t,
                "connections": c.unwrap_or(0),
                "bytes_up": up.unwrap_or(0),
                "bytes_down": down.unwrap_or(0),
            })
        })
        .collect())
}

/// GET /api/stats/hourly
pub async fn hourly(
    state: web::Data<AppState>,
    req: HttpRequest,
    q: web::Query<StatsQuery>,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let items = series(&state.pool, "stats_hourly", "stat_time", &q).await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "items": items }))))
}

/// GET /api/stats/daily
pub async fn daily(
    state: web::Data<AppState>,
    req: HttpRequest,
    q: web::Query<StatsQuery>,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let items = series(&state.pool, "stats_daily", "stat_date", &q).await?;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "items": items }))))
}

/// GET /api/stats/overview —— 今日/昨日流量连接数、Top N 条目/节点、在线节点数、即将到期、接近超限
pub async fn overview(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let pool = &state.pool;
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let yesterday = (chrono::Local::now() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string();

    // 今日/昨日：优先用 stats_daily，没有则回退到 access_logs 实时统计
    async fn day_sum(
        pool: &sqlx::SqlitePool,
        date: &str,
    ) -> AppResult<(i64, i64, i64)> {
        let r: Option<(Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT SUM(total_connections), SUM(total_bytes_up), SUM(total_bytes_down)
             FROM stats_daily WHERE stat_date = ?",
        )
        .bind(date)
        .fetch_optional(pool)
        .await?;
        let (c, up, down) = r.unwrap_or((None, None, None));
        if c.unwrap_or(0) > 0 || up.unwrap_or(0) > 0 {
            return Ok((c.unwrap_or(0), up.unwrap_or(0), down.unwrap_or(0)));
        }
        // 回退：直接从 access_logs 按 started_at 前缀统计
        let r2: (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0)
             FROM access_logs WHERE substr(started_at, 1, 10) = ?",
        )
        .bind(date)
        .fetch_one(pool)
        .await?;
        Ok((r2.0.unwrap_or(0), r2.1.unwrap_or(0), r2.2.unwrap_or(0)))
    }
    let (tc, tup, tdown) = day_sum(pool, &today).await?;
    let (yc, yup, ydown) = day_sum(pool, &yesterday).await?;

    // Top N 条目（近 7 天流量）
    let week_ago = (chrono::Local::now() - chrono::Duration::days(7))
        .format("%Y-%m-%d")
        .to_string();
    let top_rules: Vec<(String, i64, Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT rule_type, rule_id, SUM(total_connections), SUM(total_bytes_up), SUM(total_bytes_down)
         FROM stats_daily WHERE stat_date >= ? GROUP BY rule_type, rule_id
         ORDER BY SUM(total_bytes_up) + SUM(total_bytes_down) DESC LIMIT 10",
    )
    .bind(&week_ago)
    .fetch_all(pool)
    .await?;
    // 补条目名称
    let mut top_rules_json = Vec::new();
    for (rt, rid, c, up, down) in top_rules {
        let name: Option<String> = entry_name(pool, &rt, rid).await;
        top_rules_json.push(serde_json::json!({
            "rule_type": rt, "rule_id": rid, "name": name,
            "connections": c.unwrap_or(0),
            "bytes_up": up.unwrap_or(0), "bytes_down": down.unwrap_or(0),
        }));
    }

    // Top N 节点
    let top_nodes: Vec<(i64, Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT node_id, SUM(total_connections), SUM(total_bytes_up), SUM(total_bytes_down)
         FROM stats_daily WHERE stat_date >= ? GROUP BY node_id
         ORDER BY SUM(total_bytes_up) + SUM(total_bytes_down) DESC LIMIT 10",
    )
    .bind(&week_ago)
    .fetch_all(pool)
    .await?;
    let mut top_nodes_json = Vec::new();
    for (nid, c, up, down) in top_nodes {
        let name: Option<String> =
            sqlx::query_scalar("SELECT name FROM nodes WHERE id = ?")
                .bind(nid)
                .fetch_optional(pool)
                .await?;
        top_nodes_json.push(serde_json::json!({
            "node_id": nid, "name": name,
            "connections": c.unwrap_or(0),
            "bytes_up": up.unwrap_or(0), "bytes_down": down.unwrap_or(0),
        }));
    }

    // 在线节点数
    let timeout = state.cfg.nodes.heartbeat_timeout_secs;
    let online_nodes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM nodes WHERE enabled = 1 AND (
           is_local = 1 OR (last_heartbeat_at IS NOT NULL AND
           strftime('%s','now') - strftime('%s', last_heartbeat_at) <= ?))",
    )
    .bind(timeout)
    .fetch_one(pool)
    .await?;
    let total_nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE enabled = 1")
        .fetch_one(pool)
        .await?;

    // 即将到期（7 天内）
    let expiring = expiring_entries(pool).await?;
    // 接近超限（使用率 >= 80%）
    let near_quota = near_quota_entries(pool).await?;

    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "today": { "connections": tc, "bytes_up": tup, "bytes_down": tdown },
        "yesterday": { "connections": yc, "bytes_up": yup, "bytes_down": ydown },
        "top_rules": top_rules_json,
        "top_nodes": top_nodes_json,
        "online_nodes": online_nodes,
        "total_nodes": total_nodes,
        "expiring": expiring,
        "near_quota": near_quota,
    }))))
}

async fn entry_name(pool: &sqlx::SqlitePool, rule_type: &str, rule_id: i64) -> Option<String> {
    let table = match rule_type {
        "proxy" => "proxy_rules",
        "forward" => "port_forwards",
        "tunnel" => "tunnels",
        _ => return None,
    };
    sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE id = ?"))
        .bind(rule_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

/// 7 天内到期的启用条目
async fn expiring_entries(pool: &sqlx::SqlitePool) -> AppResult<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for (table, etype) in [
        ("proxy_rules", "proxy"),
        ("port_forwards", "forward"),
        ("tunnels", "tunnel"),
    ] {
        let rows: Vec<(i64, String, String)> = sqlx::query_as(&format!(
            "SELECT id, name, expires_at FROM {table}
             WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at != ''
             AND date(expires_at) <= date('now', 'localtime', '+7 days')
             ORDER BY expires_at LIMIT 20"
        ))
        .fetch_all(pool)
        .await?;
        for (id, name, exp) in rows {
            out.push(serde_json::json!({
                "entry_type": etype, "entry_id": id, "name": name, "expires_at": exp,
            }));
        }
    }
    // 订阅（7 天内到期）
    let subs: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, name, expires_at FROM subscriptions
         WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at != ''
         AND date(expires_at) <= date('now', 'localtime', '+7 days')
         ORDER BY expires_at LIMIT 20",
    )
    .fetch_all(pool)
    .await?;
    for (id, name, exp) in subs {
        out.push(serde_json::json!({
            "entry_type": "subscription", "entry_id": id, "name": name, "expires_at": exp,
        }));
    }
    Ok(out)
}

/// 配额使用率 >= 80% 的条目
async fn near_quota_entries(pool: &sqlx::SqlitePool) -> AppResult<Vec<serde_json::Value>> {
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT entry_type, entry_id, quota_bytes, used_bytes FROM entry_quotas
         WHERE quota_bytes > 0 AND CAST(used_bytes AS REAL) / quota_bytes >= 0.8
         ORDER BY CAST(used_bytes AS REAL) / quota_bytes DESC LIMIT 20",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for (et, eid, quota, used) in rows {
        let name = entry_name(pool, &et, eid).await;
        out.push(serde_json::json!({
            "entry_type": et, "entry_id": eid, "name": name,
            "quota_bytes": quota, "used_bytes": used,
            "usage": used as f64 / quota as f64,
        }));
    }
    Ok(out)
}
