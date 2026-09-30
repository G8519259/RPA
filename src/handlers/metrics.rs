//! P13 —— Prometheus 指标（GET /metrics，Prometheus 文本格式，需登录）

use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::OnceLock;

use crate::error::AppResult;
use crate::middleware::auth_user;
use crate::state::AppState;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/metrics", web::get().to(metrics));
}

fn start_time() -> &'static std::time::Instant {
    static T: OnceLock<std::time::Instant> = OnceLock::new();
    T.get_or_init(std::time::Instant::now)
}

pub async fn metrics(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    let _user = auth_user(&req)?;
    let p = &state.pool;

    let nodes_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
        .fetch_one(p)
        .await?;
    let nodes_online: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE online_state = 'online' AND enabled = 1")
            .fetch_one(p)
            .await?;
    let mut out = String::new();
    fn g(out: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"));
    }

    g(&mut out, "rpa_uptime_seconds", "Master 进程运行时长（秒）", start_time().elapsed().as_secs());
    g(&mut out, "rpa_nodes_total", "节点总数", nodes_total);
    g(&mut out, "rpa_nodes_online", "在线节点数", nodes_online);

    for (t, table) in [("proxy", "proxy_rules"), ("forward", "port_forwards"), ("tunnel", "tunnels")] {
        let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(p)
            .await?;
        let enabled: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE enabled = 1"))
            .fetch_one(p)
            .await?;
        out.push_str(&format!(
            "# HELP rpa_entries_by_type 按类型统计的条目数\n# TYPE rpa_entries_by_type gauge\nrpa_entries_by_type{{type=\"{t}\"}} {total}\n"
        ));
        out.push_str(&format!(
            "# HELP rpa_entries_enabled_by_type 按类型统计的启用条目数\n# TYPE rpa_entries_enabled_by_type gauge\nrpa_entries_enabled_by_type{{type=\"{t}\"}} {enabled}\n"
        ));
    }

    let subs_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions")
        .fetch_one(p)
        .await?;
    let subs_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE enabled = 1")
            .fetch_one(p)
            .await?;
    g(&mut out, "rpa_subscriptions_total", "订阅总数", subs_total);
    g(&mut out, "rpa_subscriptions_enabled", "启用的订阅数", subs_enabled);

    let traffic: Option<i64> = sqlx::query_scalar("SELECT SUM(used_bytes) FROM entry_quotas")
        .fetch_one(p)
        .await?;
    g(&mut out, 
        "rpa_traffic_used_bytes_total",
        "配额统计的累计用量（字节）",
        traffic.unwrap_or(0),
    );

    let ev_pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_events WHERE status = 'pending'")
            .fetch_one(p)
            .await?;
    let ev_failed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_events WHERE status = 'failed'")
            .fetch_one(p)
            .await?;
    g(&mut out, "rpa_alert_events_pending", "待发送的告警事件数", ev_pending);
    g(&mut out, "rpa_alert_events_failed", "发送失败的告警事件数", ev_failed);

    let sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')")
            .fetch_one(p)
            .await?;
    g(&mut out, "rpa_sessions_active", "有效会话数", sessions);

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(out))
}
