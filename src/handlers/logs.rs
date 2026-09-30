//! P7 —— 日志与审计 API（§6.7）：
//! - GET  /api/logs/audit
//! - GET  /api/logs/access
//! - GET  /api/logs/access/export   (CSV)
//! - GET  /api/logs/subscription
//! - POST /api/logs/cleanup         {"days": N} 手动清理 N 天前日志

use actix_web::{HttpResponse, web};
use serde::Deserialize;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::ApiResp;
use crate::state::AppState;
use crate::util::client_ip;

use actix_web::HttpRequest;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/logs")
            .route("/audit", web::get().to(audit_list))
            .route("/access", web::get().to(access_list))
            .route("/access/export", web::get().to(access_export))
            .route("/subscription", web::get().to(subscription_list))
            .route("/cleanup", web::post().to(cleanup)),
    );
}

fn page_of(page: Option<i64>, page_size: Option<i64>) -> (i64, i64) {
    (page.unwrap_or(1).max(1), page_size.unwrap_or(20).clamp(1, 100))
}

// ============ GET /api/logs/audit ============

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub user: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

pub async fn audit_list(
    state: web::Data<AppState>,
    q: web::Query<AuditQuery>,
) -> AppResult<HttpResponse> {
    let (page, page_size) = page_of(q.page, q.page_size);
    let user = q.user.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let action = q.action.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let rtype = q.resource_type.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let from = q.from.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let to = q.to.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let total: i64 = {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM audit_logs WHERE ");
        let mut sep = qb.separated(" AND ");
        sep.push("1=1");
        if let Some(u) = user { sep.push("actor_name = "); sep.push_bind_unseparated(u); }
        if let Some(a) = action { sep.push("action = "); sep.push_bind_unseparated(a); }
        if let Some(r) = rtype { sep.push("resource_type = "); sep.push_bind_unseparated(r); }
        if let Some(f) = from { sep.push("created_at >= "); sep.push_bind_unseparated(f); }
        if let Some(t) = to { sep.push("created_at <= "); sep.push_bind_unseparated(t); }
        drop(sep);
        qb.build_query_scalar().fetch_one(&state.pool).await?
    };
    let rows: Vec<serde_json::Value> = {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
            "SELECT id, actor_user_id, actor_name, action, resource_type, resource_id,
                    node_id, detail, ip_addr, created_at FROM audit_logs WHERE ",
        );
        let mut sep = qb.separated(" AND ");
        sep.push("1=1");
        if let Some(u) = user { sep.push("actor_name = "); sep.push_bind_unseparated(u); }
        if let Some(a) = action { sep.push("action = "); sep.push_bind_unseparated(a); }
        if let Some(r) = rtype { sep.push("resource_type = "); sep.push_bind_unseparated(r); }
        if let Some(f) = from { sep.push("created_at >= "); sep.push_bind_unseparated(f); }
        if let Some(t) = to { sep.push("created_at <= "); sep.push_bind_unseparated(t); }
        drop(sep);
        qb.push(" ORDER BY id DESC LIMIT ");
        qb.push_bind(page_size);
        qb.push(" OFFSET ");
        qb.push_bind((page - 1) * page_size);
        qb.build_query_as::<(
            i64, Option<i64>, Option<String>, String, Option<String>, Option<i64>,
            Option<i64>, Option<String>, Option<String>, String,
        )>()
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(|(id, uid, aname, action, rtype, rid, nid, detail, ip, ca)| {
            serde_json::json!({
                "id": id, "actor_user_id": uid, "actor_name": aname, "action": action,
                "resource_type": rtype, "resource_id": rid, "node_id": nid,
                "detail": detail.and_then(|d| serde_json::from_str::<serde_json::Value>(&d).ok()),
                "ip_addr": ip, "created_at": ca,
            })
        })
        .collect()
    };
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "total": total, "page": page, "page_size": page_size, "items": rows,
    }))))
}

// ============ GET /api/logs/access ============

#[derive(Debug, Deserialize)]
pub struct AccessQuery {
    pub node_id: Option<i64>,
    pub rule_type: Option<String>,
    pub rule_id: Option<i64>,
    pub client_ip: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

pub async fn access_list(
    state: web::Data<AppState>,
    q: web::Query<AccessQuery>,
) -> AppResult<HttpResponse> {
    let (page, page_size) = page_of(q.page, q.page_size);
    let rtype = q.rule_type.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let cip = q.client_ip.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let from = q.from.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let to = q.to.as_deref().map(str::trim).filter(|s| !s.is_empty());

    macro_rules! conds {
        ($qb:expr) => {{
            let mut sep = $qb.separated(" AND ");
            sep.push("1=1");
            if let Some(n) = q.node_id { sep.push("node_id = "); sep.push_bind_unseparated(n); }
            if let Some(r) = rtype { sep.push("rule_type = "); sep.push_bind_unseparated(r); }
            if let Some(r) = q.rule_id { sep.push("rule_id = "); sep.push_bind_unseparated(r); }
            if let Some(c) = cip { sep.push("client_ip LIKE "); sep.push_bind_unseparated(format!("%{c}%")); }
            if let Some(f) = from { sep.push("started_at >= "); sep.push_bind_unseparated(f); }
            if let Some(t) = to { sep.push("started_at <= "); sep.push_bind_unseparated(t); }
        }};
    }

    let total: i64 = {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM access_logs WHERE ");
        conds!(qb);
        qb.build_query_scalar().fetch_one(&state.pool).await?
    };
    let rows: Vec<serde_json::Value> = {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
            "SELECT id, node_id, rule_type, rule_id, client_ip, started_at, ended_at,
                    bytes_up, bytes_down, status FROM access_logs WHERE ",
        );
        conds!(qb);
        qb.push(" ORDER BY id DESC LIMIT ");
        qb.push_bind(page_size);
        qb.push(" OFFSET ");
        qb.push_bind((page - 1) * page_size);
        qb.build_query_as::<(
            i64, i64, String, i64, Option<String>, String, Option<String>, i64, i64, Option<String>,
        )>()
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(|(id, nid, rtype, rid, cip, sa, ea, up, down, st)| {
            serde_json::json!({
                "id": id, "node_id": nid, "rule_type": rtype, "rule_id": rid,
                "client_ip": cip, "started_at": sa, "ended_at": ea,
                "bytes_up": up, "bytes_down": down, "status": st,
            })
        })
        .collect()
    };
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "total": total, "page": page, "page_size": page_size, "items": rows,
    }))))
}

// ============ GET /api/logs/access/export (CSV) ============

fn csv_esc(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub async fn access_export(
    state: web::Data<AppState>,
    q: web::Query<AccessQuery>,
) -> AppResult<HttpResponse> {
    let rtype = q.rule_type.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let cip = q.client_ip.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let from = q.from.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let to = q.to.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
        "SELECT id, node_id, rule_type, rule_id, client_ip, started_at, ended_at,
                bytes_up, bytes_down, status FROM access_logs WHERE ",
    );
    {
        let mut sep = qb.separated(" AND ");
        sep.push("1=1");
        if let Some(n) = q.node_id { sep.push("node_id = "); sep.push_bind_unseparated(n); }
        if let Some(r) = rtype { sep.push("rule_type = "); sep.push_bind_unseparated(r); }
        if let Some(r) = q.rule_id { sep.push("rule_id = "); sep.push_bind_unseparated(r); }
        if let Some(c) = cip { sep.push("client_ip LIKE "); sep.push_bind_unseparated(format!("%{c}%")); }
        if let Some(f) = from { sep.push("started_at >= "); sep.push_bind_unseparated(f); }
        if let Some(t) = to { sep.push("started_at <= "); sep.push_bind_unseparated(t); }
    }
    qb.push(" ORDER BY id DESC LIMIT 50000");
    let rows: Vec<(
        i64, i64, String, i64, Option<String>, String, Option<String>, i64, i64, Option<String>,
    )> = qb.build_query_as().fetch_all(&state.pool).await?;

    let mut csv = String::from("id,node_id,rule_type,rule_id,client_ip,started_at,ended_at,bytes_up,bytes_down,status\n");
    for (id, nid, rtype, rid, cip, sa, ea, up, down, st) in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            id,
            nid,
            csv_esc(&rtype),
            rid,
            csv_esc(cip.as_deref().unwrap_or("")),
            csv_esc(&sa),
            csv_esc(ea.as_deref().unwrap_or("")),
            up,
            down,
            csv_esc(st.as_deref().unwrap_or("")),
        ));
    }
    Ok(HttpResponse::Ok()
        .content_type("text/csv; charset=utf-8")
        .insert_header(("Content-Disposition", "attachment; filename=\"access_logs.csv\""))
        .body(format!("\u{FEFF}{csv}")))
}

// ============ GET /api/logs/subscription ============

#[derive(Debug, Deserialize)]
pub struct SubLogQuery {
    pub subscription_id: Option<i64>,
    pub result: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

pub async fn subscription_list(
    state: web::Data<AppState>,
    q: web::Query<SubLogQuery>,
) -> AppResult<HttpResponse> {
    let (page, page_size) = page_of(q.page, q.page_size);
    let result = q.result.as_deref().map(str::trim).filter(|s| !s.is_empty());

    macro_rules! conds {
        ($qb:expr) => {{
            let mut sep = $qb.separated(" AND ");
            sep.push("1=1");
            if let Some(sid) = q.subscription_id { sep.push("l.subscription_id = "); sep.push_bind_unseparated(sid); }
            if let Some(r) = result { sep.push("l.result = "); sep.push_bind_unseparated(r); }
        }};
    }

    let total: i64 = {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM subscription_logs l WHERE ");
        conds!(qb);
        qb.build_query_scalar().fetch_one(&state.pool).await?
    };
    let rows: Vec<serde_json::Value> = {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
            "SELECT l.id, l.subscription_id, s.name, l.client_ip, l.user_agent, l.format,
                    l.result, l.accessed_at FROM subscription_logs l
             LEFT JOIN subscriptions s ON s.id = l.subscription_id WHERE ",
        );
        conds!(qb);
        qb.push(" ORDER BY l.id DESC LIMIT ");
        qb.push_bind(page_size);
        qb.push(" OFFSET ");
        qb.push_bind((page - 1) * page_size);
        qb.build_query_as::<(
            i64, i64, Option<String>, Option<String>, Option<String>, Option<String>, String, String,
        )>()
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(|(id, sid, sname, cip, ua, fmt, result, ca)| {
            serde_json::json!({
                "id": id, "subscription_id": sid, "subscription_name": sname,
                "client_ip": cip, "user_agent": ua, "format": fmt,
                "result": result, "created_at": ca,
            })
        })
        .collect()
    };
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "total": total, "page": page, "page_size": page_size, "items": rows,
    }))))
}


// ============ POST /api/logs/cleanup ============

#[derive(Debug, Deserialize)]
pub struct CleanupReq {
    pub days: i64,
}

pub async fn cleanup(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<CleanupReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    if body.days < 1 || body.days > 3650 {
        return Err(AppError::bad("days 范围 1~3650"));
    }
    let cutoff = format!("-{} days", body.days);
    let mut counts = serde_json::Map::new();
    for (table, col) in [
        ("access_logs", "started_at"),
        ("subscription_logs", "accessed_at"),
        ("audit_logs", "created_at"),
    ] {
        let r = sqlx::query(&format!(
            "DELETE FROM {table} WHERE {col} < datetime('now', ?)"
        ))
        .bind(&cutoff)
        .execute(&state.pool)
        .await?;
        counts.insert(table.to_string(), serde_json::json!(r.rows_affected()));
    }
    // 清理后截断 WAL
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&state.pool)
        .await;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    audit(
        &state.pool,
        Some(user.id),
        &user.username,
        "logs_cleanup",
        None,
        None,
        None,
        serde_json::json!({"days": body.days, "deleted": counts}),
        &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "days": body.days, "deleted": counts,
    }))))
}
