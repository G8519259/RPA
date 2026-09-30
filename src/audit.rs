use crate::util::now_str;
use sqlx::SqlitePool;

/// 写审计日志
#[allow(clippy::too_many_arguments)]
pub async fn audit(
    pool: &SqlitePool,
    actor_user_id: Option<i64>,
    actor_name: &str,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<i64>,
    node_id: Option<i64>,
    detail: serde_json::Value,
    ip_addr: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_logs
           (actor_user_id, actor_name, action, resource_type, resource_id, node_id, detail, ip_addr, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(actor_user_id)
    .bind(actor_name)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(node_id)
    .bind(detail.to_string())
    .bind(if ip_addr.is_empty() { None } else { Some(ip_addr) })
    .bind(now_str())
    .execute(pool)
    .await;
}

/// 系统动作的审计（actor_name='system'）
pub async fn audit_system(
    pool: &SqlitePool,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<i64>,
    detail: serde_json::Value,
) {
    audit(
        pool,
        None,
        "system",
        action,
        resource_type,
        resource_id,
        None,
        detail,
        "",
    )
    .await;
}
