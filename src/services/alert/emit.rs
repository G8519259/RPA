//! P12 —— 事件写入（规则匹配 + 冷却去重，§14.4）

use sqlx::SqlitePool;

use super::{AlertDraft, AlertRule};
use crate::error::AppError;

/// 事件源唯一入口：匹配已启用的同 event_type 规则，冷却窗口内去重后写入 alert_events。
pub async fn emit(pool: &SqlitePool, a: AlertDraft) -> Result<(), AppError> {
    let rules: Vec<AlertRule> = sqlx::query_as(
        "SELECT * FROM alert_rules WHERE enabled = 1 AND event_type = ?",
    )
    .bind(a.event_type)
    .fetch_all(pool)
    .await?;
    for r in rules {
        let window = format!("-{} seconds", r.cooldown_secs.max(0));
        sqlx::query(
            "INSERT INTO alert_events
               (rule_id, event_type, dedup_key, severity, title, body, resource_type, resource_id, status)
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, 'pending'
              WHERE NOT EXISTS (
                SELECT 1 FROM alert_events
                 WHERE rule_id = ? AND dedup_key = ? AND created_at > datetime('now', ?))",
        )
        .bind(r.id)
        .bind(a.event_type)
        .bind(&a.dedup_key)
        .bind(a.severity)
        .bind(&a.title)
        .bind(&a.body)
        .bind(&a.resource_type)
        .bind(a.resource_id)
        .bind(r.id)
        .bind(&a.dedup_key)
        .bind(&window)
        .execute(pool)
        .await?;
    }
    Ok(())
}
