//! P7 —— 日志清理后台任务：
//! 每天凌晨（本地时区）按保留期清理 access_logs / subscription_logs / audit_logs，
//! 清理后执行 PRAGMA wal_checkpoint(TRUNCATE)。

use sqlx::SqlitePool;

use crate::config::LogCfg;

/// 执行一轮清理，返回各表删除行数
pub async fn cleanup_once(pool: &SqlitePool, cfg: &LogCfg) -> anyhow::Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    for (table, col, days) in [
        ("access_logs", "started_at", cfg.access_log_retention_days),
        (
            "subscription_logs",
            "created_at",
            cfg.subscription_log_retention_days,
        ),
        ("audit_logs", "created_at", cfg.audit_log_retention_days),
        // 指标快照保留 7 天（与 access 日志保留期解耦，避免图表断档）
        ("metrics_snapshots", "collected_at", 7),
    ] {
        if days <= 0 {
            continue;
        }
        let r = sqlx::query(&format!(
            "DELETE FROM {table} WHERE {col} < datetime('now', ?)"
        ))
        .bind(format!("-{} days", days))
        .execute(pool)
        .await?;
        out.push((table.to_string(), r.rows_affected()));
    }
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await;
    Ok(out)
}

/// 距离下一次本地时区 03:00 的时长
fn until_next_3am() -> std::time::Duration {
    let now = chrono::Local::now();
    let next = now
        .date_naive()
        .and_hms_opt(3, 0, 0)
        .map(|t| {
            let dt = t.and_local_timezone(chrono::Local).single().unwrap_or(now);
            if dt <= now { dt + chrono::Duration::days(1) } else { dt }
        })
        .unwrap_or(now + chrono::Duration::days(1));
    (next - now).to_std().unwrap_or(std::time::Duration::from_secs(3600))
}

/// 后台任务：每天凌晨 03:00（本地时区）执行清理
pub async fn run_cleaner(pool: SqlitePool, cfg: LogCfg) {
    loop {
        tokio::time::sleep(until_next_3am()).await;
        match cleanup_once(&pool, &cfg).await {
            Ok(rows) => {
                let total: u64 = rows.iter().map(|(_, n)| n).sum();
                if total > 0 {
                    tracing::info!("日志清理完成，删除 {} 行: {:?}", total, rows);
                }
            }
            Err(e) => tracing::error!("日志清理失败: {e:#}"),
        }
    }
}
