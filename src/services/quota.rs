//! P10/P11 —— 配额用量累计
//!
//! 统计入口只有两个：Worker 上报（`/internal/node/stats/flush`）和本机运行时（P11 接入）。
//! 二者都走 `add_usage`，保证口径一致。

use crate::error::AppError;

/// 累计配额用量（上行 + 下行都计入），在写 stats_hourly 的同一个事务里调用。
pub async fn add_usage(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entry_type: &str, // 与 stats_hourly.rule_type 词汇一致：proxy | forward | tunnel
    entry_id: i64,
    bytes_up: i64,
    bytes_down: i64,
) -> Result<(), AppError> {
    let total = bytes_up.saturating_add(bytes_down);
    if total <= 0 {
        return Ok(());
    }
    sqlx::query(
        "UPDATE entry_quotas
            SET used_bytes = used_bytes + ?, updated_at = datetime('now')
          WHERE entry_type = ? AND entry_id = ? AND quota_bytes > 0",
    )
    .bind(total)
    .bind(entry_type)
    .bind(entry_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
