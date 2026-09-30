//! P11/P12 —— 生命周期任务：到期 / 配额 / 自动停用 / 即将到期扫描
//!
//! 每 60 秒一轮（`LifecycleCfg.tick_secs`），单个 tokio 任务。数据库操作放在一个短事务内，
//! 事务提交后统一调用 alert::emit 写入告警事件（P12：按规则匹配 + 冷却去重，投递器异步发送）。
//!
//! 停用原因规则（§13.2，务必遵守）：
//! - 管理员手动停用 → enabled=0, disabled_reason='manual'
//! - 到期自动停用 → enabled=0, disabled_reason='expired'
//! - 配额用尽自动停用 → enabled=0, disabled_reason='quota'
//! - 自动恢复只处理 disabled_reason='expired'（到期已延到未来）或 'quota'（配额已恢复）的对象
//! - 所有自动停用/恢复都要更新 updated_at（Worker 靠它判断配置变化）并写审计日志（actor='system'）

use chrono::{Datelike, NaiveDate, NaiveDateTime};
use sqlx::SqlitePool;

use crate::audit::audit_system;
use crate::config::LifecycleCfg;
use crate::error::AppError;
use crate::models::QuotaRow;
use crate::services::alert::{days_before_of, emit, AlertDraft};

const ENTRY_TABLES: [(&str, &str); 3] = [
    ("proxy", "proxy_rules"),
    ("forward", "port_forwards"),
    ("tunnel", "tunnels"),
];

/// 配额预警默认阈值（百分比）；以 quota_warn 规则的 params 为准
const DEFAULT_WARN_THRESHOLDS: [i64; 2] = [80, 95];

/// 返回包含 now 的那个月度周期起点（00:00:00，UTC 存储）。
/// tz_offset_hours 用于按本地时区划分周期（默认 8）。
pub fn cycle_start(now_utc: NaiveDateTime, reset_day: u32, tz_offset_hours: i64) -> NaiveDateTime {
    let local = now_utc + chrono::Duration::hours(tz_offset_hours);
    let d = reset_day.clamp(1, 28);
    let (y, m) = if local.day() >= d {
        (local.year(), local.month())
    } else if local.month() == 1 {
        (local.year() - 1, 12)
    } else {
        (local.year(), local.month() - 1)
    };
    let start_local = NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    start_local - chrono::Duration::hours(tz_offset_hours) // 转回 UTC 存储
}

fn table_of(entry_type: &str) -> Result<&'static str, AppError> {
    ENTRY_TABLES
        .iter()
        .find(|(t, _)| *t == entry_type)
        .map(|(_, table)| *table)
        .ok_or_else(|| AppError::bad("未知的条目类型"))
}

pub async fn lifecycle_tick(
    pool: &SqlitePool,
    cfg: &LifecycleCfg,
    tz_offset_hours: i64,
    base_url: &str,
) -> anyhow::Result<()> {
    let mut alerts: Vec<AlertDraft> = Vec::new();
    // 告警阈值以规则参数为准（事务外读取一次）
    let quota_thresholds = warn_thresholds_of(pool).await?;
    let entry_days = days_before_for(pool, "entry_expiring").await?;
    let sub_days = days_before_for(pool, "sub_expiring").await?;
    let mut tx = pool.begin().await?;

    // 1) 条目到期 → 自动停用（只处理 enabled=1 的；manual 停用的不改写原因）
    for (t, table) in ENTRY_TABLES {
        let rows: Vec<(i64, String, String)> = sqlx::query_as(&format!(
            "SELECT id, name, expires_at FROM {table}
              WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at <= datetime('now')"
        ))
        .fetch_all(&mut *tx)
        .await?;
        for (id, name, expires_at) in rows {
            sqlx::query(&format!(
                "UPDATE {table} SET enabled = 0, disabled_reason = 'expired',
                        updated_at = datetime('now') WHERE id = ?"
            ))
            .bind(id)
            .execute(&mut *tx)
            .await?;
            audit_system(
                pool,
                "entry_auto_expired",
                Some(t),
                Some(id),
                serde_json::json!({"name": name}),
            )
            .await;
            alerts.push(AlertDraft::entry_expired(t, id, &name, &expires_at, base_url));
        }
    }

    // 2) 订阅到期 → 标记停用
    let subs: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM subscriptions
          WHERE enabled = 1 AND expires_at IS NOT NULL AND expires_at <= datetime('now')",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (id, name) in subs {
        sqlx::query(
            "UPDATE subscriptions SET enabled = 0, disabled_reason = 'expired',
                    updated_at = datetime('now') WHERE id = ?",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        audit_system(
            pool,
            "sub_auto_expired",
            Some("subscription"),
            Some(id),
            serde_json::json!({"name": name}),
        )
        .await;
        alerts.push(AlertDraft::sub_expired(id, &name, base_url));
    }

    // 3) 月度配额重置 + 恢复因配额停用的条目
    reset_monthly_quotas(&mut tx, tz_offset_hours).await?;

    // 4) 配额检查：预警 + 超限停用
    check_quotas(&mut tx, &quota_thresholds, tz_offset_hours, base_url, &mut alerts).await?;

    // 5) 即将到期提醒（订阅与条目，按阈值）
    collect_expiring_notices(&mut tx, &entry_days, &sub_days, tz_offset_hours, base_url, &mut alerts)
        .await?;

    // 6) 过期订阅自动清理（可选）
    if cfg.expired_sub_cleanup_days > 0 {
        sqlx::query(
            "DELETE FROM subscriptions
              WHERE disabled_reason = 'expired'
                AND expires_at <= datetime('now', ?)",
        )
        .bind(format!("-{} days", cfg.expired_sub_cleanup_days))
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    // 7) 事务外写入告警事件（去重在 emit 内完成，§13.5 / §14.4）
    for a in alerts {
        emit(pool, a).await?;
    }
    Ok(())
}

/// 读取 quota_warn 规则的 percent 阈值（无规则时用默认 [80, 95]）
async fn warn_thresholds_of(pool: &SqlitePool) -> anyhow::Result<Vec<i64>> {
    let params: Option<String> = sqlx::query_scalar(
        "SELECT params FROM alert_rules WHERE enabled = 1 AND event_type = 'quota_warn' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(params
        .and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok())
        .and_then(|v| v.get("percent").cloned())
        .and_then(|v| serde_json::from_value::<Vec<i64>>(v).ok())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_WARN_THRESHOLDS.to_vec()))
}

/// 读取某 event_type 规则的 days_before（无规则时用默认 [7,3,1]）
async fn days_before_for(pool: &SqlitePool, event_type: &str) -> anyhow::Result<Vec<i64>> {
    let params: Option<String> = sqlx::query_scalar(
        "SELECT params FROM alert_rules WHERE enabled = 1 AND event_type = ? LIMIT 1",
    )
    .bind(event_type)
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(params
        .map(|p| days_before_of(&p))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![7, 3, 1]))
}

/// 月度配额重置：进入新周期 → 用量清零、状态恢复，并恢复 disabled_reason='quota' 的条目
async fn reset_monthly_quotas(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tz_offset_hours: i64,
) -> anyhow::Result<()> {
    let now_utc = chrono::Utc::now().naive_utc();
    let rows: Vec<QuotaRow> =
        sqlx::query_as("SELECT * FROM entry_quotas WHERE period = 'monthly' AND quota_bytes > 0")
            .fetch_all(&mut **tx)
            .await?;
    for q in rows {
        let start = cycle_start(now_utc, q.reset_day as u32, tz_offset_hours);
        let period_start =
            NaiveDateTime::parse_from_str(&q.period_start, "%Y-%m-%d %H:%M:%S")
                .unwrap_or(NaiveDateTime::MIN);
        if period_start >= start {
            continue; // 还在本周期内
        }
        let start_s = start.format("%Y-%m-%d %H:%M:%S").to_string();
        sqlx::query(
            "UPDATE entry_quotas SET used_bytes = 0, status = 'ok', warn_level = 0,
                    exceeded_at = NULL, period_start = ?, updated_at = datetime('now')
             WHERE id = ?",
        )
        .bind(&start_s)
        .bind(q.id)
        .execute(&mut **tx)
        .await?;
        // 只恢复因配额停用的条目
        let table = table_of(&q.entry_type)?;
        let n = sqlx::query(&format!(
            "UPDATE {table} SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now')
             WHERE id = ? AND disabled_reason = 'quota'"
        ))
        .bind(q.entry_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if n > 0 {
            tracing::info!(
                "配额月度重置：{}/{}（quota_id={}）恢复启用",
                q.entry_type,
                q.entry_id,
                q.id
            );
        }
    }
    Ok(())
}

/// 配额检查：超限停用 + 阈值预警
async fn check_quotas(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    warn_thresholds: &[i64],
    tz_offset_hours: i64,
    base_url: &str,
    alerts: &mut Vec<AlertDraft>,
) -> anyhow::Result<()> {
    let rows: Vec<QuotaRow> =
        sqlx::query_as("SELECT * FROM entry_quotas WHERE quota_bytes > 0 AND status = 'ok'")
            .fetch_all(&mut **tx)
            .await?;
    for q in rows {
        check_one_quota(tx, &q, warn_thresholds, tz_offset_hours, base_url, alerts).await?;
    }
    Ok(())
}

/// 对单个配额做超限/预警检查（flush 后立刻调用，把超限到停用的延迟压到约 10 秒）
pub async fn check_quota_now(
    pool: &SqlitePool,
    entry_type: &str,
    entry_id: i64,
    tz_offset_hours: i64,
    base_url: &str,
) -> anyhow::Result<()> {
    let warn_thresholds = warn_thresholds_of(pool).await?;
    let mut tx = pool.begin().await?;
    let mut alerts: Vec<AlertDraft> = Vec::new();
    if let Some(q) = sqlx::query_as::<_, QuotaRow>(
        "SELECT * FROM entry_quotas WHERE entry_type = ? AND entry_id = ? AND quota_bytes > 0 AND status = 'ok'",
    )
    .bind(entry_type)
    .bind(entry_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        check_one_quota(&mut tx, &q, &warn_thresholds, tz_offset_hours, base_url, &mut alerts).await?;
    }
    tx.commit().await?;
    for a in alerts {
        emit(pool, a).await?;
    }
    Ok(())
}

async fn check_one_quota(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    q: &QuotaRow,
    warn_thresholds: &[i64],
    tz_offset_hours: i64,
    base_url: &str,
    alerts: &mut Vec<AlertDraft>,
) -> anyhow::Result<()> {
    let table = table_of(&q.entry_type)?;
    if q.used_bytes >= q.quota_bytes {
        // 超限停用：只停用当前启用的；manual 停用的保持原因不变（enabled=1 才改）
        sqlx::query(&format!(
            "UPDATE {table} SET enabled = 0, disabled_reason = 'quota',
                    updated_at = datetime('now') WHERE id = ? AND enabled = 1"
        ))
        .bind(q.entry_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE entry_quotas SET status = 'exceeded', exceeded_at = datetime('now'),
                    updated_at = datetime('now') WHERE id = ?",
        )
        .bind(q.id)
        .execute(&mut **tx)
        .await?;
        let name: Option<String> =
            sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE id = ?"))
                .bind(q.entry_id)
                .fetch_optional(&mut **tx)
                .await?
                .flatten();
        alerts.push(AlertDraft::quota_exceeded(
            &q.entry_type,
            q.entry_id,
            name.as_deref().unwrap_or("未知条目"),
            &q.period_start,
            tz_offset_hours,
            base_url,
        ));
    } else {
        // 预警：used_pct 落到哪个阈值区间，仅当超过已发出的最高阈值时触发
        let pct = q.used_bytes * 100 / q.quota_bytes.max(1);
        let level = warn_thresholds
            .iter()
            .filter(|t| **t <= pct)
            .max()
            .copied()
            .unwrap_or(0);
        if level > q.warn_level {
            sqlx::query(
                "UPDATE entry_quotas SET warn_level = ?, updated_at = datetime('now') WHERE id = ?",
            )
            .bind(level)
            .bind(q.id)
            .execute(&mut **tx)
            .await?;
            let name: Option<String> =
                sqlx::query_scalar(&format!("SELECT name FROM {table} WHERE id = ?"))
                    .bind(q.entry_id)
                    .fetch_optional(&mut **tx)
                    .await?
                    .flatten();
            alerts.push(AlertDraft::quota_warn(
                &q.entry_type,
                q.entry_id,
                name.as_deref().unwrap_or("未知条目"),
                &q.period_start,
                level,
                q.used_bytes,
                q.quota_bytes,
                base_url,
            ));
        }
    }
    Ok(())
}

/// 即将到期提醒（§14.5）：按阈值 days_before，只发"最贴近当前剩余天数"的一条。
/// 去重靠 emit（dedup_key 带阈值与到期时间 + 规则 10 年冷却），同一阈值只发一次。
async fn collect_expiring_notices(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    entry_days: &[i64],
    sub_days: &[i64],
    tz_offset_hours: i64,
    base_url: &str,
    alerts: &mut Vec<AlertDraft>,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let entry_max = entry_days.iter().max().copied().unwrap_or(7);
    let sub_max = sub_days.iter().max().copied().unwrap_or(7);

    // 条目
    for (t, table) in ENTRY_TABLES {
        let rows: Vec<(i64, String, String)> = sqlx::query_as(&format!(
            "SELECT id, name, expires_at FROM {table}
              WHERE enabled = 1 AND expires_at IS NOT NULL
                AND expires_at > datetime('now')
                AND expires_at <= datetime('now', '+{entry_max} days')"
        ))
        .fetch_all(&mut **tx)
        .await?;
        for (id, name, expires_at) in rows {
            let Some(left) = crate::services::alert::days_left(&expires_at, now) else {
                continue;
            };
            let days_cfg = crate::services::alert::DaysBefore {
                days_before: entry_days.to_vec(),
            };
            if let Some(d) = days_cfg.pick(left) {
                alerts.push(AlertDraft::entry_expiring(
                    t,
                    id,
                    &name,
                    d,
                    &expires_at,
                    tz_offset_hours,
                    base_url,
                ));
            }
        }
    }

    // 订阅
    let subs: Vec<(i64, String, String)> = sqlx::query_as(&format!(
        "SELECT id, name, expires_at FROM subscriptions
          WHERE enabled = 1 AND expires_at IS NOT NULL
            AND expires_at > datetime('now')
            AND expires_at <= datetime('now', '+{sub_max} days')"
    ))
    .fetch_all(&mut **tx)
    .await?;
    for (id, name, expires_at) in subs {
        let Some(left) = crate::services::alert::days_left(&expires_at, now) else {
            continue;
        };
        let days_cfg = crate::services::alert::DaysBefore {
            days_before: sub_days.to_vec(),
        };
        if let Some(d) = days_cfg.pick(left) {
            alerts.push(AlertDraft::sub_expiring(
                id,
                &name,
                d,
                &expires_at,
                tz_offset_hours,
                base_url,
            ));
        }
    }
    Ok(())
}

/// 管理员手动"重置用量"：used_bytes=0、status='ok'、warn_level=0，并恢复因配额停用的条目
pub async fn reset_quota_usage(
    pool: &SqlitePool,
    entry_type: &str,
    entry_id: i64,
) -> Result<bool, AppError> {
    let table = table_of(entry_type)?;
    let mut tx = pool.begin().await?;
    let q: Option<QuotaRow> =
        sqlx::query_as("SELECT * FROM entry_quotas WHERE entry_type = ? AND entry_id = ?")
            .bind(entry_type)
            .bind(entry_id)
            .fetch_optional(&mut *tx)
            .await
            ?;
    let q = q.ok_or_else(|| AppError::not_found("该条目未设置配额"))?;
    // monthly 配额重置后 period_start 设为当前周期起点，避免立刻又被判定进入新周期
    let now_utc = chrono::Utc::now().naive_utc();
    let start_s = if q.period == "monthly" {
        cycle_start(now_utc, q.reset_day as u32, 8)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    } else {
        q.period_start.clone()
    };
    sqlx::query(
        "UPDATE entry_quotas SET used_bytes = 0, status = 'ok', warn_level = 0,
                exceeded_at = NULL, period_start = ?, updated_at = datetime('now')
         WHERE id = ?",
    )
    .bind(&start_s)
    .bind(q.id)
    .execute(&mut *tx)
    .await
    ?;
    let n = sqlx::query(&format!(
        "UPDATE {table} SET enabled = 1, disabled_reason = NULL, updated_at = datetime('now')
         WHERE id = ? AND disabled_reason = 'quota'"
    ))
    .bind(entry_id)
    .execute(&mut *tx)
    .await
    ?
    .rows_affected();
    // 条目 updated_at 刷新，Worker 感知
    sqlx::query(&format!(
        "UPDATE {table} SET updated_at = datetime('now') WHERE id = ?"
    ))
    .bind(entry_id)
    .execute(&mut *tx)
    .await
    ?;
    tx.commit().await?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn ndt(y: i32, m: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(h, mi, 0).unwrap()
    }

    #[test]
    fn cycle_start_shanghai() {
        // UTC 2026-09-30 06:53 → 北京时间 14:53（30日）≥1日 → 周期起点=本地9月1日00:00 = UTC 8月31日16:00
        let got = cycle_start(ndt(2026, 9, 30, 6, 53), 1, 8);
        assert_eq!(got, ndt(2026, 8, 31, 16, 0));
        // UTC 2026-09-01 00:30 → 北京时间 08:30（1日）≥1日 → 周期起点=本地9月1日00:00
        let got = cycle_start(ndt(2026, 9, 1, 0, 30), 1, 8);
        assert_eq!(got, ndt(2026, 8, 31, 16, 0));
        // UTC 2026-08-31 15:00 → 北京时间 23:00（31日）≥1 → 周期起点=本地8月1日00:00 = UTC 7月31日16:00
        let got = cycle_start(ndt(2026, 8, 31, 15, 0), 1, 8);
        assert_eq!(got, ndt(2026, 7, 31, 16, 0));
    }

    #[test]
    fn cycle_start_before_reset_day() {
        // reset_day=15；UTC 2026-09-10 00:00 → 本地 08:00（10日）<15 → 上月15日00:00本地 = UTC 8月14日16:00
        let got = cycle_start(ndt(2026, 9, 10, 0, 0), 15, 8);
        assert_eq!(got, ndt(2026, 8, 14, 16, 0));
        // 1月回绕：UTC 2026-01-05 00:00 → 本地1月5日 <15 → 2025年12月15日00:00本地
        let got = cycle_start(ndt(2026, 1, 5, 0, 0), 15, 8);
        assert_eq!(got, ndt(2025, 12, 14, 16, 0));
    }
}
