//! P9 —— 统计聚合与本机指标采集
//!
//! - aggregate 任务：每 5 分钟把 access_logs 的新行按小时/天聚合成 stats_hourly/stats_daily（增量 UPSERT）
//! - metrics 任务：每 60 秒采集本机 CPU/内存/实时连接数/网卡速率，写入 metrics_snapshots

use sqlx::SqlitePool;

const CURSOR_KEY: &str = "stats_agg_cursor";

/// 启动后台聚合任务（每 5 分钟）
pub fn spawn_aggregator(pool: SqlitePool) {
    tokio::spawn(async move {
        // 启动时立刻跑一次，之后每 5 分钟
        if let Err(e) = aggregate_once(&pool).await {
            tracing::warn!("统计聚合失败: {e:#}");
        }
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tick.tick().await;
            if let Err(e) = aggregate_once(&pool).await {
                tracing::warn!("统计聚合失败: {e:#}");
            }
        }
    });
}

/// 单次指标采集：CPU/内存/实时连接数/网卡速率 → metrics_snapshots
async fn collect_metrics_once(
    sys: &mut sysinfo::System,
    nets: &mut sysinfo::Networks,
    prev: &mut (u64, u64, Option<std::time::Instant>),
    pool: &SqlitePool,
    runtime: &std::sync::Arc<crate::services::runtime::RuntimeManager>,
) {
    sys.refresh_all();
    nets.refresh();
    let cpu = sys.global_cpu_usage() as f64;
    let mem = if sys.total_memory() > 0 {
        sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0
    } else {
        0.0
    };
    let mut rx: u64 = 0;
    let mut tx: u64 = 0;
    for (_, d) in nets.iter() {
        rx += d.received();
        tx += d.transmitted();
    }
    let now = std::time::Instant::now();
    let (up_bps, down_bps) = match prev.2 {
        Some(t) => {
            let dt = now.duration_since(t).as_secs_f64().max(1.0);
            (
                ((tx.saturating_sub(prev.1)) as f64 / dt * 8.0) as i64,
                ((rx.saturating_sub(prev.0)) as f64 / dt * 8.0) as i64,
            )
        }
        None => (0, 0),
    };
    prev.0 = rx;
    prev.1 = tx;
    prev.2 = Some(now);
    let conns: i64 = runtime
        .status_snapshot()
        .await
        .iter()
        .map(|s| s["conns"].as_u64().unwrap_or(0) as i64)
        .sum();
    let at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Err(e) = sqlx::query(
        "INSERT INTO metrics_snapshots (node_id, collected_at, cpu, mem, conns, net_up_bps, net_down_bps)
         VALUES (1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&at)
    .bind(cpu)
    .bind(mem)
    .bind(conns)
    .bind(up_bps)
    .bind(down_bps)
    .execute(pool)
    .await
    {
        tracing::warn!("写入本机指标失败: {e:#}");
    }
}

/// 启动本机指标采集任务（每 60 秒）
pub fn spawn_metrics(pool: SqlitePool, runtime: std::sync::Arc<crate::services::runtime::RuntimeManager>) {
    tokio::spawn(async move {
        let mut sys = sysinfo::System::new_all();
        let mut nets = sysinfo::Networks::new_with_refreshed_list();
        let mut prev = (0u64, 0u64, None);
        collect_metrics_once(&mut sys, &mut nets, &mut prev, &pool, &runtime).await;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            collect_metrics_once(&mut sys, &mut nets, &mut prev, &pool, &runtime).await;
        }
    });
}

/// 单次聚合：把水位线之后的新 access_logs 行聚合成小时/天统计
pub async fn aggregate_once(pool: &SqlitePool) -> anyhow::Result<(i64, i64)> {
    let cursor: i64 = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM settings WHERE key = ?",
    )
    .bind(CURSOR_KEY)
    .fetch_optional(pool)
    .await?
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);
    let mut tx = pool.begin().await?;
    let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM access_logs")
        .fetch_one(&mut *tx)
        .await?;
    let max_id = max_id.unwrap_or(0);
    if max_id <= cursor {
        return Ok((0, 0));
    }
    // 按小时聚合（started_at 是本地时间字符串 "YYYY-MM-DD HH:MM:SS"，直接截断）
    let h = sqlx::query(
        "INSERT INTO stats_hourly (stat_time, node_id, rule_type, rule_id, total_connections, total_bytes_up, total_bytes_down)
         SELECT replace(substr(started_at, 1, 13), ' ', 'T'), node_id, rule_type, rule_id,
                COUNT(*), COALESCE(SUM(bytes_up), 0), COALESCE(SUM(bytes_down), 0)
         FROM access_logs WHERE id > ? AND id <= ?
         GROUP BY 1, 2, 3, 4
         ON CONFLICT(stat_time, node_id, rule_type, rule_id) DO UPDATE SET
           total_connections = stats_hourly.total_connections + excluded.total_connections,
           total_bytes_up = stats_hourly.total_bytes_up + excluded.total_bytes_up,
           total_bytes_down = stats_hourly.total_bytes_down + excluded.total_bytes_down",
    )
    .bind(cursor)
    .bind(max_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // 按天聚合
    let d = sqlx::query(
        "INSERT INTO stats_daily (stat_date, node_id, rule_type, rule_id, total_connections, total_bytes_up, total_bytes_down)
         SELECT substr(started_at, 1, 10), node_id, rule_type, rule_id,
                COUNT(*), COALESCE(SUM(bytes_up), 0), COALESCE(SUM(bytes_down), 0)
         FROM access_logs WHERE id > ? AND id <= ?
         GROUP BY 1, 2, 3, 4
         ON CONFLICT(stat_date, node_id, rule_type, rule_id) DO UPDATE SET
           total_connections = stats_daily.total_connections + excluded.total_connections,
           total_bytes_up = stats_daily.total_bytes_up + excluded.total_bytes_up,
           total_bytes_down = stats_daily.total_bytes_down + excluded.total_bytes_down",
    )
    .bind(cursor)
    .bind(max_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // 配额用量记账：本机运行时产生的流量与 Worker 上报走同一个 add_usage
    let groups: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT rule_type, rule_id, COALESCE(SUM(bytes_up), 0), COALESCE(SUM(bytes_down), 0)
         FROM access_logs WHERE id > ? AND id <= ?
         GROUP BY rule_type, rule_id",
    )
    .bind(cursor)
    .bind(max_id)
    .fetch_all(&mut *tx)
    .await?;
    for (rule_type, rule_id, up, down) in groups {
        crate::services::quota::add_usage(&mut tx, &rule_type, rule_id, up, down).await?;
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(CURSOR_KEY)
    .bind(max_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!("统计聚合：access_logs {cursor}..{max_id} → 小时 {h} 行 / 天 {d} 行");
    Ok((h as i64, d as i64))
}
