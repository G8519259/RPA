//! P10 —— Worker 模式
//!
//! ```bash
//! rust_proxy_admin --mode worker --master https://admin.example.com --token <TOKEN>
//! ```
//!
//! - 心跳：每 10 秒 POST /internal/node/heartbeat（版本 + 负载）
//! - 配置：每 15 秒 GET /internal/node/config（If-None-Match / 304），有变化则 diff 启停任务
//! - 上报：每 10 秒批量上报访问日志 + 统计增量 + 运行状态；每 60 秒上报指标
//!   上报失败本地缓冲（access_logs 本来就在本地库），下次重试；超 10 万行丢弃最旧。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::services::runtime::{EntryKey, EntrySpec, RuntimeManager};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_BUFFER_ROWS: i64 = 100_000;

struct Worker {
    cfg: Config,
    master: String,
    token: String,
    http: reqwest::Client,
    pool: SqlitePool,
    runtime: Arc<RuntimeManager>,
    sys: tokio::sync::Mutex<sysinfo::System>,
    nets: tokio::sync::Mutex<sysinfo::Networks>,
    prev_net: tokio::sync::Mutex<(u64, u64, Option<std::time::Instant>)>,
}

impl Worker {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.master, path)
    }

    async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> anyhow::Result<reqwest::Response> {
        let resp = self
            .http
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(body)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            anyhow::bail!("Master 拒绝：token 无效（401）");
        }
        Ok(resp)
    }

    /// 拉取配置并做热更新；返回 true 表示配置有变化
    async fn sync_config(&self, etag: &mut Option<String>) -> anyhow::Result<bool> {
        let mut rb = self
            .http
            .get(self.url("/internal/node/config"))
            .header("Authorization", format!("Bearer {}", self.token));
        if let Some(e) = etag.as_deref() {
            rb = rb.header("If-None-Match", e);
        }
        let resp = rb.send().await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            anyhow::bail!("Master 拒绝：token 无效（401）");
        }
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(false);
        }
        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body: serde_json::Value = resp.json().await?;
        let entries: Vec<EntrySpec> = serde_json::from_value(
            body.pointer("/data/entries").cloned().unwrap_or(serde_json::Value::Null),
        )?;
        let mut desired: HashMap<EntryKey, EntrySpec> = HashMap::new();
        for e in entries {
            desired.insert((e.entry_type.clone(), e.id), e);
        }
        self.runtime.sync_with(desired).await;
        *etag = new_etag;
        Ok(true)
    }

    /// 本机负载（心跳用）
    async fn local_load(&self) -> serde_json::Value {
        let mut sys = self.sys.lock().await;
        sys.refresh_all();
        let cpu = sys.global_cpu_usage() as f64;
        let mem = if sys.total_memory() > 0 {
            sys.used_memory() as f64 / sys.total_memory() as f64 * 100.0
        } else {
            0.0
        };
        drop(sys);
        let conns: i64 = self
            .runtime
            .status_snapshot()
            .await
            .iter()
            .map(|s| s["conns"].as_u64().unwrap_or(0) as i64)
            .sum();
        serde_json::json!({ "cpu": cpu, "mem": mem, "conns": conns })
    }

    async fn heartbeat(&self) -> anyhow::Result<()> {
        let load = self.local_load().await;
        let resp = self
            .post_json(
                "/internal/node/heartbeat",
                &serde_json::json!({ "version": VERSION, "load": load }),
            )
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("心跳失败: {}", resp.status());
        }
        Ok(())
    }

    /// 统计上报水位线（worker_stats_cursor）：只统计 id 大于它的行
    async fn stats_cursor(&self) -> i64 {
        sqlx::query_scalar::<_, Option<String>>("SELECT value FROM settings WHERE key = 'worker_stats_cursor'")
            .fetch_optional(&self.pool)
            .await
            .unwrap_or(None)
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// 上报访问日志：读本地 access_logs → POST → 成功后删除已上报行
    async fn flush_access_logs(&self) -> anyhow::Result<usize> {
        // 缓冲上限：超限丢弃最旧
        let cnt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access_logs")
            .fetch_one(&self.pool)
            .await?;
        if cnt > MAX_BUFFER_ROWS {
            sqlx::query(
                "DELETE FROM access_logs WHERE id IN (SELECT id FROM access_logs ORDER BY id LIMIT ?)",
            )
            .bind(cnt - MAX_BUFFER_ROWS)
            .execute(&self.pool)
            .await?;
            tracing::warn!("Worker 上报缓冲超限，丢弃 {} 条最旧日志", cnt - MAX_BUFFER_ROWS);
        }
        let rows: Vec<(i64, String, i64, String, String, Option<String>, i64, i64, String)> =
            sqlx::query_as(
                "SELECT id, rule_type, rule_id, client_ip, started_at, ended_at, bytes_up, bytes_down, status
                 FROM access_logs ORDER BY id LIMIT 2000",
            )
            .fetch_all(&self.pool)
            .await?;
        if rows.is_empty() {
            return Ok(0);
        }
        let max_id = rows.iter().map(|r| r.0).max().unwrap_or(0);
        let items: Vec<_> = rows
            .iter()
            .map(|(_, rt, rid, cip, st, et, up, dn, status)| {
                serde_json::json!({
                    "rule_type": rt, "rule_id": rid, "client_ip": cip,
                    "started_at": st, "ended_at": et,
                    "bytes_up": up, "bytes_down": dn, "status": status,
                })
            })
            .collect();
        let n = items.len();
        let resp = self
            .post_json("/internal/node/logs/access", &serde_json::json!({ "items": items }))
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("上报访问日志失败: {}", resp.status());
        }
        sqlx::query("DELETE FROM access_logs WHERE id <= ?")
            .bind(max_id)
            .execute(&self.pool)
            .await?;
        Ok(n)
    }

    /// 上报统计增量：只统计 id > 水位线的行；成功后推进水位线。
    /// 与 flush_access_logs 串行执行（先 stats 后 logs），保证不丢不重。
    async fn flush_stats(&self) -> anyhow::Result<usize> {
        let cursor = self.stats_cursor().await;
        let grouped: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT rule_type, rule_id, COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0)
             FROM access_logs WHERE id > ? GROUP BY rule_type, rule_id",
        )
        .bind(cursor)
        .fetch_all(&self.pool)
        .await?;
        if grouped.is_empty() {
            return Ok(0);
        }
        let max_id: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id),0) FROM access_logs WHERE id > ?")
            .bind(cursor)
            .fetch_one(&self.pool)
            .await?;
        let items: Vec<_> = grouped
            .into_iter()
            .map(|(rt, rid, c, up, dn)| {
                serde_json::json!({
                    "rule_type": rt, "rule_id": rid,
                    "connections": c, "bytes_up": up, "bytes_down": dn,
                })
            })
            .collect();
        let n = items.len();
        let resp = self
            .post_json("/internal/node/stats/flush", &serde_json::json!({ "items": items }))
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("上报统计增量失败: {}", resp.status());
        }
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ('worker_stats_cursor', ?)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(max_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(n)
    }

    /// 上报运行状态
    async fn report_runtime(&self) -> anyhow::Result<()> {
        let snap = self.runtime.status_snapshot().await;
        let items: Vec<_> = snap
            .iter()
            .map(|s| {
                serde_json::json!({
                    "entry_type": s["entry_type"], "entry_id": s["entry_id"],
                    "status": s["status"], "conns": s["conns"],
                })
            })
            .collect();
        let resp = self
            .post_json("/internal/node/runtime_status", &serde_json::json!({ "items": items }))
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("上报运行状态失败: {}", resp.status());
        }
        Ok(())
    }

    /// 上报指标（每 60 秒）
    async fn report_metrics(&self) -> anyhow::Result<()> {
        let mut sys = self.sys.lock().await;
        let mut nets = self.nets.lock().await;
        let mut prev = self.prev_net.lock().await;
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
        drop(prev);
        drop(nets);
        drop(sys);
        let conns: i64 = self
            .runtime
            .status_snapshot()
            .await
            .iter()
            .map(|s| s["conns"].as_u64().unwrap_or(0) as i64)
            .sum();
        let resp = self
            .post_json(
                "/internal/node/metrics",
                &serde_json::json!({
                    "cpu": cpu, "mem": mem, "conns": conns,
                    "net_up_bps": up_bps, "net_down_bps": down_bps,
                }),
            )
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("上报指标失败: {}", resp.status());
        }
        Ok(())
    }
}

pub async fn run_worker(cfg: Config, master: String, token: String) -> anyhow::Result<()> {
    // tracing 已在 main 里初始化
    let master = master.trim_end_matches('/').to_string();
    tracing::info!("Worker 模式启动，Master: {master}");

    // 本地库只做上报缓冲（access_logs / settings）
    let db_url = "sqlite:data/worker.db";
    std::fs::create_dir_all("data").ok();
    let pool = crate::db::connect(db_url).await?;
    crate::db::migrate(&pool).await?;

    let runtime = RuntimeManager::new(pool.clone(), cfg.clone());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let w = Arc::new(Worker {
        cfg,
        master,
        token,
        http,
        pool,
        runtime,
        sys: tokio::sync::Mutex::new(sysinfo::System::new_all()),
        nets: tokio::sync::Mutex::new(sysinfo::Networks::new_with_refreshed_list()),
        prev_net: tokio::sync::Mutex::new((0, 0, None)),
    });

    // 首次拉配置（失败则退出，让外部 supervisor 重启）
    let mut etag = None;
    w.sync_config(&mut etag).await?;
    tracing::info!("Worker 首次配置同步完成");

    // 心跳循环（10 秒）
    let w2 = w.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            if let Err(e) = w2.heartbeat().await {
                tracing::warn!("心跳失败: {e:#}");
            }
        }
    });
    // 配置拉取循环（15 秒）
    let w2 = w.clone();
    tokio::spawn(async move {
        let mut etag = etag;
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            match w2.sync_config(&mut etag).await {
                Ok(true) => tracing::info!("Worker 配置已更新"),
                Ok(false) => {}
                Err(e) => tracing::warn!("拉取配置失败: {e:#}"),
            }
        }
    });
    // 上报循环（访问日志 + 统计增量 + 运行状态，每 10 秒；指标每 60 秒）
    let w2 = w.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        let mut rounds: u64 = 0;
        loop {
            tick.tick().await;
            rounds += 1;
            // 先统计增量，后删日志（顺序保证不丢不重）
            if let Err(e) = w2.flush_stats().await {
                tracing::warn!("上报统计增量失败: {e:#}");
            } else if let Err(e) = w2.flush_access_logs().await {
                tracing::warn!("上报访问日志失败: {e:#}");
            }
            if let Err(e) = w2.report_runtime().await {
                tracing::warn!("上报运行状态失败: {e:#}");
            }
            if rounds % 6 == 0 {
                if let Err(e) = w2.report_metrics().await {
                    tracing::warn!("上报指标失败: {e:#}");
                }
            }
        }
    });

    // 主任务挂起
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
