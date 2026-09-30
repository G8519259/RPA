//! P12 —— 节点在线状态巡检（§14.5）
//!
//! 每 15 秒一轮：非本机、已启用的节点按 `nodes.online_state` 状态机判定，
//! 只在状态翻转时 emit（一次离线只发一次，恢复时再发一次，离线期间不反复轰炸）。
//! 从未上线过的新节点（last_heartbeat_at 为空）保持 unknown，不误报。

use chrono::NaiveDateTime;
use sqlx::SqlitePool;

use crate::services::alert::{emit, offline_secs_of, AlertDraft};

pub async fn node_watch_loop(
    pool: SqlitePool,
    tz_offset_hours: i64,
    base_url: String,
    heartbeat_timeout_secs: i64,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tick.tick().await;
        if let Err(e) = node_watch_tick(&pool, tz_offset_hours, &base_url, heartbeat_timeout_secs).await {
            tracing::warn!("节点巡检失败: {e:#}");
        }
    }
}

pub async fn node_watch_tick(
    pool: &SqlitePool,
    tz_offset_hours: i64,
    base_url: &str,
    heartbeat_timeout_secs: i64,
) -> anyhow::Result<()> {
    // offline_secs 取自 node_offline 规则参数（默认 90），必须 >= heartbeat_timeout
    let offline_secs = {
        let params: Option<String> = sqlx::query_scalar(
            "SELECT params FROM alert_rules WHERE enabled = 1 AND event_type = 'node_offline' LIMIT 1",
        )
        .fetch_optional(pool)
        .await?
        .flatten();
        params
            .map(|p| offline_secs_of(&p))
            .unwrap_or(90)
            .max(heartbeat_timeout_secs.max(1))
    };

    let nodes: Vec<(i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, name, last_heartbeat_at, online_state FROM nodes
          WHERE is_local = 0 AND enabled = 1",
    )
    .fetch_all(pool)
    .await?;

    let now = chrono::Utc::now().naive_utc();
    let timeout = chrono::Duration::seconds(heartbeat_timeout_secs.max(1));
    let offline_dur = chrono::Duration::seconds(offline_secs);

    for (id, name, last_hb_opt, state) in nodes {
        let Some(last_hb) = last_hb_opt else { continue }; // 从未上线，保持 unknown
        let Ok(last) = NaiveDateTime::parse_from_str(last_hb.trim(), "%Y-%m-%d %H:%M:%S") else {
            continue;
        };
        let age = now - last;
        let is_online = age <= timeout;
        let is_offline = age >= offline_dur;

        match (state.as_str(), is_online, is_offline) {
            ("online", false, true) => {
                sqlx::query("UPDATE nodes SET online_state = 'offline' WHERE id = ?")
                    .bind(id)
                    .execute(pool)
                    .await?;
                tracing::warn!("节点离线：{name}（id={id}）");
                emit(
                    pool,
                    AlertDraft::node_offline(id, &name, &last_hb, offline_secs, tz_offset_hours, base_url),
                )
                .await?;
            }
            ("offline", true, _) => {
                sqlx::query("UPDATE nodes SET online_state = 'online' WHERE id = ?")
                    .bind(id)
                    .execute(pool)
                    .await?;
                tracing::info!("节点恢复：{name}（id={id}）");
                emit(pool, AlertDraft::node_online(id, &name, base_url)).await?;
            }
            ("unknown", true, _) => {
                sqlx::query("UPDATE nodes SET online_state = 'online' WHERE id = ?")
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
            _ => {}
        }
    }
    Ok(())
}
