//! P12 —— 告警投递器（§14.6）
//!
//! 每 10 秒一轮：取 pending 且到重试时间的事件 → 按规则绑定的渠道逐个发送。
//! - 只要有一个渠道成功就算成功；
//! - 规则未绑定渠道：直接标 sent，last_error="规则未绑定渠道"；
//! - 失败：attempts+1，退避 60 / 120 / 240 / 480 秒，超过 5 次 status=failed。

use reqwest::Client;
use sqlx::SqlitePool;

use super::{email, telegram, webhook, AlertDraft, AlertEvent};

/// 后台任务入口（main.rs 里 spawn）
pub async fn dispatcher_loop(pool: SqlitePool, http: Client, secret_key: Option<String>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        let evs: Vec<AlertEvent> = match sqlx::query_as(
            "SELECT * FROM alert_events
              WHERE status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= datetime('now'))
              ORDER BY id LIMIT 50",
        )
        .fetch_all(&pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("告警投递：查询事件失败: {e:?}");
                continue;
            }
        };

        for ev in evs {
            match send_event(&pool, &http, &ev, secret_key.as_deref()).await {
                Ok(()) => {
                    let _ = sqlx::query(
                        "UPDATE alert_events SET status='sent', sent_at=datetime('now'),
                                attempts=attempts+1, last_error=NULL WHERE id=?",
                    )
                    .bind(ev.id)
                    .execute(&pool)
                    .await;
                }
                Err(SendError::NoChannel) => {
                    // §14.6：规则未绑定渠道的事件直接标 sent，避免堆积
                    let _ = sqlx::query(
                        "UPDATE alert_events SET status='sent', sent_at=datetime('now'),
                                attempts=attempts+1, last_error='规则未绑定渠道' WHERE id=?",
                    )
                    .bind(ev.id)
                    .execute(&pool)
                    .await;
                }
                Err(SendError::Other(e)) => {
                    let attempts = ev.attempts + 1;
                    let (status, delay) = if attempts >= 5 {
                        ("failed", 0)
                    } else {
                        ("pending", 30 * (1 << attempts)) // 60,120,240,480 秒
                    };
                    let err = truncate(&e.to_string(), 300);
                    let _ = sqlx::query(
                        "UPDATE alert_events SET status=?, attempts=?, last_error=?,
                                next_retry_at=datetime('now', ?) WHERE id=?",
                    )
                    .bind(status)
                    .bind(attempts)
                    .bind(err)
                    .bind(format!("+{delay} seconds"))
                    .bind(ev.id)
                    .execute(&pool)
                    .await;
                }
            }
        }
    }
}

/// 发送失败分类：NoChannel（规则未绑定渠道）直接标 sent，避免堆积
#[derive(Debug)]
pub enum SendError {
    NoChannel,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for SendError {
    fn from(e: anyhow::Error) -> Self {
        SendError::Other(e)
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::NoChannel => write!(f, "规则未绑定渠道"),
            SendError::Other(e) => write!(f, "{e}"),
        }
    }
}

async fn send_event(
    pool: &SqlitePool,
    http: &Client,
    ev: &AlertEvent,
    secret_key: Option<&str>,
) -> Result<(), SendError> {
    let rule_id = ev
        .rule_id
        .ok_or_else(|| anyhow::anyhow!("事件没有关联规则"))?;
    let channel_ids: String = sqlx::query_scalar(
        "SELECT channel_ids FROM alert_rules WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| SendError::Other(anyhow::anyhow!("查规则失败: {e}")))?
    .flatten()
    .unwrap_or_else(|| "[]".to_string());
    let ids: Vec<i64> = serde_json::from_str(&channel_ids).unwrap_or_default();
    if ids.is_empty() {
        return Err(SendError::NoChannel);
    }

    let mut ok = 0;
    let mut errs: Vec<String> = Vec::new();
    for cid in ids {
        let ch: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT kind, config, enabled FROM alert_channels WHERE id = ?",
        )
        .bind(cid)
        .fetch_optional(pool)
        .await
        .map_err(|e| SendError::Other(anyhow::anyhow!("查渠道失败: {e}")))?;
        let Some((kind, config_str, enabled)) = ch else {
            continue;
        };
        if enabled == 0 {
            continue;
        }
        let cfg: serde_json::Value = serde_json::from_str(&config_str).unwrap_or_default();
        // P13：渠道密钥可能是 AES-GCM 密文，先解密
        let cfg = super::crypto::decrypt_config(&cfg, secret_key);
        let r = match kind.as_str() {
            "telegram" => telegram::send(http, &cfg, &text_of(ev)).await,
            "webhook" => webhook::send(http, &cfg, ev).await,
            "email" => email::send(http, &cfg, ev).await,
            k => Err(anyhow::anyhow!("未知渠道类型: {k}")),
        };
        match r {
            Ok(()) => ok += 1,
            Err(e) => errs.push(truncate(&e.to_string(), 150)),
        }
    }
    if ok > 0 {
        Ok(())
    } else if errs.is_empty() {
        Err(SendError::Other(anyhow::anyhow!(
            "规则绑定的渠道均不可用（已删除或被禁用）"
        )))
    } else {
        Err(SendError::Other(anyhow::anyhow!("{}", errs.join("；"))))
    }
}

/// Telegram 渠道的发送文本
fn text_of(ev: &AlertEvent) -> String {
    format!("{}\n\n{}", ev.title, ev.body)
}

/// 直接用草稿发送到某个渠道（用于"发送测试"按钮，不经过规则与事件表）
pub async fn send_draft_to_channel(
    pool: &SqlitePool,
    http: &Client,
    channel_id: i64,
    draft: &AlertDraft,
    secret_key: Option<&str>,
) -> anyhow::Result<()> {
    let ch: Option<(String, String, i64)> =
        sqlx::query_as("SELECT kind, config, enabled FROM alert_channels WHERE id = ?")
            .bind(channel_id)
            .fetch_optional(pool)
            .await?;
    let (kind, config_str, enabled) = ch.ok_or_else(|| anyhow::anyhow!("渠道不存在"))?;
    if enabled == 0 {
        anyhow::bail!("渠道已禁用");
    }
    let cfg: serde_json::Value = serde_json::from_str(&config_str).unwrap_or_default();
    let cfg = super::crypto::decrypt_config(&cfg, secret_key);
    let ev = AlertEvent {
        id: 0,
        rule_id: None,
        event_type: draft.event_type.to_string(),
        dedup_key: draft.dedup_key.clone(),
        severity: draft.severity.to_string(),
        title: draft.title.clone(),
        body: draft.body.clone(),
        resource_type: draft.resource_type.as_ref().map(|s| s.to_string()),
        resource_id: draft.resource_id,
        status: "pending".into(),
        attempts: 0,
        next_retry_at: None,
        last_error: None,
        created_at: String::new(),
        sent_at: None,
    };
    match kind.as_str() {
        "telegram" => telegram::send(http, &cfg, &text_of(&ev)).await,
        "webhook" => webhook::send(http, &cfg, &ev).await,
        "email" => email::send(http, &cfg, &ev).await,
        k => Err(anyhow::anyhow!("未知渠道类型: {k}")),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}
