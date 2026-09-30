//! P12 —— Webhook 渠道发送（§14.2）
//!
//! POST JSON：{event_type, severity, title, body, resource_type, resource_id, created_at}
//! 配置 secret 时附带 `X-RPA-Signature: sha256=<HMAC-SHA256(body, secret) 十六进制>`。

use anyhow::Context;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::Value;
use sha2::Sha256;

use super::AlertEvent;

/// 发送一条告警事件到 webhook。
pub async fn send(http: &Client, cfg: &Value, ev: &AlertEvent) -> anyhow::Result<()> {
    let url = cfg
        .get("url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("缺少 url")?;

    let body = serde_json::json!({
        "event_type": ev.event_type,
        "severity": ev.severity,
        "title": ev.title,
        "body": ev.body,
        "resource_type": ev.resource_type,
        "resource_id": ev.resource_id,
        "created_at": ev.created_at,
    });
    let body_str = serde_json::to_string(&body)?;

    let mut req = http
        .post(url)
        .header("Content-Type", "application/json")
        .body(body_str.clone())
        .timeout(std::time::Duration::from_secs(15));

    // 可选签名
    if let Some(secret) = cfg.get("secret").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        req = req.header("X-RPA-Signature", sign(secret, body_str.as_bytes()));
    }
    // 可选自定义请求头
    if let Some(headers) = cfg.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in headers {
            if let Some(vs) = v.as_str() {
                req = req.header(k.as_str(), vs);
            }
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Webhook 请求失败: {}", e.without_url()))?;
    if !resp.status().is_success() {
        anyhow::bail!("Webhook 返回 HTTP {}", resp.status());
    }
    Ok(())
}

fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}
