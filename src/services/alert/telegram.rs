//! P12 —— Telegram 渠道发送
//!
//! POST https://api.telegram.org/bot<token>/sendMessage。
//! 安全：URL 里含 bot_token，日志与错误信息中不得打印完整 URL。

use anyhow::Context;
use reqwest::Client;
use serde_json::Value;

/// 发送纯文本消息（Markdown 未启用时按原样显示）。
pub async fn send(http: &Client, cfg: &Value, text: &str) -> anyhow::Result<()> {
    let token = cfg
        .get("bot_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("缺少 bot_token")?;
    let chat = cfg
        .get("chat_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("缺少 chat_id")?;

    let client = if let Some(proxy) = cfg.get("proxy").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        let p = reqwest::Proxy::all(proxy).context("代理地址无效")?;
        Client::builder().proxy(p).build().context("构建代理客户端失败")?
    } else {
        http.clone()
    };

    let resp = client
        .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .json(&serde_json::json!({
            "chat_id": chat,
            "text": text,
            "disable_web_page_preview": true,
        }))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        // reqwest 的错误可能把 URL（含 token）带出来，截断 URL 部分
        .map_err(|e| anyhow::anyhow!("Telegram 请求失败: {}", scrub_url(&e.to_string())))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Telegram 返回 HTTP {}: {}",
            status,
            truncate(&body, 200)
        );
    }
    Ok(())
}

/// 错误文本中移除疑似 bot URL 的片段（形如 bot<token>/...）
fn scrub_url(s: &str) -> String {
    let re = regex_lite_token(s);
    re
}

fn regex_lite_token(s: &str) -> String {
    // 无 regex 依赖：手工把 "bot<...>/" 片段替换掉
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].starts_with("bot") && i + 4 < bytes.len() && !s[i + 3..i + 4].eq("/") {
            // 从 "bot" 起到下一个 '/' 为止全部替换
            if let Some(end) = s[i..].find('/') {
                out.push_str("bot<redacted>/");
                i += end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}
