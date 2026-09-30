//! P12 —— Email 渠道发送（§14.2，lettre SMTP）
//!
//! config：{host, port, tls("starttls"|"plain"), username, password, from, to:[...]}

use anyhow::Context;
use reqwest::Client;
use serde_json::Value;

use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::AlertEvent;

pub async fn send(_http: &Client, cfg: &Value, ev: &AlertEvent) -> anyhow::Result<()> {
    let host = cfg
        .get("host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("缺少 host")?;
    let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(587) as u16;
    let from = cfg
        .get("from")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("缺少 from")?;
    let to_list: Vec<String> = cfg
        .get("to")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    if to_list.is_empty() {
        anyhow::bail!("收件人 to 列表为空");
    }

    let mut builder = match cfg.get("tls").and_then(|v| v.as_str()).unwrap_or("starttls") {
        "plain" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| anyhow::anyhow!("SMTP 配置失败: {e}"))?,
    };
    builder = builder.port(port);
    if let (Some(u), Some(p)) = (
        cfg.get("username").and_then(|v| v.as_str()),
        cfg.get("password").and_then(|v| v.as_str()),
    ) {
        if !u.is_empty() {
            builder = builder.credentials(Credentials::new(u.to_string(), p.to_string()));
        }
    }
    let mailer = builder.build();

    let mut msg = Message::builder().from(from.parse().map_err(|e| anyhow::anyhow!("from 无效: {e}"))?);
    for to in &to_list {
        msg = msg.to(to.parse().map_err(|e| anyhow::anyhow!("to 无效 {to}: {e}"))?);
    }
    let email = msg
        .subject(format!("[RustProxyAdmin 告警] {}", ev.title))
        .header(header::ContentType::TEXT_PLAIN)
        .multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(ev.body.clone())),
        )
        .map_err(|e| anyhow::anyhow!("构建邮件失败: {e}"))?;

    mailer
        .send(email)
        .await
        .map_err(|e| anyhow::anyhow!("SMTP 发送失败: {e}"))?;
    Ok(())
}
