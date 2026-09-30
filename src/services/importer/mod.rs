//! P6 —— 订阅导入：安全拉取 / 格式识别 / 解析 / 解析缓存（§10）

pub mod fetch;
pub mod parse_clash;
pub mod parse_singbox;
pub mod parse_uri;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{AppError, AppResult};

/// §10.3 解析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNode {
    pub name: String,
    pub kind: String, // ss | vmess | vless | trojan | socks5 | http | ...
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub extra: serde_json::Value, // 原始字段全量保留
    pub duplicate: bool,          // 与现有条目 (kind, host, port) 重复
}

/// 服务端解析缓存条目（parse_token → 结果，10 分钟过期）
#[derive(Debug, Clone)]
pub struct CachedParse {
    pub nodes: Vec<ParsedNode>,
    pub source_url: Option<String>,
    pub source_type: String,
    pub created: Instant,
}

impl CachedParse {
    pub fn is_expired(&self) -> bool {
        self.created.elapsed() > Duration::from_secs(600)
    }
}

/// 从解析缓存取结果（过期/不存在返回 None，调用方提示重新解析）
pub async fn take_cached(
    cache: &tokio::sync::Mutex<HashMap<String, CachedParse>>,
    token: &str,
) -> Option<CachedParse> {
    let mut g = cache.lock().await;
    let c = g.get(token)?;
    if c.is_expired() {
        g.remove(token);
        return None;
    }
    Some(c.clone())
}

pub fn b64_decode(s: &str) -> AppResult<String> {
    let s = s.trim();
    // 补齐 padding
    let mut owned;
    let s = if s.len() % 4 != 0 {
        owned = s.to_string();
        while owned.len() % 4 != 0 {
            owned.push('=');
        }
        &owned
    } else {
        s
    };
    for eng in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::URL_SAFE,
    ] {
        if let Ok(b) = eng.decode(s) {
            if let Ok(t) = String::from_utf8(b) {
                return Ok(t);
            }
        }
    }
    Err(AppError::bad("base64 解码失败"))
}

/// 格式识别：JSON → YAML → base64 解码后再判断 → 按行 URI（§10.1）
pub fn parse_content(content: &str) -> AppResult<(String, Vec<ParsedNode>)> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(AppError::bad("内容为空"));
    }
    // 1) Sing-box JSON：含 outbounds 数组
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if v.get("outbounds").and_then(|o| o.as_array()).is_some() {
                return Ok(("singbox".into(), parse_singbox::parse_singbox(trimmed)?));
            }
        }
    }
    // 2) Clash YAML：含 proxies 数组
    if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
        let has_proxies = v
            .get(&serde_yaml::Value::String("proxies".to_string()))
            .and_then(|p| p.as_sequence())
            .is_some();
        if has_proxies {
            return Ok(("clash".into(), parse_clash::parse_clash(trimmed)?));
        }
    }
    // 3) base64 解码后再判断
    if let Ok(decoded) = b64_decode(trimmed) {
        let d = decoded.trim();
        let looks_uri = d.lines().any(|l| l.trim().contains("://"));
        if looks_uri {
            match parse_uri::parse_uri_list(d) {
                Ok(nodes) => return Ok(("base64".into(), nodes)),
                Err(_) => {}
            }
        }
        // 解码后也可能是 JSON/YAML
        if let Ok((t, nodes)) = parse_content_boxed(d) {
            let t = if t == "uri_list" { "base64".into() } else { t };
            return Ok((t, nodes));
        }
    }
    // 4) 按行 URI
    if let Ok(nodes) = parse_uri::parse_uri_list(trimmed) {
        return Ok(("uri_list".into(), nodes));
    }
    Err(AppError::bad("无法识别的订阅格式"))
}

/// 内部递归用的识别（不含 base64 层，避免无限递归）
fn parse_content_boxed(content: &str) -> AppResult<(String, Vec<ParsedNode>)> {
    let trimmed = content.trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .and_then(|v| v.get("outbounds").and_then(|o| o.as_array()).cloned())
            .is_some()
    {
        return Ok(("singbox".into(), parse_singbox::parse_singbox(trimmed)?));
    }
    if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
        if v
            .get(&serde_yaml::Value::String("proxies".to_string()))
            .and_then(|p| p.as_sequence())
            .is_some()
        {
            return Ok(("clash".into(), parse_clash::parse_clash(trimmed)?));
        }
    }
    if let Ok(nodes) = parse_uri::parse_uri_list(trimmed) {
        return Ok(("uri_list".into(), nodes));
    }
    Err(AppError::bad("无法识别的订阅格式"))
}

/// 标记与现有 proxy_rules 条目 (upstream_type, upstream_addr) 重复的节点
pub async fn mark_duplicates(pool: &SqlitePool, nodes: &mut [ParsedNode]) -> AppResult<()> {
    for n in nodes.iter_mut() {
        let addr = format!("{}:{}", n.host, n.port);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM proxy_rules WHERE upstream_type = ? AND upstream_addr = ?)",
        )
        .bind(&n.kind)
        .bind(&addr)
        .fetch_one(pool)
        .await?;
        n.duplicate = exists;
    }
    Ok(())
}
