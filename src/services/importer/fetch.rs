//! P6 —— 安全拉取（防 SSRF，§10.2）：
//! 只允许 http/https；DNS 解析后拒绝回环/私网/链路本地/云元数据地址；
//! 超时 15s，响应体上限 5MB，最多跟随 3 次重定向（每次重定向后重新校验）。

use std::net::IpAddr;

use crate::error::{AppError, AppResult};

const MAX_BODY: usize = 5 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;

fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 127 // 127.0.0.0/8 回环
                || o[0] == 10 // 10.0.0.0/8
                || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16
                || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16 链路本地/云元数据
                || o[0] == 0 // 0.0.0.0/8
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 链路本地
        }
    }
}

/// 校验 URL 并解析主机 DNS，所有解析结果都不能是内网地址
async fn check_url(url: &str) -> AppResult<(String, u16)> {
    let parsed = url::Url::parse(url).map_err(|_| AppError::bad("URL 格式错误"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(AppError::bad("只允许 http/https 订阅地址"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::bad("URL 缺少主机名"))?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    // DNS 解析后逐个检查
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|_| AppError::bad("DNS 解析失败"))?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(AppError::bad("DNS 解析失败"));
    }
    for ip in &addrs {
        if is_blocked_ip(ip) {
            return Err(AppError::bad("订阅地址解析到内网/保留地址，已拒绝（防 SSRF）"));
        }
    }
    Ok((host.to_string(), port))
}

/// 安全拉取订阅内容（手动处理重定向，每次重定向后重新校验）
pub async fn fetch_subscription(
    client: &reqwest::Client,
    url: &str,
    user_agent: &str,
) -> AppResult<String> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        check_url(&current).await?;
        // 禁用 reqwest 自动重定向，手动处理以便每次校验
        let resp = client
            .get(&current)
            .header("User-Agent", user_agent)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| AppError::bad(format!("拉取失败：{e}")))?;
        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AppError::bad("重定向缺少 Location"))?;
            let base = url::Url::parse(&current).map_err(|_| AppError::bad("URL 错误"))?;
            let next = base
                .join(loc)
                .map_err(|_| AppError::bad("重定向地址错误"))?;
            current = next.to_string();
            continue;
        }
        if !status.is_success() {
            return Err(AppError::bad(format!("订阅地址返回 HTTP {status}")));
        }
        let len: Option<usize> = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        if let Some(l) = len {
            if l > MAX_BODY {
                return Err(AppError::bad("订阅内容超过 5 MB 上限"));
            }
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AppError::bad(format!("读取响应失败：{e}")))?;
        if bytes.len() > MAX_BODY {
            return Err(AppError::bad("订阅内容超过 5 MB 上限"));
        }
        return Ok(String::from_utf8_lossy(&bytes).into_owned());
    }
    Err(AppError::bad("重定向次数过多（超过 3 次）"))
}
