use crate::error::{AppError, AppResult};
use actix_web::HttpRequest;
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Utc};
use rand::TryRngCore;
use std::net::IpAddr;

pub const TIME_FMT: &str = "%Y-%m-%d %H:%M:%S";

/// 当前 UTC 时间字符串
pub fn now_str() -> String {
    Utc::now().format(TIME_FMT).to_string()
}

pub fn now_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

pub fn parse_time(s: &str) -> AppResult<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, TIME_FMT)
        .map_err(|_| AppError::bad("时间格式应为 YYYY-MM-DD HH:MM:SS（UTC）"))
}

/// 32 字节随机数 base64url（256 bit），用于订阅 token / Node api_token / session id / csrf
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .expect("OsRng 失败");
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// 条目类型 → 表名白名单，杜绝表名注入
pub fn table_of(t: &str) -> AppResult<&'static str> {
    match t {
        "proxy" => Ok("proxy_rules"),
        "forward" => Ok("port_forwards"),
        "tunnel" => Ok("tunnels"),
        _ => Err(AppError::bad("未知条目类型")),
    }
}

pub fn valid_entry_type(t: &str) -> bool {
    matches!(t, "proxy" | "forward" | "tunnel")
}

/// 客户端真实 IP：仅可信反代才读 X-Forwarded-For
pub fn client_ip(req: &HttpRequest, trusted_proxies: &[String]) -> String {
    let peer = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let trusted = trusted_proxies.iter().any(|p| p == &peer || p == "*");
    if trusted {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                if let Some(first) = s.split(',').next() {
                    let ip = first.trim();
                    if !ip.is_empty() {
                        return ip.to_string();
                    }
                }
            }
        }
    }
    peer
}

pub fn header_str(req: &HttpRequest, name: &str) -> String {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// "host:port" 拆分，host 可能带方括号 IPv6
pub fn split_host_port(addr: &str) -> (String, Option<u16>) {
    let addr = addr.trim();
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            let host = addr[1..end].to_string();
            let rest = &addr[end + 1..];
            let port = rest.strip_prefix(':').and_then(|p| p.parse().ok());
            return (host, port);
        }
    }
    match addr.rfind(':') {
        Some(i) => {
            let (h, p) = addr.split_at(i);
            // 避免把 IPv6 无端口当成 host:port
            if h.contains(':') {
                (addr.to_string(), None)
            } else {
                (h.to_string(), p[1..].parse().ok())
            }
        }
        None => (addr.to_string(), None),
    }
}

pub fn fmt_bytes(b: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// 过期时间计算：1d | 7d | 30d | 90d | permanent | custom
pub fn calc_expires(preset: &str, custom: Option<&str>) -> AppResult<Option<String>> {
    let d = match preset {
        "1d" => 1,
        "7d" => 7,
        "30d" => 30,
        "90d" => 90,
        "permanent" => return Ok(None),
        "custom" => {
            let s = custom.ok_or_else(|| AppError::bad("缺少 expires_at"))?;
            parse_time(s)?;
            return Ok(Some(s.to_string()));
        }
        _ => return Err(AppError::bad("未知的过期预设")),
    };
    Ok(Some(
        (Utc::now() + Duration::days(d)).format(TIME_FMT).to_string(),
    ))
}

/// 返回包含 now 的那个月度周期起点（00:00:00，UTC 存储）
pub fn cycle_start(now_utc: NaiveDateTime, reset_day: u32, tz_offset_hours: i64) -> NaiveDateTime {
    let local = now_utc + Duration::hours(tz_offset_hours);
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
    start_local - Duration::hours(tz_offset_hours)
}

/// UTC 字符串 → 本地（台北）显示字符串
pub fn to_local_str(utc_s: &str, tz_offset_hours: i64) -> String {
    match NaiveDateTime::parse_from_str(utc_s, TIME_FMT) {
        Ok(dt) => (dt + Duration::hours(tz_offset_hours))
            .format(TIME_FMT)
            .to_string(),
        Err(_) => utc_s.to_string(),
    }
}

/// 是否为内网 / 回环 / 链路本地 / 元数据地址（SSRF 防护用）
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
                || o[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
        }
    }
}

pub fn truncate(s: &str, n: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.char_indices() {
        if i >= n {
            break;
        }
        out.push(c);
    }
    out
}
