//! P6 —— Sing-box JSON 解析：outbounds 数组 → ParsedNode（过滤非节点类型）

use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::services::importer::ParsedNode;

/// 非节点类型（选择器/测速/直连/拦截/dns 等），解析时过滤
const NON_NODE_TYPES: &[&str] = &[
    "selector", "urltest", "direct", "block", "dns", "tun", "redirect", "tproxy", "shadowsocksr",
];

pub fn parse_singbox(content: &str) -> AppResult<Vec<ParsedNode>> {
    let root: Value =
        serde_json::from_str(content).map_err(|e| AppError::bad(format!("JSON 解析失败：{e}")))?;
    let outbounds = root
        .get("outbounds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::bad("不是 Sing-box 订阅：缺少 outbounds 数组"))?;

    let mut out = Vec::new();
    for ob in outbounds {
        let typ = ob.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if typ.is_empty() || NON_NODE_TYPES.contains(&typ) {
            continue;
        }
        let kind = match typ {
            "shadowsocks" => "ss",
            "vmess" => "vmess",
            "vless" => "vless",
            "trojan" => "trojan",
            "socks" => "socks5",
            "http" => {
                if ob
                    .get("tls")
                    .and_then(|t| t.get("enabled"))
                    .and_then(|e| e.as_bool())
                    .unwrap_or(false)
                {
                    "https"
                } else {
                    "http"
                }
            }
            "hysteria2" => "hysteria2",
            "tuic" => "tuic",
            "wireguard" => "wireguard",
            _ => continue,
        }
        .to_string();
        let host = ob
            .get("server")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let port: u16 = ob
            .get("server_port")
            .and_then(|p| p.as_u64().and_then(|x| u16::try_from(x).ok()))
            .unwrap_or(0);
        if host.is_empty() || port == 0 {
            continue;
        }
        let name = ob
            .get("tag")
            .and_then(|t| t.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{host}:{port}"));
        let (username, password) = match kind.as_str() {
            "ss" => (None, ob.get("password").and_then(|x| x.as_str()).map(str::to_string)),
            "trojan" => (None, ob.get("password").and_then(|x| x.as_str()).map(str::to_string)),
            "vmess" | "vless" => (None, ob.get("uuid").and_then(|x| x.as_str()).map(str::to_string)),
            "hysteria2" => (
                None,
                ob.get("password")
                    .and_then(|x| x.as_str())
                    .or_else(|| ob.get("auth").and_then(|x| x.as_str()))
                    .map(str::to_string),
            ),
            "tuic" => (
                None,
                ob.get("uuid")
                    .and_then(|x| x.as_str())
                    .or_else(|| ob.get("password").and_then(|x| x.as_str()))
                    .map(str::to_string),
            ),
            _ => (
                ob.get("username").and_then(|x| x.as_str()).map(str::to_string),
                ob.get("password").and_then(|x| x.as_str()).map(str::to_string),
            ),
        };
        out.push(ParsedNode {
            name,
            kind,
            host,
            port,
            username,
            password,
            extra: ob.clone(),
            duplicate: false,
        });
    }
    if out.is_empty() {
        return Err(AppError::bad("Sing-box 订阅中未解析出可用节点"));
    }
    Ok(out)
}
