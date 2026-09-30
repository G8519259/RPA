//! P6 —— Clash YAML 解析：proxies 数组 → ParsedNode（原始字段全量保留为 extra）

use serde_yaml::Value;

use crate::error::{AppError, AppResult};
use crate::services::importer::ParsedNode;

fn get_str(m: &serde_yaml::Mapping, key: &str) -> Option<String> {
    m.get(&Value::String(key.to_string()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_port(m: &serde_yaml::Mapping) -> Option<u16> {
    let v = m.get(&Value::String("port".to_string()))?;
    if let Some(n) = v.as_u64() {
        return u16::try_from(n).ok();
    }
    if let Some(s) = v.as_str() {
        return s.parse().ok();
    }
    None
}

pub fn parse_clash(content: &str) -> AppResult<Vec<ParsedNode>> {
    let root: Value =
        serde_yaml::from_str(content).map_err(|e| AppError::bad(format!("YAML 解析失败：{e}")))?;
    let proxies = root
        .get(&Value::String("proxies".to_string()))
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| AppError::bad("不是 Clash 订阅：缺少 proxies 数组"))?;

    let mut out = Vec::new();
    for p in proxies {
        let m = match p.as_mapping() {
            Some(m) => m,
            None => continue,
        };
        let name = get_str(m, "name").unwrap_or_else(|| "未命名".to_string());
        let kind = get_str(m, "type").unwrap_or_default().to_lowercase();
        let host = get_str(m, "server").unwrap_or_default();
        let port = get_port(m).unwrap_or(0);
        if host.is_empty() || port == 0 {
            continue;
        }
        let kind = match kind.as_str() {
            "ss" | "shadowsocks" => "ss",
            "vmess" => "vmess",
            "vless" => "vless",
            "trojan" => "trojan",
            "socks5" | "socks" => "socks5",
            "http" => "http",
            "https" => "https",
            "hysteria2" | "hysteria" => "hysteria2",
            "tuic" => "tuic",
            _ => continue, // 不支持的类型跳过
        }
        .to_string();
        let (username, password) = match kind.as_str() {
            "ss" => (None, get_str(m, "password")),
            "trojan" => (None, get_str(m, "password")),
            "vmess" | "vless" => (None, get_str(m, "uuid")),
            "hysteria2" => (None, get_str(m, "password").or_else(|| get_str(m, "auth"))),
            "tuic" => (None, get_str(m, "password").or_else(|| get_str(m, "uuid"))),
            _ => (get_str(m, "username"), get_str(m, "password")),
        };
        // extra：整个节点字典转 JSON 全量保留
        let extra =
            serde_json::to_value(p).unwrap_or(serde_json::Value::Object(Default::default()));
        out.push(ParsedNode {
            name,
            kind,
            host,
            port,
            username,
            password,
            extra,
            duplicate: false,
        });
    }
    if out.is_empty() {
        return Err(AppError::bad("Clash 订阅中未解析出可用节点"));
    }
    Ok(out)
}
