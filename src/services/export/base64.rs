//! P4 —— Base64 订阅导出（每行一个代理 URI，整体 base64）

use crate::models::ExportNode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// 各协议 URI：
/// - ss://base64(method:password)@host:port#name
/// - trojan://password@host:port#name
/// - vless://uuid@host:port?encryption=none#name
/// - socks5://[user:pass@]host:port#name
/// - http(s)://[user:pass@]host:port#name
pub fn render(nodes: &[ExportNode], _sub_name: &str) -> (String, &'static str, &'static str) {
    // 每行一个 URI；无法转成 URI 的条目跳过
    let mut lines: Vec<String> = Vec::new();
    for n in nodes.iter().filter(|n| n.entry_type == "proxy") {
        if let Some(uri) = proxy_uri(n) {
            lines.push(uri);
        }
    }
    let joined = lines.join("\n");
    (STANDARD.encode(joined), "text/plain; charset=utf-8", "txt")
}

fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

fn userinfo(n: &ExportNode) -> String {
    match (&n.username, &n.password) {
        (Some(u), Some(p)) => format!("{}:{}@", enc(u), enc(p)),
        (Some(u), None) => format!("{}@", enc(u)),
        _ => String::new(),
    }
}

fn proxy_uri(n: &ExportNode) -> Option<String> {
    let name = enc(&n.name);
    Some(match n.kind.as_str() {
        "ss" => {
            let method = "aes-256-gcm"; // 未存储加密方式，默认
            let pw = n.password.as_deref().unwrap_or("");
            let up = STANDARD.encode(format!("{method}:{pw}"));
            format!("ss://{up}@{}:{}#{}", n.host, n.port, name)
        }
        "trojan" => {
            let pw = enc(n.password.as_deref().unwrap_or(""));
            format!("trojan://{pw}@{}:{}#{}", n.host, n.port, name)
        }
        "vless" => {
            let uuid = enc(n.password.as_deref().unwrap_or(""));
            format!("vless://{uuid}@{}:{}?encryption=none#{}", n.host, n.port, name)
        }
        "vmess" => {
            // vmess URI 需要完整 JSON，这里只能输出最小可用结构
            let vm = serde_json::json!({
                "v": "2", "ps": n.name, "add": n.host, "port": n.port.to_string(),
                "id": n.password.as_deref().unwrap_or(""), "aid": "0",
                "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
            });
            format!("vmess://{}", STANDARD.encode(vm.to_string()))
        }
        "socks5" => format!("socks5://{}{}:{}#{}", userinfo(n), n.host, n.port, name),
        "https" => format!("https://{}{}:{}#{}", userinfo(n), n.host, n.port, name),
        "http" => format!("http://{}{}:{}#{}", userinfo(n), n.host, n.port, name),
        _ => return None, // 无法转成 URI 的条目跳过
    })
}
