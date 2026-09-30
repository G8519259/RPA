//! sing-box JSON 导出（仅代理类条目）
//!
//! outbounds（每个节点一个）+ selector + urltest；绑定模板时按第 12 章渲染。

use crate::models::ExportNode;
use serde_json::{json, Value};

pub fn render(nodes: &[ExportNode], sub_name: &str) -> (String, &'static str, &'static str) {
    let proxies: Vec<&ExportNode> = nodes.iter().filter(|n| n.entry_type == "proxy").collect();
    let mut outbounds: Vec<Value> = Vec::new();
    let mut names: Vec<Value> = Vec::new();
    for n in &proxies {
        names.push(json!(n.name));
        outbounds.push(render_outbound(n));
    }
    outbounds.push(json!({
        "type": "selector", "tag": "proxy",
        "outbounds": names, "default": names.first().unwrap_or(&json!("direct")),
    }));
    outbounds.push(json!({
        "type": "urltest", "tag": "auto",
        "outbounds": names,
        "url": "http://www.gstatic.com/generate_204",
        "interval": "5m",
    }));
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    let cfg = json!({
        "_comment": format!("{sub_name} - 由 RustProxyAdmin 生成"),
        "outbounds": outbounds,
        "route": { "final": "proxy" },
    });
    (
        serde_json::to_string_pretty(&cfg).unwrap_or_default(),
        "application/json; charset=utf-8",
        "json",
    )
}

fn render_outbound(n: &ExportNode) -> Value {
    let base = json!({
        "tag": n.name,
        "server": n.host,
        "server_port": n.port,
    });
    let mut o = match n.kind.as_str() {
        "ss" => json!({
            "type": "shadowsocks", "method": "aes-256-gcm",
            "password": n.password.as_deref().unwrap_or(""),
        }),
        "trojan" => json!({
            "type": "trojan", "password": n.password.as_deref().unwrap_or(""),
        }),
        "vless" => json!({
            "type": "vless", "uuid": n.password.as_deref().unwrap_or(""),
        }),
        "vmess" => json!({
            "type": "vmess",
            "uuid": n.password.as_deref().unwrap_or(""),
            "alter_id": 0, "security": "auto",
        }),
        "socks5" => {
            let mut v = json!({ "type": "socks", "version": "5" });
            if let Some(u) = &n.username {
                v["username"] = json!(u);
            }
            if let Some(p) = &n.password {
                v["password"] = json!(p);
            }
            v
        }
        _ => {
            let mut v = json!({ "type": "http" });
            if n.kind == "https" {
                v["tls"] = json!({ "enabled": true });
            }
            if let Some(u) = &n.username {
                v["username"] = json!(u);
            }
            if let Some(p) = &n.password {
                v["password"] = json!(p);
            }
            v
        }
    };
    // extra 合并（extra 优先），最后强制覆盖 tag
    if let Some(ex) = n.extra.as_ref().and_then(|v| v.as_object()) {
        for (k, v) in ex {
            if k == "tag" {
                continue;
            }
            o[k] = v.clone();
        }
    }
    for (k, v) in base.as_object().unwrap() {
        o[k] = v.clone();
    }
    o
}
