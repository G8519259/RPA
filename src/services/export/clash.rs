//! Clash YAML 导出（仅代理类条目）
//!
//! 无模板时输出 proxies + select 类型的 PROXY 组 + url-test 类型的 AUTO 组 + rules [MATCH,PROXY]。
//! 带 extra 的条目把 extra 字段合并进去（extra 优先，最后强制覆盖 name）。

use crate::models::ExportNode;

/// 渲染 clash 配置。返回 (content, content_type, filename_ext)
pub fn render(nodes: &[ExportNode], sub_name: &str) -> (String, &'static str, &'static str) {
    let proxies: Vec<&ExportNode> = nodes.iter().filter(|n| n.entry_type == "proxy").collect();
    let mut out = String::new();
    out.push_str(&format!("# {sub_name} - 由 RustProxyAdmin 生成\n"));
    out.push_str("proxies:\n");
    for n in &proxies {
        out.push_str(&render_proxy(n));
    }
    let names: Vec<String> = proxies.iter().map(|n| n.name.clone()).collect();
    out.push_str("proxy-groups:\n");
    out.push_str("  - name: PROXY\n    type: select\n    proxies:\n      - AUTO\n");
    for nm in &names {
        out.push_str(&format!("      - {}\n", yaml_str(nm)));
    }
    if names.is_empty() {
        out.push_str("      - DIRECT\n");
    }
    out.push_str("  - name: AUTO\n    type: url-test\n    url: \"http://www.gstatic.com/generate_204\"\n    interval: 300\n    proxies:\n");
    for nm in &names {
        out.push_str(&format!("      - {}\n", yaml_str(nm)));
    }
    out.push_str("rules:\n  - MATCH,PROXY\n");
    (out, "text/yaml; charset=utf-8", "yaml")
}

fn render_proxy(n: &ExportNode) -> String {
    let name = yaml_str(&n.name);
    let mut s = format!("  - name: {name}\n");
    match n.kind.as_str() {
        "ss" => {
            s.push_str("    type: ss\n");
            s.push_str(&format!("    server: {}\n    port: {}\n", n.host, n.port));
            // 本系统未存储加密方式，默认 aes-256-gcm；如需指定请使用自定义模板
            s.push_str("    cipher: aes-256-gcm\n");
            s.push_str(&format!(
                "    password: {}\n",
                yaml_str(n.password.as_deref().unwrap_or(""))
            ));
            s.push_str("    udp: true\n");
        }
        "trojan" => {
            s.push_str("    type: trojan\n");
            s.push_str(&format!("    server: {}\n    port: {}\n", n.host, n.port));
            s.push_str(&format!(
                "    password: {}\n",
                yaml_str(n.password.as_deref().unwrap_or(""))
            ));
            s.push_str("    udp: true\n");
        }
        "vless" => {
            s.push_str("    type: vless\n");
            s.push_str(&format!("    server: {}\n    port: {}\n", n.host, n.port));
            s.push_str(&format!(
                "    uuid: {}\n",
                yaml_str(n.password.as_deref().unwrap_or(""))
            ));
            s.push_str("    encryption: none\n    udp: true\n");
        }
        "vmess" => {
            // extra 里若有完整 vmess 参数则合并；否则输出最小可用结构
            s.push_str("    type: vmess\n");
            s.push_str(&format!("    server: {}\n    port: {}\n", n.host, n.port));
            s.push_str(&format!(
                "    uuid: {}\n",
                yaml_str(n.password.as_deref().unwrap_or(""))
            ));
            s.push_str("    alterId: 0\n    cipher: auto\n    udp: true\n");
        }
        "socks5" => {
            s.push_str("    type: socks5\n");
            s.push_str(&format!("    server: {}\n    port: {}\n", n.host, n.port));
            if let Some(u) = &n.username {
                s.push_str(&format!("    username: {}\n", yaml_str(u)));
            }
            if let Some(p) = &n.password {
                s.push_str(&format!("    password: {}\n", yaml_str(p)));
            }
            s.push_str("    udp: true\n");
        }
        _ => {
            // http / https
            s.push_str("    type: http\n");
            s.push_str(&format!("    server: {}\n    port: {}\n", n.host, n.port));
            if n.kind == "https" {
                s.push_str("    tls: true\n");
            }
            if let Some(u) = &n.username {
                s.push_str(&format!("    username: {}\n", yaml_str(u)));
            }
            if let Some(p) = &n.password {
                s.push_str(&format!("    password: {}\n", yaml_str(p)));
            }
        }
    }
    // 合并 extra（extra 优先），最后强制覆盖 name
    if let Some(ex) = n.extra.as_ref().and_then(|v| v.as_object()) {
        for (k, v) in ex {
            if k == "name" {
                continue;
            }
            s.push_str(&format!("    {k}: {}\n", yaml_scalar(v)));
        }
    }
    s
}

fn yaml_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => yaml_str(s),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => yaml_str(&other.to_string()),
    }
}

fn yaml_str(s: &str) -> String {
    // 简单转义：含特殊字符则加双引号
    if s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') && !s.is_empty() {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}
