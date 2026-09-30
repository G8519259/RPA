//! P6 —— URI 解析：ss / vmess / vless / trojan / hysteria2 / tuic / socks5 / http(s)

use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::services::importer::{ParsedNode, b64_decode};

/// 解析单行 URI；无法识别返回 None（调用方跳过）
pub fn parse_uri_line(line: &str) -> Option<ParsedNode> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let scheme_end = line.find("://")?;
    let scheme = line[..scheme_end].to_lowercase();
    match scheme.as_str() {
        "ss" => parse_ss(line),
        "vmess" => parse_vmess(line),
        "vless" => parse_vless(line),
        "trojan" => parse_trojan(line),
        "hysteria2" | "hy2" => parse_hysteria2(line),
        "tuic" => parse_tuic(line),
        "socks5" | "socks" => parse_socks5(line),
        "http" | "https" => parse_http(line, &scheme),
        _ => None,
    }
}

fn name_from_fragment(line: &str, fallback: &str) -> String {
    line.rfind('#')
        .map(|i| percent_decode(&line[i + 1..]).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn percent_decode(s: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let mut it = s.as_bytes().iter().peekable();
    while let Some(&b) = it.next() {
        if b == b'%' {
            let h: Vec<u8> = it.by_ref().take(2).copied().collect();
            if h.len() == 2 {
                if let (Ok(hex),) = (std::str::from_utf8(&h),) {
                    if let Ok(v) = u8::from_str_radix(hex, 16) {
                        bytes.push(v);
                        continue;
                    }
                }
                bytes.push(b'%');
                bytes.extend_from_slice(&h);
            } else {
                bytes.push(b'%');
                bytes.extend_from_slice(&h);
            }
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| s.to_string())
}

fn split_user_host(rest: &str) -> Option<((String, Option<String>), String, u16)> {
    // rest: [userinfo@]host:port[/...][?...][#...]
    let no_frag = rest.split('#').next().unwrap_or(rest);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    let no_path = no_query.split('/').next().unwrap_or(no_query);
    let (userinfo, hostport) = match no_path.rfind('@') {
        Some(i) => (Some(&no_path[..i]), &no_path[i + 1..]),
        None => (None, no_path),
    };
    let (host, port) = if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        let h = &hostport[1..end];
        let p: u16 = hostport[end + 1..].trim_start_matches(':').parse().ok()?;
        (h.to_string(), p)
    } else {
        let i = hostport.rfind(':')?;
        let h = hostport[..i].to_string();
        let p: u16 = hostport[i + 1..].parse().ok()?;
        if h.is_empty() {
            return None;
        }
        (h, p)
    };
    let (user, pass) = match userinfo {
        Some(u) => match u.find(':') {
            Some(i) => (
                percent_decode(&u[..i]),
                Some(percent_decode(&u[i + 1..])),
            ),
            None => (percent_decode(u), None),
        },
        None => (String::new(), None),
    };
    Some(((user, pass), host, port))
}

fn parse_ss(line: &str) -> Option<ParsedNode> {
    let rest = &line[5..];
    if let Some(((user, pass), host, port)) = split_user_host(rest) {
        let (method, password) = if !user.is_empty() && pass.is_none() {
            let dec = b64_decode(&user).ok()?;
            let i = dec.find(':')?;
            (dec[..i].to_string(), dec[i + 1..].to_string())
        } else if let Some(p) = pass {
            (user, p)
        } else {
            return None;
        };
        let name = name_from_fragment(line, &format!("{host}:{port}"));
        return Some(ParsedNode {
            name,
            kind: "ss".into(),
            host,
            port,
            username: None,
            password: Some(password),
            extra: json!({"method": method}),
            duplicate: false,
        });
    }
    // 整体 base64 形式：ss://base64(method:password@host:port)
    let no_frag = rest.split('#').next().unwrap_or(rest);
    let dec = b64_decode(no_frag).ok()?;
    let frag = line.rfind('#').map(|i| &line[i..]).unwrap_or("");
    parse_ss(&format!("ss://{dec}{frag}"))
}

fn parse_vmess(line: &str) -> Option<ParsedNode> {
    let rest = line[8..].split('#').next().unwrap_or(&line[8..]);
    let dec = b64_decode(rest.trim()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&dec).ok()?;
    let host = v.get("add")?.as_str()?.to_string();
    let port: u16 = v
        .get("port")
        .and_then(|p| {
            p.as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| p.as_u64().and_then(|x| u16::try_from(x).ok()))
        })
        .unwrap_or(0);
    if host.is_empty() || port == 0 {
        return None;
    }
    let name = v
        .get("ps")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| name_from_fragment(line, &format!("{host}:{port}")));
    let mut extra = v.clone();
    if let Some(m) = extra.as_object_mut() {
        m.remove("ps");
    }
    Some(ParsedNode {
        name,
        kind: "vmess".into(),
        host,
        port,
        username: None,
        password: v.get("id").and_then(|x| x.as_str()).map(str::to_string),
        extra,
        duplicate: false,
    })
}

fn parse_vless(line: &str) -> Option<ParsedNode> {
    let rest = &line[8..];
    let ((user, _), host, port) = split_user_host(rest)?;
    if user.is_empty() {
        return None;
    }
    Some(ParsedNode {
        name: name_from_fragment(line, &format!("{host}:{port}")),
        kind: "vless".into(),
        host,
        port,
        username: None,
        password: Some(user),
        extra: json!({}),
        duplicate: false,
    })
}

fn parse_trojan(line: &str) -> Option<ParsedNode> {
    let rest = &line[9..];
    let ((user, _), host, port) = split_user_host(rest)?;
    if user.is_empty() {
        return None;
    }
    Some(ParsedNode {
        name: name_from_fragment(line, &format!("{host}:{port}")),
        kind: "trojan".into(),
        host,
        port,
        username: None,
        password: Some(user),
        extra: json!({}),
        duplicate: false,
    })
}

fn parse_hysteria2(line: &str) -> Option<ParsedNode> {
    let scheme_len = if line.starts_with("hysteria2://") {
        13
    } else {
        6
    };
    let rest = &line[scheme_len..];
    let ((user, _), host, port) = split_user_host(rest)?;
    if user.is_empty() {
        return None;
    }
    Some(ParsedNode {
        name: name_from_fragment(line, &format!("{host}:{port}")),
        kind: "hysteria2".into(),
        host,
        port,
        username: None,
        password: Some(user),
        extra: json!({}),
        duplicate: false,
    })
}

fn parse_tuic(line: &str) -> Option<ParsedNode> {
    let rest = &line[7..];
    let ((user, pass), host, port) = split_user_host(rest)?;
    if user.is_empty() {
        return None;
    }
    Some(ParsedNode {
        name: name_from_fragment(line, &format!("{host}:{port}")),
        kind: "tuic".into(),
        host,
        port,
        username: None,
        password: pass.or(Some(user)),
        extra: json!({}),
        duplicate: false,
    })
}

fn parse_socks5(line: &str) -> Option<ParsedNode> {
    let scheme_len = if line.starts_with("socks5://") { 9 } else { 8 };
    let rest = &line[scheme_len..];
    let ((user, pass), host, port) = split_user_host(rest)?;
    Some(ParsedNode {
        name: name_from_fragment(line, &format!("{host}:{port}")),
        kind: "socks5".into(),
        host,
        port,
        username: if user.is_empty() { None } else { Some(user) },
        password: pass,
        extra: json!({}),
        duplicate: false,
    })
}

fn parse_http(line: &str, scheme: &str) -> Option<ParsedNode> {
    let rest = &line[scheme.len() + 3..];
    let ((user, pass), host, port) = split_user_host(rest).or_else(|| {
        let no_frag = rest.split('#').next().unwrap_or(rest);
        let no_query = no_frag.split('?').next().unwrap_or(no_frag);
        let host = no_query.split('/').next().unwrap_or(no_query).to_string();
        if host.is_empty() {
            return None;
        }
        let port = if scheme == "https" { 443 } else { 80 };
        Some(((String::new(), None), host, port))
    })?;
    Some(ParsedNode {
        name: name_from_fragment(line, &format!("{host}:{port}")),
        kind: scheme.to_string(),
        host,
        port,
        username: if user.is_empty() { None } else { Some(user) },
        password: pass,
        extra: json!({}),
        duplicate: false,
    })
}

/// 按行解析 URI 列表
pub fn parse_uri_list(content: &str) -> AppResult<Vec<ParsedNode>> {
    let mut out = Vec::new();
    for line in content.lines() {
        if let Some(n) = parse_uri_line(line) {
            out.push(n);
        }
    }
    if out.is_empty() {
        return Err(AppError::bad("未解析出任何节点 URI"));
    }
    Ok(out)
}
