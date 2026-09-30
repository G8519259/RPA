//! P5 —— 订阅模板：结构化标记渲染 + 保存前校验。
//!
//! 标记（§12.2）：@ALL / @TAG:x / @GROUP:x / @TYPE:x / @REGEX:re；普通字符串原样保留。
//! 渲染：Clash=YAML 解析后填 proxies 并展开 proxy-groups 成员；
//!       Sing-box=JSON 解析后展开 selector/urltest 的 outbounds 并追加节点。

use std::collections::{HashMap, HashSet};

use serde_json::Value as JsonValue;
use serde_yaml::{Mapping, Value as YamlValue};

use crate::error::{AppError, AppResult};
use crate::models::{ExportNode, SubTemplate, Subscription};

pub struct Rendered {
    pub content: String,
    pub content_type: String,
    pub ext: String,
}

pub const FORMATS: &[&str] = &["clash", "singbox", "json", "base64"];

pub fn validate_format(f: &str) -> AppResult<()> {
    if FORMATS.contains(&f) {
        Ok(())
    } else {
        Err(AppError::bad(format!(
            "不支持的订阅格式：{f}（可选：{}）",
            FORMATS.join("/")
        )))
    }
}

/// 渲染订阅：resolve 条目 → 模板优先（仅格式匹配）→ 默认输出
pub async fn render_subscription(
    pool: &sqlx::SqlitePool,
    sub: &Subscription,
    format: &str,
) -> AppResult<Rendered> {
    validate_format(format)?;
    let refs = super::resolve::resolve_entries(pool, sub).await?;
    let nodes = super::resolve::load_export_nodes(pool, &refs).await?;

    if let Some(tid) = sub.template_id {
        let tpl: Option<SubTemplate> =
            sqlx::query_as("SELECT * FROM sub_templates WHERE id = ?")
                .bind(tid)
                .fetch_optional(pool)
                .await?;
        if let Some(tpl) = tpl {
            if tpl.format == format {
                let content = match format {
                    "clash" => render_clash_with_template(&tpl.content, &nodes)?,
                    "singbox" => render_singbox_with_template(&tpl.content, &nodes)?,
                    _ => unreachable!(),
                };
                let ct = if format == "singbox" {
                    "application/json; charset=utf-8"
                } else {
                    "text/yaml; charset=utf-8"
                };
                let ext = if format == "clash" { "yaml" } else { "json" };
                return Ok(Rendered {
                    content,
                    content_type: ct.to_string(),
                    ext: ext.to_string(),
                });
            }
        }
    }

    let (content, ct, ext) = match format {
        "clash" => super::clash::render(&nodes, &sub.name),
        "singbox" => super::singbox::render(&nodes, &sub.name),
        "json" => super::json::render(&nodes, &sub.name),
        "base64" => super::base64::render(&nodes, &sub.name),
        _ => unreachable!(),
    };
    Ok(Rendered {
        content,
        content_type: ct.to_string(),
        ext: ext.to_string(),
    })
}

// ================= 渲染 =================

/// 重名追加 " #2" / " #3"
pub fn dedup_names(nodes: &[ExportNode]) -> Vec<ExportNode> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    nodes
        .iter()
        .map(|n| {
            let c = counts.entry(n.name.clone()).or_insert(0);
            *c += 1;
            let mut n = n.clone();
            if *c > 1 {
                n.name = format!("{} #{}", n.name, c);
            }
            n
        })
        .collect()
}

/// 展开分组/选择器成员标记；结果按原顺序去重；为空则补 DIRECT
pub fn expand_members(items: &[String], nodes: &[ExportNode]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in items {
        if s == "@ALL" {
            out.extend(nodes.iter().map(|n| n.name.clone()));
        } else if let Some(t) = s.strip_prefix("@TAG:") {
            out.extend(
                nodes
                    .iter()
                    .filter(|n| n.tags.iter().any(|x| x == t))
                    .map(|n| n.name.clone()),
            );
        } else if let Some(g) = s.strip_prefix("@GROUP:") {
            out.extend(
                nodes
                    .iter()
                    .filter(|n| n.group.as_deref() == Some(g))
                    .map(|n| n.name.clone()),
            );
        } else if let Some(t) = s.strip_prefix("@TYPE:") {
            out.extend(
                nodes
                    .iter()
                    .filter(|n| n.entry_type == t)
                    .map(|n| n.name.clone()),
            );
        } else if let Some(r) = s.strip_prefix("@REGEX:") {
            if r.len() <= 200 {
                if let Ok(re) = regex::Regex::new(r) {
                    out.extend(
                        nodes
                            .iter()
                            .filter(|n| re.is_match(&n.name))
                            .map(|n| n.name.clone()),
                    );
                }
            }
        } else {
            out.push(s.clone());
        }
    }
    let mut seen = HashSet::new();
    out.retain(|x| seen.insert(x.clone()));
    if out.is_empty() {
        out.push("DIRECT".into());
    }
    out
}

fn yaml_str_val(s: &str) -> YamlValue {
    YamlValue::String(s.to_string())
}

/// Clash 节点字典（Value 版）：基础字段 + extra 合并（extra 优先），name 强制覆盖
pub fn clash_proxy_value(n: &ExportNode) -> YamlValue {
    let mut m = Mapping::new();
    m.insert(yaml_str_val("name"), yaml_str_val(&n.name));
    match n.kind.as_str() {
        "ss" => {
            m.insert(yaml_str_val("type"), yaml_str_val("ss"));
            m.insert(yaml_str_val("server"), yaml_str_val(&n.host));
            m.insert(yaml_str_val("port"), YamlValue::Number(n.port.into()));
            m.insert(yaml_str_val("cipher"), yaml_str_val("aes-256-gcm"));
            m.insert(
                yaml_str_val("password"),
                yaml_str_val(n.password.as_deref().unwrap_or("")),
            );
            m.insert(yaml_str_val("udp"), YamlValue::Bool(true));
        }
        "trojan" => {
            m.insert(yaml_str_val("type"), yaml_str_val("trojan"));
            m.insert(yaml_str_val("server"), yaml_str_val(&n.host));
            m.insert(yaml_str_val("port"), YamlValue::Number(n.port.into()));
            m.insert(
                yaml_str_val("password"),
                yaml_str_val(n.password.as_deref().unwrap_or("")),
            );
            m.insert(yaml_str_val("udp"), YamlValue::Bool(true));
        }
        "vless" => {
            m.insert(yaml_str_val("type"), yaml_str_val("vless"));
            m.insert(yaml_str_val("server"), yaml_str_val(&n.host));
            m.insert(yaml_str_val("port"), YamlValue::Number(n.port.into()));
            m.insert(
                yaml_str_val("uuid"),
                yaml_str_val(n.password.as_deref().unwrap_or("")),
            );
            m.insert(yaml_str_val("encryption"), yaml_str_val("none"));
            m.insert(yaml_str_val("udp"), YamlValue::Bool(true));
        }
        "vmess" => {
            m.insert(yaml_str_val("type"), yaml_str_val("vmess"));
            m.insert(yaml_str_val("server"), yaml_str_val(&n.host));
            m.insert(yaml_str_val("port"), YamlValue::Number(n.port.into()));
            m.insert(
                yaml_str_val("uuid"),
                yaml_str_val(n.password.as_deref().unwrap_or("")),
            );
            m.insert(yaml_str_val("alterId"), YamlValue::Number(0.into()));
            m.insert(yaml_str_val("cipher"), yaml_str_val("auto"));
            m.insert(yaml_str_val("udp"), YamlValue::Bool(true));
        }
        "socks5" => {
            m.insert(yaml_str_val("type"), yaml_str_val("socks5"));
            m.insert(yaml_str_val("server"), yaml_str_val(&n.host));
            m.insert(yaml_str_val("port"), YamlValue::Number(n.port.into()));
            if let Some(u) = &n.username {
                m.insert(yaml_str_val("username"), yaml_str_val(u));
            }
            if let Some(p) = &n.password {
                m.insert(yaml_str_val("password"), yaml_str_val(p));
            }
            m.insert(yaml_str_val("udp"), YamlValue::Bool(true));
        }
        _ => {
            m.insert(yaml_str_val("type"), yaml_str_val("http"));
            m.insert(yaml_str_val("server"), yaml_str_val(&n.host));
            m.insert(yaml_str_val("port"), YamlValue::Number(n.port.into()));
            if n.kind == "https" {
                m.insert(yaml_str_val("tls"), YamlValue::Bool(true));
            }
            if let Some(u) = &n.username {
                m.insert(yaml_str_val("username"), yaml_str_val(u));
            }
            if let Some(p) = &n.password {
                m.insert(yaml_str_val("password"), yaml_str_val(p));
            }
        }
    }
    if let Some(ex) = n.extra.as_ref().and_then(|v| v.as_object()) {
        for (k, v) in ex {
            if k == "name" {
                continue;
            }
            let yv = serde_json::from_str::<YamlValue>(&v.to_string())
                .unwrap_or(YamlValue::String(v.to_string()));
            m.insert(yaml_str_val(k), yv);
        }
    }
    YamlValue::Mapping(m)
}

pub fn render_clash_with_template(tpl: &str, nodes: &[ExportNode]) -> AppResult<String> {
    let mut root: YamlValue = serde_yaml::from_str(tpl)
        .map_err(|e| AppError::bad(&format!("模板解析失败：{e}")))?;
    let map = root
        .as_mapping_mut()
        .ok_or_else(|| AppError::bad("模板顶层必须是对象"))?;

    let nodes = dedup_names(nodes);
    let proxies: Vec<YamlValue> = nodes.iter().map(clash_proxy_value).collect();
    map.insert(yaml_str_val("proxies"), YamlValue::Sequence(proxies));

    if let Some(YamlValue::Sequence(groups)) = map.get_mut(&yaml_str_val("proxy-groups")) {
        for g in groups.iter_mut() {
            if let Some(YamlValue::Sequence(list)) = g.get_mut(&yaml_str_val("proxies")) {
                let items: Vec<String> =
                    list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
                let expanded = expand_members(&items, &nodes);
                *list = expanded.into_iter().map(|s| yaml_str_val(&s)).collect();
            }
        }
    }
    serde_yaml::to_string(&root).map_err(|e| AppError::internal(&e.to_string()))
}

/// Sing-box 节点出站（与 singbox.rs 的 render_outbound 对齐）
pub fn singbox_outbound_value(n: &ExportNode) -> JsonValue {
    let mut o = match n.kind.as_str() {
        "ss" => serde_json::json!({
            "type": "shadowsocks", "method": "aes-256-gcm",
            "password": n.password.as_deref().unwrap_or(""),
        }),
        "trojan" => serde_json::json!({
            "type": "trojan", "password": n.password.as_deref().unwrap_or(""),
        }),
        "vless" => serde_json::json!({
            "type": "vless", "uuid": n.password.as_deref().unwrap_or(""),
        }),
        "vmess" => serde_json::json!({
            "type": "vmess", "uuid": n.password.as_deref().unwrap_or(""),
            "alter_id": 0, "security": "auto",
        }),
        "socks5" => {
            let mut v = serde_json::json!({ "type": "socks", "version": "5" });
            if let Some(u) = &n.username {
                v["username"] = serde_json::json!(u);
            }
            if let Some(p) = &n.password {
                v["password"] = serde_json::json!(p);
            }
            v
        }
        _ => {
            let mut v = serde_json::json!({ "type": "http" });
            if n.kind == "https" {
                v["tls"] = serde_json::json!({ "enabled": true });
            }
            if let Some(u) = &n.username {
                v["username"] = serde_json::json!(u);
            }
            if let Some(p) = &n.password {
                v["password"] = serde_json::json!(p);
            }
            v
        }
    };
    if let Some(ex) = n.extra.as_ref().and_then(|v| v.as_object()) {
        for (k, v) in ex {
            if k == "tag" {
                continue;
            }
            o[k] = v.clone();
        }
    }
    o["tag"] = serde_json::json!(&n.name);
    o["server"] = serde_json::json!(&n.host);
    o["server_port"] = serde_json::json!(n.port);
    o
}

pub fn render_singbox_with_template(tpl: &str, nodes: &[ExportNode]) -> AppResult<String> {
    let mut root: JsonValue = serde_json::from_str(tpl)
        .map_err(|e| AppError::bad(&format!("模板解析失败：{e}")))?;
    let map = root
        .as_object_mut()
        .ok_or_else(|| AppError::bad("模板顶层必须是对象"))?;

    let nodes = dedup_names(nodes);
    // 展开 selector / urltest 的 outbounds 标记
    if let Some(JsonValue::Array(outbounds)) = map.get_mut("outbounds") {
        for ob in outbounds.iter_mut() {
            let is_group = ob
                .get("type")
                .and_then(|t| t.as_str())
                .map(|t| t == "selector" || t == "urltest")
                .unwrap_or(false);
            if !is_group {
                continue;
            }
            if let Some(JsonValue::Array(list)) = ob.get_mut("outbounds") {
                let items: Vec<String> =
                    list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
                let expanded = expand_members(&items, &nodes);
                *list = expanded.into_iter().map(JsonValue::String).collect();
            }
        }
        // 节点写入同一个 outbounds 数组（tag 去重）
        let mut tags: HashSet<String> = outbounds
            .iter()
            .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(str::to_string))
            .collect();
        for n in &nodes {
            if tags.insert(n.name.clone()) {
                outbounds.push(singbox_outbound_value(n));
            }
        }
    }
    serde_json::to_string_pretty(&root).map_err(|e| AppError::internal(&e.to_string()))
}

// ================= 校验（§12.4） =================

/// 收集模板中出现的所有 @REGEX: 表达式
fn collect_regexes(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(i) = rest.find("@REGEX:") {
        let after = &rest[i + 7..];
        let end = after
            .find(|c: char| c == '"' || c == '\'' || c == ',' || c == ']' || c == '\n' || c == ' ')
            .unwrap_or(after.len());
        out.push(after[..end].to_string());
        rest = &after[end..];
    }
    out
}

/// 返回错误列表；为空表示通过
pub fn validate_template(content: &str, format: &str) -> Vec<String> {
    let mut errs: Vec<String> = Vec::new();
    if content.len() > 256 * 1024 {
        errs.push("模板大小超过 256 KB".to_string());
        return errs;
    }
    if format != "clash" && format != "singbox" {
        errs.push("format 只能是 clash 或 singbox".to_string());
        return errs;
    }
    for re_str in collect_regexes(content) {
        if re_str.len() > 200 {
            errs.push(format!("@REGEX 表达式超过 200 字符：{re_str}"));
        } else if regex::Regex::new(&re_str).is_err() {
            errs.push(format!("@REGEX 无法编译：{re_str}"));
        }
    }

    if format == "clash" {
        let root: Result<YamlValue, _> = serde_yaml::from_str(content);
        let root = match root {
            Ok(v) => v,
            Err(e) => {
                errs.push(format!("YAML 解析失败：{e}"));
                return errs;
            }
        };
        let map = match root.as_mapping() {
            Some(m) => m,
            None => {
                errs.push("模板顶层必须是对象".to_string());
                return errs;
            }
        };
        if map.contains_key(&yaml_str_val("proxies")) {
            errs.push("模板里禁止自带 proxies（系统会自动写入，删掉该字段）".to_string());
        }
        let mut group_names: HashSet<String> = HashSet::new();
        let mut dup: HashSet<String> = HashSet::new();
        if let Some(groups) = map.get(&yaml_str_val("proxy-groups")) {
            match groups.as_sequence() {
                None => errs.push("proxy-groups 必须是数组".to_string()),
                Some(seq) => {
                    for (i, g) in seq.iter().enumerate() {
                        let gm = match g.as_mapping() {
                            Some(m) => m,
                            None => {
                                errs.push(format!("proxy-groups[{i}] 必须是对象"));
                                continue;
                            }
                        };
                        let name = gm
                            .get(&yaml_str_val("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let typ = gm
                            .get(&yaml_str_val("type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if name.is_empty() || typ.is_empty() {
                            errs.push(format!("proxy-groups[{i}] 缺少 name 或 type"));
                            continue;
                        }
                        if !group_names.insert(name.to_string()) {
                            dup.insert(name.to_string());
                        }
                        if let Some(members) = gm.get(&yaml_str_val("proxies")) {
                            match members.as_sequence() {
                                None => errs.push(format!("分组 {name} 的 proxies 必须是数组")),
                                Some(list) => {
                                    for m in list {
                                        if let Some(s) = m.as_str() {
                                            if !s.starts_with('@')
                                                && s != "DIRECT"
                                                && s != "REJECT"
                                            {
                                                // 稍后统一检查引用是否存在
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for d in &dup {
            errs.push(format!("分组名重复：{d}"));
        }
        // 引用检查：分组成员 / rules 引用的目标
        let valid_targets: HashSet<&str> =
            group_names.iter().map(String::as_str).collect();
        let check_ref = |s: &str, errs: &mut Vec<String>, ctx: &str| {
            if s.starts_with('@') || s == "DIRECT" || s == "REJECT" {
                return;
            }
            if !valid_targets.contains(s) {
                errs.push(format!("{ctx} 引用了不存在的分组 {s}"));
            }
        };
        if let Some(seq) = map
            .get(&yaml_str_val("proxy-groups"))
            .and_then(|v| v.as_sequence())
        {
            for g in seq {
                if let (Some(name), Some(list)) = (
                    g.get(&yaml_str_val("name")).and_then(|v| v.as_str()),
                    g.get(&yaml_str_val("proxies")).and_then(|v| v.as_sequence()),
                ) {
                    for m in list {
                        if let Some(s) = m.as_str() {
                            check_ref(s, &mut errs, &format!("分组 {name}"));
                        }
                    }
                }
            }
        }
        if let Some(rules) = map.get(&yaml_str_val("rules")).and_then(|v| v.as_sequence())
        {
            for r in rules {
                if let Some(s) = r.as_str() {
                    if let Some(target) = s.rsplit(',').next() {
                        let target = target.trim();
                        if !target.is_empty() {
                            check_ref(target, &mut errs, "rules");
                        }
                    }
                }
            }
        }
    } else {
        let root: Result<JsonValue, _> = serde_json::from_str(content);
        let root = match root {
            Ok(v) => v,
            Err(e) => {
                errs.push(format!("JSON 解析失败：{e}"));
                return errs;
            }
        };
        let map = match root.as_object() {
            Some(m) => m,
            None => {
                errs.push("模板顶层必须是对象".to_string());
                return errs;
            }
        };
        if let Some(JsonValue::Array(outbounds)) = map.get("outbounds") {
            let mut tags: HashSet<String> = HashSet::new();
            let mut dup: HashSet<String> = HashSet::new();
            for (i, ob) in outbounds.iter().enumerate() {
                let typ = ob.get("type").and_then(|t| t.as_str()).unwrap_or("");
                let tag = ob.get("tag").and_then(|t| t.as_str()).unwrap_or("");
                if matches!(
                    typ,
                    "shadowsocks" | "trojan" | "vless" | "vmess" | "socks" | "http" | "hysteria2" | "tuic" | "wireguard"
                ) {
                    errs.push(format!(
                        "outbounds[{i}] 是节点类型（{typ}），模板里禁止自带节点（系统会自动写入）"
                    ));
                }
                if !tag.is_empty() && !tags.insert(tag.to_string()) {
                    dup.insert(tag.to_string());
                }
            }
            for d in &dup {
                errs.push(format!("outbound tag 重复：{d}"));
            }
        }
    }
    errs
}

/// 预览用假节点
pub fn sample_nodes() -> Vec<ExportNode> {
    vec![
        ExportNode {
            name: "香港-01".into(),
            kind: "ss".into(),
            host: "1.2.3.4".into(),
            port: 8388,
            username: None,
            password: Some("pass123".into()),
            extra: None,
            entry_type: "proxy".into(),
            group: Some("家宽".into()),
            tags: vec!["香港".into()],
        },
        ExportNode {
            name: "美国-01".into(),
            kind: "vmess".into(),
            host: "5.6.7.8".into(),
            port: 443,
            username: None,
            password: Some("uuid-xxx".into()),
            extra: None,
            entry_type: "proxy".into(),
            group: None,
            tags: vec!["美国".into()],
        },
        ExportNode {
            name: "转发-游戏".into(),
            kind: "tcp".into(),
            host: "9.9.9.9".into(),
            port: 25565,
            username: None,
            password: None,
            extra: None,
            entry_type: "forward".into(),
            group: Some("家宽".into()),
            tags: vec![],
        },
    ]
}

/// 用假节点渲染预览
pub fn preview_render(content: &str, format: &str) -> AppResult<String> {
    let nodes = dedup_names(&sample_nodes());
    match format {
        "clash" => render_clash_with_template(content, &nodes),
        "singbox" => render_singbox_with_template(content, &nodes),
        _ => Err(AppError::bad("format 只能是 clash 或 singbox")),
    }
}
