//! 订阅导出 —— 范围解析（文档 §9.2）与条目 → ExportNode（文档 §9.1）。
//!
//! 解析顺序：
//! 1. 基础集合：all → 三张表全部启用条目；single/custom → subscription_entries；
//!    rule → include 规则并集 + subscription_entries 例外条目；
//! 2. 减去 exclude 规则命中的条目（custom 与 rule 都支持）；
//! 3. 过滤掉 enabled = 0 的条目；
//! 4. 按分组排序 → 条目 id 排序（custom 按 sort_order）。

use sqlx::SqlitePool;

use crate::error::{AppError, AppResult};

use crate::models::{EntryRef, ExportNode, SubRule, Subscription};
use crate::util::table_of;

/// 计算订阅实际命中的条目引用
pub async fn resolve_entries(pool: &SqlitePool, sub: &Subscription) -> AppResult<Vec<EntryRef>> {
    let mut set: std::collections::BTreeSet<(String, i64)> = Default::default();
    // custom 的手工条目需要 sort_order，单独记
    let mut custom_order: std::collections::HashMap<(String, i64), i64> =
        std::collections::HashMap::new();

    if sub.scope == "all" {
        for t in ["proxy", "forward", "tunnel"] {
            let table = table_of(t)?;
            let sql = format!("SELECT id FROM {table} WHERE enabled = 1");
            for (id,) in sqlx::query_as::<_, (i64,)>(&sql).fetch_all(pool).await? {
                set.insert((t.to_string(), id));
            }
        }
    } else {
        for e in sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT entry_type, entry_id, sort_order FROM subscription_entries WHERE subscription_id = ?",
        )
        .bind(sub.id)
        .fetch_all(pool)
        .await?
        {
            set.insert((e.0.clone(), e.1));
            custom_order.insert((e.0, e.1), e.2);
        }
        let rules: Vec<SubRule> =
            sqlx::query_as("SELECT * FROM subscription_rules WHERE subscription_id = ?")
                .bind(sub.id)
                .fetch_all(pool)
                .await?;
        if sub.scope == "rule" {
            for r in rules.iter().filter(|r| r.mode == "include") {
                for k in match_rule(pool, r).await? {
                    set.insert(k);
                }
            }
        } else if sub.scope != "single" && sub.scope != "custom" {
            return Err(AppError::bad(format!("未知订阅范围：{}", sub.scope)));
        }
        for r in rules.iter().filter(|r| r.mode == "exclude") {
            for k in match_rule(pool, r).await? {
                set.remove(&k);
                custom_order.remove(&k);
            }
        }
    }

    // 过滤 enabled = 0 的条目
    let mut out: Vec<EntryRef> = Vec::new();
    for (t, id) in set {
        let table = table_of(&t)?;
        let sql = format!("SELECT enabled FROM {table} WHERE id = ?");
        if let Some((en,)) =
            sqlx::query_as::<_, (i64,)>(&sql).bind(id).fetch_optional(pool).await?
        {
            if en == 1 {
                out.push(EntryRef { entry_type: t, entry_id: id });
            }
        }
    }

    // 排序：custom 按 sort_order；其余按分组排序 → 条目 id
    if sub.scope == "custom" {
        out.sort_by_key(|e| {
            (
                custom_order
                    .get(&(e.entry_type.clone(), e.entry_id))
                    .copied()
                    .unwrap_or(i64::MAX),
                e.entry_id,
            )
        });
    } else {
        // 分组排序：(group_sort_order, group_id) → id
        let mut keyed: Vec<((i64, i64, i64), EntryRef)> = Vec::new();
        for e in out {
            let table = table_of(&e.entry_type)?;
            let g: Option<(i64,)> = sqlx::query_as(&format!(
                "SELECT group_id FROM {table} WHERE id = ?"
            ))
            .bind(e.entry_id)
            .fetch_optional(pool)
            .await?;
            let gid = g.map(|x| x.0).unwrap_or(0);
            let gsort: Option<(i64,)> =
                sqlx::query_as("SELECT sort_order FROM entry_groups WHERE id = ?")
                    .bind(gid)
                    .fetch_optional(pool)
                    .await?;
            let so = gsort.map(|x| x.0).unwrap_or(i64::MAX);
            keyed.push(((so, gid, e.entry_id), e));
        }
        keyed.sort_by_key(|(k, _)| *k);
        out = keyed.into_iter().map(|(_, e)| e).collect();
    }
    Ok(out)
}

/// 规则命中：kind = group | tag | node | type
async fn match_rule(pool: &SqlitePool, r: &SubRule) -> AppResult<Vec<(String, i64)>> {
    let mut out = Vec::new();
    match r.kind.as_str() {
        "group" => {
            let gid: i64 = r
                .value
                .parse()
                .map_err(|_| AppError::bad("规则 value 不是合法分组 id"))?;
            for t in ["proxy", "forward", "tunnel"] {
                let table = table_of(t)?;
                let sql = format!("SELECT id FROM {table} WHERE group_id = ?");
                for (id,) in sqlx::query_as::<_, (i64,)>(&sql).bind(gid).fetch_all(pool).await? {
                    out.push((t.to_string(), id));
                }
            }
        }
        "tag" => {
            let tid: i64 = r
                .value
                .parse()
                .map_err(|_| AppError::bad("规则 value 不是合法标签 id"))?;
            for (et, eid) in sqlx::query_as::<_, (String, i64)>(
                "SELECT entry_type, entry_id FROM entry_tags WHERE tag_id = ?",
            )
            .bind(tid)
            .fetch_all(pool)
            .await?
            {
                if table_of(&et).is_ok() {
                    out.push((et, eid));
                }
            }
        }
        "node" => {
            let nid: i64 = r
                .value
                .parse()
                .map_err(|_| AppError::bad("规则 value 不是合法节点 id"))?;
            for t in ["proxy", "forward", "tunnel"] {
                let table = table_of(t)?;
                let sql = format!("SELECT id FROM {table} WHERE node_id = ?");
                for (id,) in sqlx::query_as::<_, (i64,)>(&sql).bind(nid).fetch_all(pool).await? {
                    out.push((t.to_string(), id));
                }
            }
        }
        "type" => {
            let t = r.value.as_str();
            table_of(t)?;
            let table = table_of(t)?;
            let sql = format!("SELECT id FROM {table}");
            for (id,) in sqlx::query_as::<_, (i64,)>(&sql).fetch_all(pool).await? {
                out.push((t.to_string(), id));
            }
        }
        other => return Err(AppError::bad(format!("未知规则类型：{other}"))),
    }
    Ok(out)
}

/// 条目 → ExportNode（文档 §9.1）；host 为空则跳过（返回 None）
pub async fn load_export_nodes(
    pool: &SqlitePool,
    refs: &[EntryRef],
) -> AppResult<Vec<ExportNode>> {
    let mut out = Vec::new();
    for r in refs {
        if let Some(n) = build_export_node(pool, &r.entry_type, r.entry_id).await? {
            out.push(n);
        }
    }
    Ok(out)
}

async fn build_export_node(
    pool: &SqlitePool,
    entry_type: &str,
    entry_id: i64,
) -> AppResult<Option<ExportNode>> {
    let table = table_of(entry_type)?;
    let row: Option<(i64, String, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT node_id, name, group_id FROM {table} WHERE id = ? AND enabled = 1"
    ))
    .bind(entry_id)
    .fetch_optional(pool)
    .await?;
    let (node_id, name, group_id) = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let public_host: Option<String> =
        sqlx::query_scalar("SELECT public_host FROM nodes WHERE id = ?")
            .bind(node_id)
            .fetch_optional(pool)
            .await?
            .flatten();

    let group: Option<String> = match group_id {
        Some(gid) if gid != 0 => {
            sqlx::query_scalar("SELECT name FROM entry_groups WHERE id = ?")
                .bind(gid)
                .fetch_optional(pool)
                .await?
        }
        _ => None,
    };
    let tags: Vec<String> = sqlx::query_scalar(
        "SELECT t.name FROM tags t JOIN entry_tags et ON et.tag_id = t.id
         WHERE et.entry_type = ? AND et.entry_id = ? ORDER BY t.name",
    )
    .bind(entry_type)
    .bind(entry_id)
    .fetch_all(pool)
    .await?;

    let (kind, host, port, username, password, extra) = match entry_type {
        "proxy" => {
            let p: Option<ProxyLite> = sqlx::query_as(
                "SELECT upstream_type, upstream_addr, auth_user, auth_pass,
                        export_host, export_port, extra
                 FROM proxy_rules WHERE id = ?",
            )
            .bind(entry_id)
            .fetch_optional(pool)
            .await?;
            let p = match p {
                Some(p) => p,
                None => return Ok(None),
            };
            let (uh, up) = split_host_port(&p.upstream_addr).unwrap_or_default();
            let host = p
                .export_host
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(uh);
            let port = p.export_port.unwrap_or(up as i64) as u16;
            let mut extra = p
                .extra
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
            if extra.is_none() {
                extra = Some(serde_json::json!({}));
            }
            (
                p.upstream_type,
                host,
                port,
                p.auth_user,
                p.auth_pass,
                extra,
            )
        }
        "forward" => {
            let f: Option<ForwardLite> = sqlx::query_as(
                "SELECT listen_port, protocol, export_host, export_port, extra
                 FROM port_forwards WHERE id = ?",
            )
            .bind(entry_id)
            .fetch_optional(pool)
            .await?;
            let f = match f {
                Some(f) => f,
                None => return Ok(None),
            };
            let host = f
                .export_host
                .filter(|s| !s.trim().is_empty())
                .or_else(|| public_host.clone().filter(|s| !s.trim().is_empty()))
                .unwrap_or_default();
            let port = f.export_port.unwrap_or(f.listen_port) as u16;
            let extra = f
                .extra
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .or_else(|| Some(serde_json::json!({ "protocol": f.protocol })));
            ("tcp".to_string(), host, port, None, None, extra)
        }
        "tunnel" => {
            let t: Option<TunnelLite> = sqlx::query_as(
                "SELECT tunnel_type, local_addr, export_host, export_port, extra
                 FROM tunnels WHERE id = ?",
            )
            .bind(entry_id)
            .fetch_optional(pool)
            .await?;
            let t = match t {
                Some(t) => t,
                None => return Ok(None),
            };
            let (_, lp) = split_host_port(&t.local_addr).unwrap_or_default();
            let host = t
                .export_host
                .filter(|s| !s.trim().is_empty())
                .or_else(|| public_host.clone().filter(|s| !s.trim().is_empty()))
                .unwrap_or_default();
            let port = t.export_port.unwrap_or(lp as i64) as u16;
            let extra = t
                .extra
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .or_else(|| Some(serde_json::json!({ "tunnel_type": t.tunnel_type })));
            (format!("tunnel/{}", t.tunnel_type), host, port, None, None, extra)
        }
        _ => return Ok(None),
    };

    if host.trim().is_empty() || port == 0 {
        return Ok(None); // host 为空则跳过
    }
    Ok(Some(ExportNode {
        name,
        kind,
        host,
        port,
        username,
        password,
        extra,
        entry_type: entry_type.to_string(),
        group,
        tags,
    }))
}

#[derive(sqlx::FromRow)]
struct ProxyLite {
    upstream_type: String,
    upstream_addr: String,
    auth_user: Option<String>,
    auth_pass: Option<String>,
    export_host: Option<String>,
    export_port: Option<i64>,
    extra: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ForwardLite {
    listen_port: i64,
    protocol: String,
    export_host: Option<String>,
    export_port: Option<i64>,
    extra: Option<String>,
}

#[derive(sqlx::FromRow)]
struct TunnelLite {
    tunnel_type: String,
    local_addr: String,
    export_host: Option<String>,
    export_port: Option<i64>,
    extra: Option<String>,
}

pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    if let Some(idx) = addr.rfind(':') {
        let (h, p) = addr.split_at(idx);
        if let Ok(port) = p[1..].parse::<u16>() {
            let h = h.trim_matches(|c| c == '[' || c == ']').to_string();
            if !h.is_empty() {
                return Some((h, port));
            }
        }
    }
    None
}
