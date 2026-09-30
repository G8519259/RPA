//! P12 —— 告警服务
//!
//! 结构（§14.1）：事件源调用 [`emit`] 写入 `alert_events`（status=pending，规则匹配 + 冷却去重）
//! → [`dispatcher_loop`] 每 10 秒取到期事件，按规则绑定的渠道发送，失败指数退避。

pub mod crypto;
pub mod dispatcher;
pub mod email;
pub mod emit;
pub mod telegram;
pub mod webhook;

pub use dispatcher::dispatcher_loop;
pub use emit::emit;

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// 告警草稿（§14.4）：业务代码只构造它，`emit` 负责按规则匹配 + 冷却去重后写库。
#[derive(Debug, Clone)]
pub struct AlertDraft {
    pub event_type: &'static str,
    pub dedup_key: String,
    pub severity: &'static str, // info | warning | critical
    pub title: String,
    pub body: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertRule {
    pub id: i64,
    pub name: String,
    pub event_type: String,
    pub params: String,      // JSON 阈值参数
    pub channel_ids: String, // JSON 数组
    pub cooldown_secs: i64,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertChannel {
    pub id: i64,
    pub name: String,
    pub kind: String, // webhook | telegram | email
    pub config: String,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertEvent {
    pub id: i64,
    pub rule_id: Option<i64>,
    pub event_type: String,
    pub dedup_key: String,
    pub severity: String,
    pub title: String,
    pub body: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,
    pub status: String, // pending | sent | failed
    pub attempts: i64,
    pub next_retry_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub sent_at: Option<String>,
}

/// UTC 时间字符串（"YYYY-MM-DD HH:MM:SS"）→ 本地时区显示（默认 +8）
pub fn local_time_str(utc: &str, tz_offset_hours: i64) -> String {
    match NaiveDateTime::parse_from_str(utc.trim(), "%Y-%m-%d %H:%M:%S") {
        Ok(dt) => (dt + chrono::Duration::hours(tz_offset_hours))
            .format("%Y-%m-%d %H:%M")
            .to_string(),
        Err(_) => utc.to_string(),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct DaysBefore {
    #[serde(default)]
    pub days_before: Vec<i64>,
}

impl DaysBefore {
    /// 取"大于等于 days_left 的最小阈值"（§14.5：只发最贴近当前剩余天数的一条）
    pub fn pick(&self, days_left: i64) -> Option<i64> {
        let mut ds = self.days_before.clone();
        ds.sort_unstable();
        ds.into_iter().find(|d| *d >= days_left)
    }
}

/// 剩余天数：ceil((expires_at - now) / 1 天)；已过期返回 None
pub fn days_left(expires_at_utc: &str, now: NaiveDateTime) -> Option<i64> {
    let exp = NaiveDateTime::parse_from_str(expires_at_utc.trim(), "%Y-%m-%d %H:%M:%S").ok()?;
    let secs = (exp - now).num_seconds();
    if secs <= 0 {
        return None;
    }
    Some((secs + 86399) / 86400)
}

fn reason_hash(s: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(s.as_bytes());
    hex::encode(&h.finalize())[..16].to_string()
}

pub fn fmt_bytes(v: i64) -> String {
    const U: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut f = v.max(0) as f64;
    let mut i = 0;
    while f >= 1024.0 && i + 1 < U.len() {
        f /= 1024.0;
        i += 1;
    }
    format!("{f:.1} {}", U[i])
}

impl AlertDraft {
    pub fn node_offline(
        node_id: i64,
        name: &str,
        last_hb: &str,
        offline_secs: i64,
        tz: i64,
        base: &str,
    ) -> Self {
        Self {
            event_type: "node_offline",
            dedup_key: format!("node_offline:{node_id}:{last_hb}"),
            severity: "critical",
            title: format!("🔴 节点离线：{name}"),
            body: format!(
                "已超过 {offline_secs} 秒未收到心跳。\n最后心跳：{}（本地）\n后台：{base}/admin/nodes",
                local_time_str(last_hb, tz)
            ),
            resource_type: Some("node".to_string()),
            resource_id: Some(node_id),
        }
    }

    pub fn node_online(node_id: i64, name: &str, base: &str) -> Self {
        Self {
            event_type: "node_online",
            dedup_key: format!(
                "node_online:{node_id}:{}",
                chrono::Utc::now().format("%Y-%m-%dT%H")
            ),
            severity: "info",
            title: format!("🟢 节点恢复：{name}"),
            body: format!("节点 {name} 已重新上线。\n后台：{base}/admin/nodes"),
            resource_type: Some("node".to_string()),
            resource_id: Some(node_id),
        }
    }

    pub fn sub_expired(id: i64, name: &str, base: &str) -> Self {
        Self {
            event_type: "sub_expired",
            dedup_key: format!("sub_expired:{id}"),
            severity: "warning",
            title: format!("🟡 订阅已到期并停用：{name}"),
            body: format!(
                "订阅「{name}」已到期，已自动停用。\n后台：{base}/admin/subscriptions/{id}"
            ),
            resource_type: Some("subscription".to_string()),
            resource_id: Some(id),
        }
    }

    pub fn sub_expiring(
        id: i64,
        name: &str,
        days: i64,
        expires_at: &str,
        tz: i64,
        base: &str,
    ) -> Self {
        Self {
            event_type: "sub_expiring",
            dedup_key: format!("sub_expiring:{id}:{days}:{expires_at}"),
            severity: "warning",
            title: format!("🟡 订阅即将到期：{name}"),
            body: format!(
                "剩余 {days} 天，到期时间 {}（本地）\n后台：{base}/admin/subscriptions/{id}",
                local_time_str(expires_at, tz)
            ),
            resource_type: Some("subscription".to_string()),
            resource_id: Some(id),
        }
    }

    pub fn entry_expired(
        entry_type: &str,
        id: i64,
        name: &str,
        expires_at: &str,
        base: &str,
    ) -> Self {
        Self {
            event_type: "entry_expired",
            dedup_key: format!("entry_expired:{entry_type}:{id}:{expires_at}"),
            severity: "warning",
            title: format!("🟡 条目已到期自动停用：{name}"),
            body: format!(
                "{entry_type}/{id}「{name}」已到期，已自动停用。\n后台：{base}/admin"
            ),
            resource_type: Some(entry_type.to_string()),
            resource_id: Some(id),
        }
    }

    pub fn entry_expiring(
        entry_type: &str,
        id: i64,
        name: &str,
        days: i64,
        expires_at: &str,
        tz: i64,
        base: &str,
    ) -> Self {
        Self {
            event_type: "entry_expiring",
            dedup_key: format!("entry_expiring:{entry_type}:{id}:{days}:{expires_at}"),
            severity: "warning",
            title: format!("🟡 条目即将到期：{name}"),
            body: format!(
                "{entry_type}/{id}「{name}」剩余 {days} 天，到期时间 {}（本地）\n后台：{base}/admin",
                local_time_str(expires_at, tz)
            ),
            resource_type: Some(entry_type.to_string()),
            resource_id: Some(id),
        }
    }

    pub fn quota_warn(
        entry_type: &str,
        id: i64,
        name: &str,
        period_start: &str,
        pct: i64,
        used: i64,
        quota: i64,
        base: &str,
    ) -> Self {
        Self {
            event_type: "quota_warn",
            // 同一周期同一阈值只发一次（§14.5）
            dedup_key: format!("quota_warn:{entry_type}:{id}:{period_start}:{pct}"),
            severity: "warning",
            title: format!("🟠 流量预警：{name}"),
            body: format!(
                "已使用 {} / {}（{pct}%）\n后台：{base}/admin/quotas",
                fmt_bytes(used),
                fmt_bytes(quota)
            ),
            resource_type: Some(entry_type.to_string()),
            resource_id: Some(id),
        }
    }

    pub fn quota_exceeded(
        entry_type: &str,
        id: i64,
        name: &str,
        period_start: &str,
        tz: i64,
        base: &str,
    ) -> Self {
        Self {
            event_type: "quota_exceeded",
            dedup_key: format!("quota_exceeded:{entry_type}:{id}:{period_start}"),
            severity: "critical",
            title: format!("🔴 流量用尽，已自动停用：{name}"),
            body: format!(
                "{entry_type}/{id}「{name}」流量已用尽，已自动停用。\n下个周期重置：{}（本地）\n后台：{base}/admin/quotas",
                local_time_str(period_start, tz)
            ),
            resource_type: Some(entry_type.to_string()),
            resource_id: Some(id),
        }
    }

    pub fn runtime_error(
        entry_type: &str,
        id: i64,
        name: &str,
        reason: &str,
        node: Option<&str>,
        base: &str,
    ) -> Self {
        let where_ = node.map(|n| format!("（节点 {n}）")).unwrap_or_default();
        Self {
            event_type: "runtime_error",
            dedup_key: format!(
                "runtime_error:{entry_type}:{id}:{}",
                reason_hash(reason)
            ),
            severity: "warning",
            title: format!("🟡 条目运行异常{where_}：{name}"),
            body: format!(
                "{entry_type}/{id}「{name}」运行异常：{reason}\n后台：{base}/admin/monitor/rules"
            ),
            resource_type: Some(entry_type.to_string()),
            resource_id: Some(id),
        }
    }

    pub fn login_fail_burst(ip: &str, fails: i64, lock_minutes: i64, base: &str) -> Self {
        Self {
            event_type: "login_fail_burst",
            dedup_key: format!(
                "login_fail_burst:{ip}:{}",
                chrono::Utc::now().format("%Y-%m-%dT%H")
            ),
            severity: "warning",
            title: format!("🟡 登录失败激增：{ip}"),
            body: format!(
                "IP {ip} 短时间内登录失败 {fails} 次，已锁定 {lock_minutes} 分钟。\n后台：{base}/admin/logs/audit"
            ),
            resource_type: None,
            resource_id: None,
        }
    }

    pub fn sub_ip_limit(sub_id: i64, name: &str, max_ips: i64, base: &str) -> Self {
        Self {
            event_type: "sub_ip_limit",
            dedup_key: format!(
                "sub_ip_limit:{sub_id}:{}",
                chrono::Utc::now().format("%Y-%m-%dT%H")
            ),
            severity: "info",
            title: format!("ℹ️ 订阅触发 IP 限制：{name}"),
            body: format!(
                "订阅「{name}」同时在线 IP 数达到上限（{max_ips}），已有请求被拒绝。\n后台：{base}/admin/subscriptions/{sub_id}"
            ),
            resource_type: Some("subscription".to_string()),
            resource_id: Some(sub_id),
        }
    }

    pub fn test_channel(name: &str, kind: &str, base: &str) -> Self {
        let nonce = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        Self {
            event_type: "__test__",
            dedup_key: format!("__test__:{nonce}"),
            severity: "info",
            title: format!("✅ 告警渠道测试：{name}"),
            body: format!(
                "这是一条来自 RustProxyAdmin 的测试告警（渠道类型：{kind}）。\n后台：{base}/admin/alerts"
            ),
            resource_type: None,
            resource_id: None,
        }
    }
}

/// 规则参数里读 days_before（无/非法时返回默认 [7,3,1]）
pub fn days_before_of(params_json: &str) -> Vec<i64> {
    serde_json::from_str::<DaysBefore>(params_json)
        .map(|d| d.days_before)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![7, 3, 1])
}

/// 规则参数里读 offline_secs（默认 90）
pub fn offline_secs_of(params_json: &str) -> i64 {
    #[derive(Deserialize)]
    struct P {
        #[serde(default)]
        offline_secs: i64,
    }
    match serde_json::from_str::<P>(params_json) {
        Ok(p) if p.offline_secs > 0 => p.offline_secs,
        _ => 90,
    }
}
