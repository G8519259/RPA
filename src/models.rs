use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// ============ 统一 API 响应 ============
#[derive(Serialize)]
pub struct ApiResp<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> ApiResp<T> {
    pub fn ok(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
}

#[derive(Serialize)]
pub struct Page<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============ 用户 / 会话 / 设置 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub csrf_token: String,
    pub ip_addr: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

// ============ 服务器节点 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Node {
    pub id: i64,
    pub name: String,
    pub is_local: i64,
    pub addr: Option<String>,
    pub public_host: Option<String>,
    #[serde(skip_serializing)]
    pub api_token: String,
    pub enabled: i64,
    pub meta: Option<String>,
    pub version: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub last_load: Option<String>,
    pub online_state: String,
    pub created_at: String,
    pub updated_at: String,
}

// ============ 分组 / 标签 / 输出模板 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct EntryGroup {
    pub id: i64,
    pub name: String,
    pub color: String,
    pub description: Option<String>,
    pub sort_order: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Tag {
    pub id: i64,
    pub name: String,
    pub color: String,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SubTemplate {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub content: String,
    pub is_builtin: i64,
    pub created_at: String,
    pub updated_at: String,
}

// ============ 导入记录 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ImportRecord {
    pub id: i64,
    pub user_id: Option<i64>,
    pub source_url: Option<String>,
    pub source_type: String,
    pub target_node_id: Option<i64>,
    pub parsed_count: i64,
    pub imported_count: i64,
    pub created_at: String,
}

// ============ 三类条目 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ProxyRule {
    pub id: i64,
    pub node_id: i64,
    pub name: String,
    pub listen_addr: Option<String>,
    pub upstream_type: String,
    pub upstream_addr: String,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub source_import_id: Option<i64>,
    pub group_id: Option<i64>,
    pub expires_at: Option<String>,
    pub enabled: i64,
    pub disabled_reason: Option<String>,
    pub remark: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PortForward {
    pub id: i64,
    pub node_id: i64,
    pub name: String,
    pub listen_ip: String,
    pub listen_port: i64,
    pub target_ip: String,
    pub target_port: i64,
    pub protocol: String,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub source_import_id: Option<i64>,
    pub group_id: Option<i64>,
    pub expires_at: Option<String>,
    pub enabled: i64,
    pub disabled_reason: Option<String>,
    pub remark: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Tunnel {
    pub id: i64,
    pub node_id: i64,
    pub name: String,
    pub tunnel_type: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub token: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub source_import_id: Option<i64>,
    pub group_id: Option<i64>,
    pub expires_at: Option<String>,
    pub enabled: i64,
    pub disabled_reason: Option<String>,
    pub remark: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ============ 订阅 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Subscription {
    pub id: i64,
    pub user_id: Option<i64>,
    pub token: String,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub default_format: String,
    pub template_id: Option<i64>,
    pub enabled: i64,
    pub disabled_reason: Option<String>,
    pub expires_at: Option<String>,
    pub max_ips: Option<i64>,
    pub access_count: i64,
    pub last_access_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SubscriptionEntry {
    pub id: i64,
    pub subscription_id: i64,
    pub entry_type: String,
    pub entry_id: i64,
    pub sort_order: i64,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SubRule {
    pub id: i64,
    pub subscription_id: i64,
    pub kind: String,
    pub value: String,
    pub mode: String,
}

// ============ 配额 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct QuotaRow {
    pub id: i64,
    pub entry_type: String,
    pub entry_id: i64,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub period: String,
    pub reset_day: i64,
    pub period_start: String,
    pub warn_level: i64,
    pub status: String,
    pub exceeded_at: Option<String>,
}

// ============ 日志 / 统计 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLog {
    pub id: i64,
    pub actor_user_id: Option<i64>,
    pub actor_name: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<i64>,
    pub node_id: Option<i64>,
    pub detail: Option<String>,
    pub ip_addr: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AccessLog {
    pub id: i64,
    pub node_id: i64,
    pub rule_type: String,
    pub rule_id: i64,
    pub client_ip: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub status: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SubscriptionLog {
    pub id: i64,
    pub subscription_id: i64,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub format: Option<String>,
    pub result: String,
    pub accessed_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MetricsSnapshot {
    pub id: i64,
    pub node_id: i64,
    pub collected_at: String,
    pub cpu: Option<f64>,
    pub mem: Option<f64>,
    pub conns: Option<i64>,
    pub net_up_bps: Option<i64>,
    pub net_down_bps: Option<i64>,
}

// ============ 告警 ============
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertChannel {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub config: String,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertRule {
    pub id: i64,
    pub name: String,
    pub event_type: String,
    pub params: String,
    pub channel_ids: String,
    pub cooldown_secs: i64,
    pub enabled: i64,
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
    pub status: String,
    pub attempts: i64,
    pub next_retry_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub sent_at: Option<String>,
}

// ============ 三类条目统一转换后的可导出节点 ============
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportNode {
    pub name: String,
    pub kind: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub extra: Option<serde_json::Value>,
    pub entry_type: String,
    pub group: Option<String>,
    pub tags: Vec<String>,
}

// ============ 请求体结构 ============
#[derive(Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}
#[derive(Deserialize)]
pub struct ChangePasswordReq {
    pub old_password: String,
    pub new_password: String,
}
#[derive(Deserialize)]
pub struct ChangeUsernameReq {
    pub password: String,
    pub new_username: String,
}
#[derive(Deserialize)]
pub struct BatchIds {
    pub ids: Vec<i64>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct EntryRef {
    pub entry_type: String,
    pub entry_id: i64,
}

#[derive(Deserialize)]
pub struct SubscriptionUpsert {
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub default_format: String,
    pub template_id: Option<i64>,
    pub enabled: Option<bool>,
    pub expire_preset: String,
    pub expires_at: Option<String>,
    pub max_ips: Option<i64>,
    #[serde(default)]
    pub entries: Vec<EntryRef>,
    #[serde(default)]
    pub rules: Vec<SubRuleInput>,
}
#[derive(Deserialize, Clone)]
pub struct SubRuleInput {
    pub kind: String,
    pub value: String,
    pub mode: String,
}

#[derive(Deserialize)]
pub struct ImportParseReq {
    pub url: Option<String>,
    pub content: Option<String>,
}
#[derive(Deserialize)]
pub struct ImportConfirmReq {
    pub parse_token: String,
    pub target_node_id: i64,
    pub target_type: String,
    pub selected: Option<Vec<usize>>,
    pub name_prefix: Option<String>,
}

#[derive(Deserialize)]
pub struct QuotaUpsert {
    pub quota_bytes: i64,
    pub period: String,
    pub reset_day: Option<i64>,
}

// ============ 通用列表查询参数 ============
#[derive(Deserialize)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub q: Option<String>,
    pub node_id: Option<i64>,
    pub enabled: Option<i64>,
    pub source_import_id: Option<i64>,
    pub group_id: Option<i64>,
    pub no_group: Option<i64>,
    pub tag_id: Option<String>,
    pub disabled_reason: Option<String>,
    pub expiring_days: Option<i64>,
}

// ============ 条目创建 / 更新 ============
#[derive(Deserialize, Clone)]
pub struct ProxyUpsert {
    pub node_id: i64,
    pub name: String,
    pub listen_addr: Option<String>,
    pub upstream_type: String,
    pub upstream_addr: String,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub group_id: Option<i64>,
    pub tag_ids: Option<Vec<i64>>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<String>,
    pub remark: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct ForwardUpsert {
    pub node_id: i64,
    pub name: String,
    pub listen_ip: Option<String>,
    pub listen_port: i64,
    pub target_ip: String,
    pub target_port: i64,
    pub protocol: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub group_id: Option<i64>,
    pub tag_ids: Option<Vec<i64>>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<String>,
    pub remark: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub struct TunnelUpsert {
    pub node_id: i64,
    pub name: String,
    pub tunnel_type: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub token: Option<String>,
    pub export_host: Option<String>,
    pub export_port: Option<i64>,
    pub extra: Option<String>,
    pub group_id: Option<i64>,
    pub tag_ids: Option<Vec<i64>>,
    pub expire_preset: Option<String>,
    pub expires_at: Option<String>,
    pub remark: Option<String>,
    pub enabled: Option<bool>,
}
