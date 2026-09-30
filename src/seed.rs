use crate::config::Config;
use crate::util::{hash_password, random_token};
use sqlx::SqlitePool;

/// 启动时自动初始化的数据（代码里做，不写进迁移）
pub async fn ensure_seed(pool: &SqlitePool, cfg: &Config) -> anyhow::Result<()> {
    // 1) 本机节点 id=1
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
        .fetch_one(pool)
        .await?;
    if n == 0 {
        sqlx::query(
            "INSERT INTO nodes (id, name, is_local, api_token, enabled, online_state)
             VALUES (1, 'local', 1, ?, 1, 'online')",
        )
        .bind(random_token(32))
        .execute(pool)
        .await?;
        tracing::info!("已创建本机节点 local (id=1)");
    }

    // 2) 管理员账户
    let u: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    if u == 0 {
        let username = if cfg.auth.init_username.is_empty() {
            "admin"
        } else {
            &cfg.auth.init_username
        };
        let password = if cfg.auth.init_password.is_empty() {
            "ChangeMe123!"
        } else {
            &cfg.auth.init_password
        };
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')")
            .bind(username)
            .bind(hash_password(password)?)
            .execute(pool)
            .await?;
        tracing::info!("已创建初始管理员账户: {username}");
        if password == "ChangeMe123!" {
            tracing::warn!("正在使用默认密码 ChangeMe123!，请立即在后台修改");
        }
    }

    // 3) 内置输出模板
    let t: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sub_templates")
        .fetch_one(pool)
        .await?;
    if t == 0 {
        for (name, desc, format, content) in builtin_templates() {
            sqlx::query(
                "INSERT INTO sub_templates (name, description, format, content, is_builtin)
                 VALUES (?, ?, ?, ?, 1)",
            )
            .bind(name)
            .bind(desc)
            .bind(format)
            .bind(content)
            .execute(pool)
            .await?;
        }
        tracing::info!("已写入内置输出模板");
    }

    // 4) 默认告警规则（未绑定渠道）
    let r: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules")
        .fetch_one(pool)
        .await?;
    if r == 0 {
        let defaults: Vec<(&str, &str, &str, i64)> = vec![
            ("节点离线", "node_offline", r#"{"offline_secs":90}"#, 3600),
            ("节点恢复", "node_online", "{}", 3600),
            ("订阅即将到期", "sub_expiring", r#"{"days_before":[7,3,1]}"#, 86400 * 3650),
            ("订阅已过期", "sub_expired", "{}", 86400 * 3650),
            ("条目即将到期", "entry_expiring", r#"{"days_before":[7,3,1]}"#, 86400 * 3650),
            ("条目已到期", "entry_expired", "{}", 86400 * 3650),
            ("配额预警", "quota_warn", r#"{"percent":[80,95]}"#, 86400 * 3650),
            ("配额用尽", "quota_exceeded", "{}", 86400 * 3650),
            ("条目运行异常", "runtime_error", "{}", 3600),
            ("登录失败激增", "login_fail_burst", r#"{"threshold":5}"#, 3600),
            ("订阅触发 IP 限制", "sub_ip_limit", "{}", 3600),
        ];
        for (name, event_type, params, cooldown) in defaults {
            sqlx::query(
                "INSERT INTO alert_rules (name, event_type, params, channel_ids, cooldown_secs, enabled)
                 VALUES (?, ?, ?, '[]', ?, 1)",
            )
            .bind(name)
            .bind(event_type)
            .bind(params)
            .bind(cooldown)
            .execute(pool)
            .await?;
        }
        tracing::info!("已写入默认告警规则");
    }
    Ok(())
}

fn builtin_templates() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        (
            "Clash 基础：全部走代理",
            "所有流量走代理，内置 PROXY 手选与 AUTO 自动测速分组",
            "clash",
            r#"mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
proxy-groups:
  - { name: "PROXY", type: select, proxies: ["AUTO", "@ALL", "DIRECT"] }
  - { name: "AUTO", type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, proxies: ["@ALL"] }
rules:
  - MATCH,PROXY
"#,
        ),
        (
            "Clash 国内直连",
            "国内直连、国外走代理，附带 DNS 配置",
            "clash",
            r#"mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5, 119.29.29.29]
proxy-groups:
  - { name: "PROXY", type: select, proxies: ["AUTO", "@ALL", "DIRECT"] }
  - { name: "AUTO", type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, proxies: ["@ALL"] }
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#,
        ),
        (
            "Clash 按地区分组",
            "用 @REGEX 按节点名把 HK / TW 节点分到不同测速组",
            "clash",
            r#"mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
proxy-groups:
  - { name: "PROXY", type: select, proxies: ["HK", "TW", "OTHER", "DIRECT"] }
  - { name: "HK", type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, proxies: ["@REGEX:(?i)hk|香港|hong"] }
  - { name: "TW", type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, proxies: ["@REGEX:(?i)tw|台湾|taiwan"] }
  - { name: "OTHER", type: select, proxies: ["@ALL"] }
rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#,
        ),
        (
            "Sing-box 基础：全部走代理",
            "selector 手选 + urltest 自动测速",
            "singbox",
            r#"{
  "outbounds": [
    { "type": "selector", "tag": "PROXY", "outbounds": ["AUTO", "@ALL", "direct"] },
    { "type": "urltest", "tag": "AUTO", "outbounds": ["@ALL"], "url": "http://www.gstatic.com/generate_204", "interval": "5m" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [],
    "final": "PROXY"
  }
}"#,
        ),
        (
            "Sing-box 国内直连",
            "geoip cn 直连，其余走代理",
            "singbox",
            r#"{
  "dns": {
    "servers": [
      { "tag": "local", "address": "223.5.5.5", "detour": "direct" }
    ]
  },
  "outbounds": [
    { "type": "selector", "tag": "PROXY", "outbounds": ["AUTO", "@ALL", "direct"] },
    { "type": "urltest", "tag": "AUTO", "outbounds": ["@ALL"], "url": "http://www.gstatic.com/generate_204", "interval": "5m" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "geoip": "cn", "outbound": "direct" }
    ],
    "final": "PROXY"
  }
}"#,
        ),
    ]
}
