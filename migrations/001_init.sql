PRAGMA foreign_keys = ON;

-- ============ 用户 / 会话 / 设置 ============
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',          -- admin | viewer
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,                         -- 32 字节随机 base64url
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    ip_addr     TEXT,
    user_agent  TEXT,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ============ 服务器节点 ============
CREATE TABLE IF NOT EXISTS nodes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    is_local          INTEGER NOT NULL DEFAULT 0,          -- 1 = Master 本机
    addr              TEXT,
    public_host       TEXT,                                -- 对外域名/IP，用于生成订阅
    api_token         TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    meta              TEXT,                                -- JSON：地区、运营商、备注
    version           TEXT,
    last_heartbeat_at TEXT,
    last_load         TEXT,                                -- JSON：{cpu,mem,conns}
    online_state      TEXT NOT NULL DEFAULT 'unknown',     -- unknown | online | offline（离线告警用）
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============ 分组 / 标签 / 输出模板 ============
CREATE TABLE IF NOT EXISTS entry_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    color       TEXT NOT NULL DEFAULT '#3b82f6',
    description TEXT,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tags (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    color      TEXT NOT NULL DEFAULT '#64748b',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sub_templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    format      TEXT NOT NULL,                             -- clash | singbox
    content     TEXT NOT NULL,                             -- Clash=YAML，Sing-box=JSON，含 @ 标记
    is_builtin  INTEGER NOT NULL DEFAULT 0,                -- 内置模板不可删除/修改，可复制
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============ 导入记录（必须先于条目表创建） ============
CREATE TABLE IF NOT EXISTS import_records (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
    source_url     TEXT,
    source_type    TEXT NOT NULL,                          -- clash | singbox | base64 | uri_list | paste
    target_node_id INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    parsed_count   INTEGER NOT NULL DEFAULT 0,
    imported_count INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============ 三类条目 ============
CREATE TABLE IF NOT EXISTS proxy_rules (                   -- 落地代理
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id          INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    listen_addr      TEXT,                                 -- 本地监听，可空（纯导入条目无需监听）
    upstream_type    TEXT NOT NULL,                        -- http | https | socks5 | ss | vmess | vless | trojan | hysteria2 | tuic ...
    upstream_addr    TEXT NOT NULL,                        -- host:port
    auth_user        TEXT,
    auth_pass        TEXT,
    export_host      TEXT,                                 -- 订阅导出地址；空则用 upstream 的 host
    export_port      INTEGER,
    extra            TEXT,                                 -- JSON：原始节点完整配置（Clash 风格字典）
    source_import_id INTEGER REFERENCES import_records(id) ON DELETE SET NULL,
    group_id         INTEGER REFERENCES entry_groups(id) ON DELETE SET NULL,
    expires_at       TEXT,                                 -- UTC；NULL = 不过期
    enabled          INTEGER NOT NULL DEFAULT 1,
    disabled_reason  TEXT,                                 -- manual | expired | quota
    remark           TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS port_forwards (                 -- 端口转发
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id          INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    listen_ip        TEXT NOT NULL DEFAULT '0.0.0.0',
    listen_port      INTEGER NOT NULL,
    target_ip        TEXT NOT NULL,
    target_port      INTEGER NOT NULL,
    protocol         TEXT NOT NULL DEFAULT 'tcp',          -- tcp | udp | both
    export_host      TEXT,
    export_port      INTEGER,
    extra            TEXT,
    source_import_id INTEGER REFERENCES import_records(id) ON DELETE SET NULL,
    group_id         INTEGER REFERENCES entry_groups(id) ON DELETE SET NULL,
    expires_at       TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1,
    disabled_reason  TEXT,
    remark           TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(node_id, listen_ip, listen_port, protocol)
);

CREATE TABLE IF NOT EXISTS tunnels (                       -- 中转隧道
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id          INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    tunnel_type      TEXT NOT NULL,                        -- tcp | ws | wss | reverse
    local_addr       TEXT NOT NULL,
    remote_addr      TEXT NOT NULL,
    token            TEXT,
    export_host      TEXT,
    export_port      INTEGER,
    extra            TEXT,
    source_import_id INTEGER REFERENCES import_records(id) ON DELETE SET NULL,
    group_id         INTEGER REFERENCES entry_groups(id) ON DELETE SET NULL,
    expires_at       TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1,
    disabled_reason  TEXT,
    remark           TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============ 多态关联表（删除条目时由应用层同事务清理） ============
CREATE TABLE IF NOT EXISTS entry_tags (
    entry_type TEXT NOT NULL,                              -- proxy | forward | tunnel
    entry_id   INTEGER NOT NULL,
    tag_id     INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (entry_type, entry_id, tag_id)
);

CREATE TABLE IF NOT EXISTS entry_quotas (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_type   TEXT NOT NULL,
    entry_id     INTEGER NOT NULL,
    quota_bytes  INTEGER NOT NULL,                         -- 0 = 无限制（等同于删除配额）
    used_bytes   INTEGER NOT NULL DEFAULT 0,
    period       TEXT NOT NULL DEFAULT 'total',            -- total | monthly
    reset_day    INTEGER NOT NULL DEFAULT 1,               -- monthly 时每月几号重置，1~28
    period_start TEXT NOT NULL DEFAULT (datetime('now')),
    warn_level   INTEGER NOT NULL DEFAULT 0,               -- 本周期已发出的最高预警百分比
    status       TEXT NOT NULL DEFAULT 'ok',               -- ok | exceeded
    exceeded_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (entry_type, entry_id)
);

-- ============ 日志 / 统计 / 监控 ============
CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_name    TEXT,                                    -- 系统动作为 'system'
    action        TEXT NOT NULL,
    resource_type TEXT,
    resource_id   INTEGER,
    node_id       INTEGER,
    detail        TEXT,                                    -- JSON
    ip_addr       TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    INTEGER NOT NULL,
    rule_type  TEXT NOT NULL,                              -- proxy | forward | tunnel
    rule_id    INTEGER NOT NULL,
    client_ip  TEXT,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    bytes_up   INTEGER NOT NULL DEFAULT 0,
    bytes_down INTEGER NOT NULL DEFAULT 0,
    status     TEXT
);

CREATE TABLE IF NOT EXISTS stats_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_time TEXT NOT NULL,                               -- 2026-09-30T14
    node_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    total_bytes_up INTEGER NOT NULL DEFAULT 0,
    total_bytes_down INTEGER NOT NULL DEFAULT 0,
    UNIQUE(stat_time, node_id, rule_type, rule_id)
);

CREATE TABLE IF NOT EXISTS stats_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_date TEXT NOT NULL,                               -- 2026-09-30
    node_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    total_bytes_up INTEGER NOT NULL DEFAULT 0,
    total_bytes_down INTEGER NOT NULL DEFAULT 0,
    UNIQUE(stat_date, node_id, rule_type, rule_id)
);

CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    collected_at TEXT NOT NULL,
    cpu REAL, mem REAL, conns INTEGER, net_up_bps INTEGER, net_down_bps INTEGER
);

-- ============ 订阅 ============
CREATE TABLE IF NOT EXISTS subscriptions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    token           TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT,
    scope           TEXT NOT NULL DEFAULT 'custom',        -- single | custom | all | rule
    default_format  TEXT NOT NULL DEFAULT 'clash',         -- clash | singbox | base64 | json
    template_id     INTEGER REFERENCES sub_templates(id) ON DELETE SET NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    disabled_reason TEXT,                                  -- manual | expired
    expires_at      TEXT,                                  -- NULL = 永久；UTC
    max_ips         INTEGER,                               -- 24h 内不同来源 IP 数上限，NULL = 不限
    access_count    INTEGER NOT NULL DEFAULT 0,
    last_access_at  TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subscription_entries (          -- 手工勾选的条目（single / custom，及 rule 的例外项）
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    entry_type      TEXT NOT NULL,
    entry_id        INTEGER NOT NULL,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(subscription_id, entry_type, entry_id)
);

CREATE TABLE IF NOT EXISTS subscription_rules (            -- 动态规则
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,                         -- group | tag | node | type
    value           TEXT NOT NULL,                         -- group/tag 存 id；node 存 node_id；type 存 proxy|forward|tunnel
    mode            TEXT NOT NULL DEFAULT 'include',       -- include | exclude
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subscription_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    client_ip       TEXT,
    user_agent      TEXT,
    format          TEXT,
    result          TEXT NOT NULL,                         -- ok | expired | disabled | ip_limit
    accessed_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ============ 告警 ============
CREATE TABLE IF NOT EXISTS alert_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL,                              -- webhook | telegram | email
    config     TEXT NOT NULL,                              -- JSON，见第 14 章
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    event_type    TEXT NOT NULL,                           -- 见 14.3 事件清单
    params        TEXT NOT NULL DEFAULT '{}',              -- JSON 阈值参数
    channel_ids   TEXT NOT NULL DEFAULT '[]',              -- JSON 数组
    cooldown_secs INTEGER NOT NULL DEFAULT 3600,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alert_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id       INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
    event_type    TEXT NOT NULL,
    dedup_key     TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'warning',         -- info | warning | critical
    title         TEXT NOT NULL,
    body          TEXT NOT NULL,
    resource_type TEXT,
    resource_id   INTEGER,
    status        TEXT NOT NULL DEFAULT 'pending',         -- pending | sent | failed
    attempts      INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,
    last_error    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    sent_at       TEXT
);

-- ============ 索引 ============
CREATE INDEX IF NOT EXISTS idx_sessions_exp      ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_proxy_node        ON proxy_rules(node_id);
CREATE INDEX IF NOT EXISTS idx_proxy_import      ON proxy_rules(source_import_id);
CREATE INDEX IF NOT EXISTS idx_proxy_group       ON proxy_rules(group_id);
CREATE INDEX IF NOT EXISTS idx_proxy_exp         ON proxy_rules(expires_at)   WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_forward_node      ON port_forwards(node_id);
CREATE INDEX IF NOT EXISTS idx_forward_import    ON port_forwards(source_import_id);
CREATE INDEX IF NOT EXISTS idx_forward_group     ON port_forwards(group_id);
CREATE INDEX IF NOT EXISTS idx_forward_exp       ON port_forwards(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tunnel_node       ON tunnels(node_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_import     ON tunnels(source_import_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_group      ON tunnels(group_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_exp        ON tunnels(expires_at)       WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_entry_tags_tag    ON entry_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_audit_created     ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_access_rule       ON access_logs(rule_type, rule_id, started_at);
CREATE INDEX IF NOT EXISTS idx_access_node_time  ON access_logs(node_id, started_at);
CREATE INDEX IF NOT EXISTS idx_stats_h_time      ON stats_hourly(stat_time);
CREATE INDEX IF NOT EXISTS idx_stats_d_date      ON stats_daily(stat_date);
CREATE INDEX IF NOT EXISTS idx_metrics_node      ON metrics_snapshots(node_id, collected_at);
CREATE INDEX IF NOT EXISTS idx_sub_token         ON subscriptions(token);
CREATE INDEX IF NOT EXISTS idx_sub_entries_sub   ON subscription_entries(subscription_id);
CREATE INDEX IF NOT EXISTS idx_sub_rules_sub     ON subscription_rules(subscription_id);
CREATE INDEX IF NOT EXISTS idx_sub_logs_sub      ON subscription_logs(subscription_id, accessed_at);
CREATE INDEX IF NOT EXISTS idx_alert_ev_status   ON alert_events(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_alert_ev_dedup    ON alert_events(rule_id, dedup_key, created_at);
