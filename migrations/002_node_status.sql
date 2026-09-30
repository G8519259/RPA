-- P10：Worker 上报的条目运行状态（Master 侧存储，供监控页展示与 runtime_error 告警用）
CREATE TABLE IF NOT EXISTS node_entry_status (
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    entry_type  TEXT NOT NULL,              -- proxy | forward | tunnel
    entry_id    INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'unknown',  -- running | idle | error:<原因>
    conns       INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (node_id, entry_type, entry_id)
);
