//! P8 —— 运行时（§15）：真实转发 / 代理 / 隧道。
//!
//! - 每个**启用**的本机节点条目对应 tokio 任务，由 [`RuntimeManager`] 持有
//!   `HashMap<(entry_type, id), RunningTask>`（JoinHandle + CancellationToken）。
//! - 配置变化时：新增 → spawn；删除 / 禁用 / 到期 / 配额停用 → cancel；修改 → cancel 后重建。
//! - TCP 转发：accept → 连接目标 → copy_bidirectional，结束记字节数与状态。
//! - UDP 转发：按客户端地址维护会话表，空闲 60 秒超时。
//! - 落地代理：监听端提供 HTTP CONNECT 与 SOCKS5 入口，出站支持 http / socks5 上游。
//! - 中转隧道：TCP 中转与 WebSocket 隧道。
//! - 启动失败（端口占用、权限不足）写入运行状态 `error:<原因>`。
//! - 每个任务持有原子计数器（当前连接数、累计上下行字节）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sqlx::SqlitePool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;

pub type EntryKey = (String, i64); // (entry_type, id)，entry_type: proxy | forward | tunnel

/// 每个运行中条目的原子计数器
#[derive(Debug, Default)]
pub struct Counters {
    /// 当前连接数
    pub conns: AtomicU64,
    /// 累计上行字节
    pub bytes_up: AtomicU64,
    /// 累计下行字节
    pub bytes_down: AtomicU64,
}

struct RunningTask {
    cancel: CancellationToken,
    handles: Vec<JoinHandle<()>>,
    counters: Arc<Counters>,
    /// 运行状态：running | idle | error:<原因>
    status: String,
    name: String,
    spec_hash: u64,
}

/// 运行时管理器
pub struct RuntimeManager {
    pool: SqlitePool,
    cfg: Config,
    tasks: tokio::sync::Mutex<HashMap<EntryKey, RunningTask>>,
}

impl RuntimeManager {
    pub fn new(pool: SqlitePool, cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            pool,
            cfg,
            tasks: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// 运行状态快照：给 API / 列表页用
    pub async fn status_snapshot(&self) -> Vec<serde_json::Value> {
        let tasks = self.tasks.lock().await;
        tasks
            .iter()
            .map(|((etype, id), t)| {
                serde_json::json!({
                    "entry_type": etype,
                    "entry_id": id,
                    "name": t.name,
                    "status": t.status,
                    "conns": t.counters.conns.load(Ordering::Relaxed),
                    "bytes_up": t.counters.bytes_up.load(Ordering::Relaxed),
                    "bytes_down": t.counters.bytes_down.load(Ordering::Relaxed),
                })
            })
            .collect()
    }

    /// 热更新：与 DB 期望状态对齐（新增→spawn；删除/禁用/修改→cancel 后重建）
    pub async fn sync(&self) {
        let desired = load_desired(&self.pool).await;
        self.sync_with(desired).await;
    }

    /// 与给定期望配置对齐（Worker 模式用 Master 下发的配置调用）
    pub async fn sync_with(&self, desired: HashMap<EntryKey, EntrySpec>) {
        let mut tasks = self.tasks.lock().await;

        // 1. 取消不再需要 / 配置变化的任务
        let mut to_remove: Vec<EntryKey> = Vec::new();
        for (key, task) in tasks.iter() {
            match desired.get(key) {
                None => to_remove.push(key.clone()),
                Some(spec) if spec.hash != task.spec_hash => to_remove.push(key.clone()),
                _ => {}
            }
        }
        for key in to_remove {
            if let Some(task) = tasks.remove(&key) {
                task.cancel.cancel();
                tracing::info!("运行时：停止 {}/{}（{}）", key.0, key.1, task.name);
            }
        }

        // 2. 启动新增的任务
        let specs: Vec<EntrySpec> = desired
            .into_iter()
            .filter(|(key, _)| !tasks.contains_key(key))
            .map(|(_, spec)| spec)
            .collect();
        drop(tasks);
        for spec in specs {
            self.spawn_spec(spec).await;
        }
    }

    async fn spawn_spec(&self, spec: EntrySpec) {
        let key: EntryKey = (spec.entry_type.clone(), spec.id);
        let cancel = CancellationToken::new();
        let counters = Arc::new(Counters::default());
        let ctx = TaskCtx {
            pool: self.pool.clone(),
            cfg: self.cfg.clone(),
            key: key.clone(),
            cancel: cancel.clone(),
            counters: counters.clone(),
        };
        // 先做黑名单 / 参数校验，再真正 bind
        let spawn_result = match &spec.kind {
            SpecKind::TcpForward { .. } | SpecKind::UdpForward { .. } => {
                run_forward(ctx, spec.clone()).await
            }
            SpecKind::Proxy { .. } => run_proxy(ctx, spec.clone()).await,
            SpecKind::Tunnel { .. } => run_tunnel(ctx, spec.clone()).await,
            SpecKind::Idle { reason } => {
                let reason = reason.clone();
                Ok((vec![], format!("idle:{reason}")))
            }
        };
        let mut tasks = self.tasks.lock().await;
        let spec_hash = spec.hash;
        match spawn_result {
            Ok((handles, status)) => {
                tracing::info!(
                    "运行时：启动 {}/{}（{}）状态={}",
                    key.0, key.1, spec.name, status
                );
                tasks.insert(
                    key,
                    RunningTask {
                        cancel,
                        handles,
                        counters,
                        status,
                        name: spec.name,
                        spec_hash,
                    },
                );
            }
            Err(e) => {
                tracing::warn!("运行时：{}/{}（{}）启动失败: {e}", key.0, key.1, spec.name);
                // P12：条目启动失败 → runtime_error 告警（同一原因 1 小时内只提醒一次）
                let base = self.cfg.server.public_base_url.clone();
                if let Err(e2) = crate::services::alert::emit(
                    &self.pool,
                    crate::services::alert::AlertDraft::runtime_error(
                        &key.0, key.1, &spec.name, &e.to_string(), None, &base,
                    ),
                )
                .await
                {
                    tracing::warn!("runtime_error 告警写入失败: {e2:#}");
                }
                tasks.insert(
                    key,
                    RunningTask {
                        cancel,
                        handles: vec![],
                        counters,
                        status: format!("error:{e}"),
                        name: spec.name,
                        spec_hash,
                    },
                );
            }
        }
    }
}

// ============ 期望配置加载 ============

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntrySpec {
    pub entry_type: String, // proxy | forward | tunnel
    pub id: i64,
    pub name: String,
    pub node_id: i64,
    pub hash: u64,
    pub kind: SpecKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecKind {
    TcpForward {
        listen_ip: String,
        listen_port: i64,
        target_ip: String,
        target_port: i64,
    },
    UdpForward {
        listen_ip: String,
        listen_port: i64,
        target_ip: String,
        target_port: i64,
    },
    Proxy {
        listen_addr: String,
        upstream_type: String,
        upstream_addr: String,
        auth_user: Option<String>,
        auth_pass: Option<String>,
        extra: Option<String>,
    },
    Tunnel {
        tunnel_type: String, // tcp | ws
        local_addr: String,
        remote_addr: String,
    },
    /// 无需监听的条目（纯导入节点等）
    Idle { reason: String },
}

pub(crate) fn spec_hash_of(parts: &[&str]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    h.finish()
}

/// 从 DB 加载本机节点（node_id=1）的启用条目
async fn load_desired(pool: &SqlitePool) -> HashMap<EntryKey, EntrySpec> {
    load_desired_for(pool, 1).await
}

/// 加载指定节点的启用条目（Worker 配置下发 / Master 本机都用这个）
pub async fn load_desired_for(pool: &SqlitePool, node_id: i64) -> HashMap<EntryKey, EntrySpec> {
    let mut out = HashMap::new();
    // ---- 落地代理 ----
    let proxies: Vec<(i64, String, Option<String>, String, String, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT id, name, listen_addr, upstream_type, upstream_addr, auth_user, auth_pass, extra
             FROM proxy_rules WHERE node_id = ? AND enabled = 1
             AND (expires_at IS NULL OR expires_at > datetime('now'))",
        )
        .bind(node_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for (id, name, listen_addr, utype, uaddr, auser, apass, extra) in proxies {
        let kind = match listen_addr.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => SpecKind::Idle { reason: "no-listen".into() },
            Some(la) => SpecKind::Proxy {
                listen_addr: la.to_string(),
                upstream_type: utype.clone(),
                upstream_addr: uaddr.clone(),
                auth_user: auser.clone(),
                auth_pass: apass.clone(),
                extra: extra.clone(),
            },
        };
        let hash = spec_hash_of(&[
            "proxy", &id.to_string(),
            listen_addr.as_deref().unwrap_or(""), &utype, &uaddr,
            auser.as_deref().unwrap_or(""), extra.as_deref().unwrap_or(""),
        ]);
        out.insert(
            ("proxy".to_string(), id),
            EntrySpec { entry_type: "proxy".into(), id, name, node_id, hash, kind },
        );
    }
    // ---- 端口转发 ----
    let forwards: Vec<(i64, String, String, i64, String, i64, String)> = sqlx::query_as(
        "SELECT id, name, listen_ip, listen_port, target_ip, target_port, protocol
         FROM port_forwards WHERE node_id = ? AND enabled = 1
         AND (expires_at IS NULL OR expires_at > datetime('now'))",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for (id, name, lip, lport, tip, tport, proto) in forwards {
        let hash = spec_hash_of(&[
            "forward", &id.to_string(), &lip, &lport.to_string(), &tip, &tport.to_string(), &proto,
        ]);
        // protocol=both 拆成两个 key：forward/tcp#id 与 forward/udp#id 用不同 entry_type 区分
        let mk = |etype: &str, kind| EntrySpec {
            entry_type: etype.into(),
            id,
            name: name.clone(),
            node_id,
            hash,
            kind,
        };
        if proto == "tcp" || proto == "both" {
            out.insert(
                ("forward".to_string(), id),
                mk(
                    "forward",
                    SpecKind::TcpForward {
                        listen_ip: lip.clone(),
                        listen_port: lport,
                        target_ip: tip.clone(),
                        target_port: tport,
                    },
                ),
            );
        }
        if proto == "udp" || proto == "both" {
            // both 时 udp 用 key ("forward_udp", id) 避免与 tcp 冲突
            let etype = if proto == "both" { "forward_udp" } else { "forward" };
            out.insert(
                (etype.to_string(), id),
                mk(
                    etype,
                    SpecKind::UdpForward {
                        listen_ip: lip.clone(),
                        listen_port: lport,
                        target_ip: tip.clone(),
                        target_port: tport,
                    },
                ),
            );
        }
    }
    // ---- 中转隧道 ----
    let tunnels: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT id, name, tunnel_type, local_addr, remote_addr
         FROM tunnels WHERE node_id = ? AND enabled = 1
         AND (expires_at IS NULL OR expires_at > datetime('now'))",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for (id, name, ttype, local, remote) in tunnels {
        let hash = spec_hash_of(&["tunnel", &id.to_string(), &ttype, &local, &remote]);
        let kind = match ttype.as_str() {
            "tcp" | "ws" => SpecKind::Tunnel {
                tunnel_type: ttype.clone(),
                local_addr: local.clone(),
                remote_addr: remote.clone(),
            },
            other => SpecKind::Idle { reason: format!("unsupported-tunnel-{other}") },
        };
        out.insert(
            ("tunnel".to_string(), id),
            EntrySpec { entry_type: "tunnel".into(), id, name, node_id, hash, kind },
        );
    }
    out
}

// ============ 任务上下文 ============

#[derive(Clone)]
pub struct TaskCtx {
    pub pool: SqlitePool,
    pub cfg: Config,
    pub key: EntryKey,
    pub cancel: CancellationToken,
    pub counters: Arc<Counters>,
}

impl TaskCtx {
    /// 连接结束：记 access_logs（按采样率）+ 累计计数器
    pub async fn finish_conn(
        &self,
        client_ip: Option<String>,
        started: chrono::DateTime<chrono::Local>,
        up: u64,
        down: u64,
        status: &str,
    ) {
        self.counters.conns.fetch_sub(1, Ordering::Relaxed);
        self.counters.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.counters.bytes_down.fetch_add(down, Ordering::Relaxed);
        let rate = self.cfg.log.access_log_sample_rate.clamp(0.0, 1.0);
        if rate <= 0.0 {
            return;
        }
        if rate < 1.0 && rand::random::<f64>() > rate {
            return;
        }
        let (etype, rule_id) = (&self.key.0, self.key.1);
        // forward_udp 归一化为 forward
        let etype = etype.strip_prefix("forward").map(|_| "forward").unwrap_or(etype);
        let ended = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let started_s = started.format("%Y-%m-%d %H:%M:%S").to_string();
        let r = sqlx::query(
            "INSERT INTO access_logs (node_id, rule_type, rule_id, client_ip, started_at, ended_at, bytes_up, bytes_down, status)
             VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(etype)
        .bind(rule_id)
        .bind(client_ip)
        .bind(started_s)
        .bind(ended)
        .bind(up as i64)
        .bind(down as i64)
        .bind(status)
        .execute(&self.pool)
        .await;
        if let Err(e) = r {
            tracing::warn!("finish_conn 写入 access_logs 失败: {e:#}");
        }
    }

    pub fn begin_conn(&self) {
        self.counters.conns.fetch_add(1, Ordering::Relaxed);
    }
}

// ============ 转发目标黑名单 ============

/// 默认禁止：云元数据地址、本机管理端口（可在配置里调整）
pub fn target_blocked(target_ip: &str, target_port: i64, mgmt_port: u16) -> Option<String> {
    let ip = target_ip.trim().trim_matches(|c| c == '[' || c == ']');
    // 云元数据
    for meta in ["169.254.169.254", "100.100.100.200", "169.254.169.123"] {
        if ip == meta {
            return Some(format!("禁止转发到云元数据地址 {ip}"));
        }
    }
    // 回环地址上的管理端口
    let is_loopback = ip == "127.0.0.1" || ip == "::1" || ip == "localhost";
    if is_loopback && target_port as u16 == mgmt_port {
        return Some(format!("禁止转发到本机管理端口 {mgmt_port}"));
    }
    None
}

pub fn mgmt_port_of(cfg: &Config) -> u16 {
    cfg.server
        .bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
}

// ============ TCP / UDP 端口转发 ============

/// 返回 (JoinHandle 列表, 状态字符串)
async fn run_forward(ctx: TaskCtx, spec: EntrySpec) -> anyhow::Result<(Vec<JoinHandle<()>>, String)> {
    let (lip, lport, tip, tport) = match &spec.kind {
        SpecKind::TcpForward { listen_ip, listen_port, target_ip, target_port } => {
            (listen_ip.clone(), *listen_port, target_ip.clone(), *target_port)
        }
        SpecKind::UdpForward { listen_ip, listen_port, target_ip, target_port } => {
            (listen_ip.clone(), *listen_port, target_ip.clone(), *target_port)
        }
        _ => anyhow::bail!("内部错误：转发任务收到非转发 spec"),
    };
    if let Some(reason) = target_blocked(&tip, tport, mgmt_port_of(&ctx.cfg)) {
        anyhow::bail!("{reason}");
    }
    let is_tcp = matches!(spec.kind, SpecKind::TcpForward { .. });
    if is_tcp {
        let listener = tokio::net::TcpListener::bind(format!("{lip}:{lport}"))
            .await
            .map_err(|e| anyhow::anyhow!("监听 {lip}:{lport} 失败: {e}"))?;
        let h = tokio::spawn(tcp_forward_loop(ctx, listener, tip, tport));
        Ok((vec![h], "running".into()))
    } else {
        let sock = tokio::net::UdpSocket::bind(format!("{lip}:{lport}"))
            .await
            .map_err(|e| anyhow::anyhow!("监听 {lip}:{lport} 失败: {e}"))?;
        let h = tokio::spawn(udp_forward_loop(ctx, sock, tip, tport));
        Ok((vec![h], "running".into()))
    }
}

async fn tcp_forward_loop(ctx: TaskCtx, listener: tokio::net::TcpListener, tip: String, tport: i64) {
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            accepted = listener.accept() => {
                let (inbound, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!("转发 accept 失败: {e}"); continue; }
                };
                let ctx2 = ctx.clone();
                let tip2 = tip.clone();
                tokio::spawn(async move {
                    let started = chrono::Local::now();
                    ctx2.begin_conn();
                    let client_ip = peer.ip().to_string();
                    let (mut up, mut down) = (0u64, 0u64);
                    let mut status = "ok";
                    match tokio::net::TcpStream::connect(format!("{tip2}:{tport}")).await {
                        Ok(outbound) => {
                            match relay_tcp(inbound, outbound).await {
                                Ok((u, d)) => { up = u; down = d; }
                                Err(_) => status = "relay_error",
                            }
                        }
                        Err(_) => status = "target_refused",
                    }
                    ctx2.finish_conn(Some(client_ip), started, up, down, status).await;
                });
            }
        }
    }
}

/// 双向转发，返回 (上行字节, 下行字节)。上行 = inbound→outbound
async fn relay_tcp(
    inbound: tokio::net::TcpStream,
    outbound: tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    let (mut ri, mut wi) = inbound.into_split();
    let (mut ro, mut wo) = outbound.into_split();
    let up = tokio::io::copy(&mut ri, &mut wo);
    let down = tokio::io::copy(&mut ro, &mut wi);
    let (u, d) = tokio::join!(up, down);
    Ok((u.unwrap_or(0), d.unwrap_or(0)))
}

// ---- UDP 转发：按客户端地址维护会话表，空闲 60 秒超时 ----

struct UdpSession {
    upstream: Arc<tokio::net::UdpSocket>,
    last_active: tokio::time::Instant,
    started: chrono::DateTime<chrono::Local>,
    up: u64,
    down: u64,
}

async fn udp_forward_loop(ctx: TaskCtx, sock: tokio::net::UdpSocket, tip: String, tport: i64) {
    let sock = Arc::new(sock);
    let mut sessions: HashMap<SocketAddr, UdpSession> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(10));
    let target: SocketAddr = match tokio::net::lookup_host(format!("{tip}:{tport}"))
        .await
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) => a,
        None => {
            tracing::warn!("UDP 转发目标解析失败: {tip}:{tport}");
            return;
        }
    };
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            _ = cleanup_tick.tick() => {
                // 清理空闲超 60 秒的会话
                let now = tokio::time::Instant::now();
                let idle: Vec<SocketAddr> = sessions.iter()
                    .filter(|(_, s)| now.duration_since(s.last_active).as_secs() > 60)
                    .map(|(a, _)| *a)
                    .collect();
                for a in idle {
                    if let Some(s) = sessions.remove(&a) {
                        let ctx2 = ctx.clone();
                        tokio::spawn(async move {
                            ctx2.finish_conn(Some(a.ip().to_string()), s.started, s.up, s.down, "ok").await;
                        });
                    }
                }
            }
            recvd = sock.recv_from(&mut buf) => {
                let (n, peer) = match recvd {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!("UDP recv 失败: {e}"); continue; }
                };
                let data = &buf[..n];
                let session = match sessions.get_mut(&peer) {
                    Some(s) => s,
                    None => {
                        let upstream = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => Arc::new(s),
                            Err(e) => { tracing::warn!("UDP 会话 socket 创建失败: {e}"); continue; }
                        };
                        // 启动上行→下行回包循环
                        let sock_c = sock.clone();
                        let up_c = upstream.clone();
                        let ctx_c = ctx.clone();
                        let cancel_c = ctx.cancel.clone();
                        tokio::spawn(async move {
                            let mut rbuf = vec![0u8; 65535];
                            loop {
                                tokio::select! {
                                    _ = cancel_c.cancelled() => break,
                                    r = up_c.recv(&mut rbuf) => {
                                        match r {
                                            Ok(m) => {
                                                let _ = sock_c.send_to(&rbuf[..m], peer).await;
                                                ctx_c.counters.bytes_down.fetch_add(m as u64, Ordering::Relaxed);
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        });
                        ctx.begin_conn();
                        sessions.insert(peer, UdpSession {
                            upstream,
                            last_active: tokio::time::Instant::now(),
                            started: chrono::Local::now(),
                            up: 0, down: 0,
                        });
                        sessions.get_mut(&peer).unwrap()
                    }
                };
                session.last_active = tokio::time::Instant::now();
                session.up += n as u64;
                ctx.counters.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                if session.upstream.send_to(data, target).await.is_err() {
                    tracing::warn!("UDP 转发到目标失败");
                }
            }
        }
    }
    // 退出时结算所有会话
    for (peer, s) in sessions {
        ctx.finish_conn(Some(peer.ip().to_string()), s.started, s.up, s.down, "shutdown").await;
    }
}

// ============ 落地代理：HTTP CONNECT + SOCKS5 入站 ============

#[derive(Clone)]
struct ProxyCfg {
    upstream_type: String,
    upstream_addr: String,
    auth_user: Option<String>,
    auth_pass: Option<String>,
    extra: Option<String>,
}

async fn run_proxy(ctx: TaskCtx, spec: EntrySpec) -> anyhow::Result<(Vec<JoinHandle<()>>, String)> {
    let pcfg = match &spec.kind {
        SpecKind::Proxy { listen_addr, upstream_type, upstream_addr, auth_user, auth_pass, extra } => {
            let listen_addr = listen_addr.clone();
            let pcfg = ProxyCfg {
                upstream_type: upstream_type.clone(),
                upstream_addr: upstream_addr.clone(),
                auth_user: auth_user.clone(),
                auth_pass: auth_pass.clone(),
                extra: extra.clone(),
            };
            // 上游类型检查：MVP 支持 direct 直连 / http / https(明文 CONNECT) / socks5 出站
            match pcfg.upstream_type.as_str() {
                "direct" | "http" | "https" | "socks5" => {}
                other => anyhow::bail!("暂不支持的上游类型: {other}（MVP 仅支持 direct/http/https/socks5 出站）"),
            }
            (listen_addr, pcfg)
        }
        _ => anyhow::bail!("内部错误：代理任务收到非代理 spec"),
    };
    let (listen_addr, pcfg) = pcfg;
    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .map_err(|e| anyhow::anyhow!("监听 {listen_addr} 失败: {e}"))?;
    let h = tokio::spawn(proxy_accept_loop(ctx, listener, pcfg));
    Ok((vec![h], "running".into()))
}

async fn proxy_accept_loop(ctx: TaskCtx, listener: tokio::net::TcpListener, pcfg: ProxyCfg) {
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            accepted = listener.accept() => {
                let (inbound, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!("代理 accept 失败: {e}"); continue; }
                };
                let ctx2 = ctx.clone();
                let pcfg2 = pcfg.clone();
                tokio::spawn(async move {
                    let started = chrono::Local::now();
                    ctx2.begin_conn();
                    let client_ip = peer.ip().to_string();
                    let (up, down, status) = handle_proxy_conn(inbound, &pcfg2).await;
                    ctx2.finish_conn(Some(client_ip), started, up, down, status).await;
                });
            }
        }
    }
}

/// 处理一个入站代理连接：peek 首字节嗅探协议（SOCKS5 首字节 0x05 / 否则 HTTP），返回 (up, down, status)
async fn handle_proxy_conn(
    inbound: tokio::net::TcpStream,
    pcfg: &ProxyCfg,
) -> (u64, u64, &'static str) {
    let mut one = [0u8; 1];
    let n = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        inbound.peek(&mut one),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => n,
        _ => return (0, 0, "handshake_timeout"),
    };
    let _ = n;
    if one[0] == 0x05 {
        handle_socks5_inbound(inbound, pcfg).await
    } else {
        handle_http_inbound(inbound, pcfg).await
    }
}

// ---- SOCKS5 入站 ----

async fn handle_socks5_inbound(
    inbound: tokio::net::TcpStream,
    pcfg: &ProxyCfg,
) -> (u64, u64, &'static str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut r, mut w) = inbound.into_split();
    // 握手：VER, NMETHODS, METHODS...
    let mut hello = [0u8; 2];
    if r.read_exact(&mut hello).await.is_err() || hello[0] != 0x05 {
        return (0, 0, "socks_bad_hello");
    }
    let nmethods = hello[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 && r.read_exact(&mut methods).await.is_err() {
        return (0, 0, "socks_bad_hello");
    }
    let need_auth = pcfg.auth_user.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    let chosen: u8 = if need_auth {
        if methods.contains(&0x02) { 0x02 } else { 0xff }
    } else if methods.contains(&0x00) {
        0x00
    } else {
        0xff
    };
    if w.write_all(&[0x05, chosen]).await.is_err() || chosen == 0xff {
        return (0, 0, "socks_no_method");
    }
    if chosen == 0x02 {
        // 用户名密码认证：VER(0x01) ULEN UNAME PLEN PASSWD
        let mut hdr = [0u8; 2];
        if r.read_exact(&mut hdr).await.is_err() {
            return (0, 0, "socks_auth_fail");
        }
        let ulen = hdr[1] as usize;
        let mut ubuf = vec![0u8; ulen + 1];
        if r.read_exact(&mut ubuf).await.is_err() {
            return (0, 0, "socks_auth_fail");
        }
        let plen = ubuf[ulen] as usize;
        let mut pbuf = vec![0u8; plen];
        if r.read_exact(&mut pbuf).await.is_err() {
            return (0, 0, "socks_auth_fail");
        }
        let user = String::from_utf8_lossy(&ubuf[..ulen]);
        let pass = String::from_utf8_lossy(&pbuf);
        let ok = pcfg.auth_user.as_deref() == Some(user.as_ref())
            && pcfg.auth_pass.as_deref() == Some(pass.as_ref());
        let _ = w.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await;
        if !ok {
            return (0, 0, "socks_auth_fail");
        }
    }
    // 请求：VER CMD RSV ATYP ADDR PORT
    let mut hdr = [0u8; 4];
    if r.read_exact(&mut hdr).await.is_err() {
        return (0, 0, "socks_bad_req");
    }
    if hdr[1] != 0x01 {
        let _ = w.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return (0, 0, "socks_unsupported_cmd");
    }
    let target: String = match hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            if r.read_exact(&mut b).await.is_err() { return (0, 0, "socks_bad_req"); }
            let port = u16::from_be_bytes([b[4], b[5]]);
            format!("{}.{}.{}.{}:{port}", b[0], b[1], b[2], b[3])
        }
        0x03 => {
            let mut l = [0u8; 1];
            if r.read_exact(&mut l).await.is_err() { return (0, 0, "socks_bad_req"); }
            let mut b = vec![0u8; l[0] as usize + 2];
            if r.read_exact(&mut b).await.is_err() { return (0, 0, "socks_bad_req"); }
            let host = String::from_utf8_lossy(&b[..l[0] as usize]);
            let port = u16::from_be_bytes([b[l[0] as usize], b[l[0] as usize + 1]]);
            format!("{host}:{port}")
        }
        0x04 => {
            let mut b = [0u8; 18];
            if r.read_exact(&mut b).await.is_err() { return (0, 0, "socks_bad_req"); }
            let port = u16::from_be_bytes([b[16], b[17]]);
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap());
            format!("[{ip}]:{port}")
        }
        _ => return (0, 0, "socks_bad_atyp"),
    };
    // 出站
    match dial_upstream(pcfg, &target).await {
        Ok(outbound) => {
            let _ = w.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            let inbound = r.reunite(w).unwrap_or_else(|_| unreachable!());
            match relay_tcp(inbound, outbound).await {
                Ok((u, d)) => (u, d, "ok"),
                Err(_) => (0, 0, "relay_error"),
            }
        }
        Err(e) => {
            tracing::debug!("SOCKS5 出站失败 {target}: {e}");
            let _ = w.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            (0, 0, "upstream_fail")
        }
    }
}

// ---- HTTP CONNECT 入站 ----

async fn handle_http_inbound(
    inbound: tokio::net::TcpStream,
    pcfg: &ProxyCfg,
) -> (u64, u64, &'static str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut r, mut w) = inbound.into_split();
    // 读完整个 HTTP 头
    let mut head = Vec::new();
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > 16384 {
            return (0, 0, "http_head_too_large");
        }
        let mut tmp = [0u8; 1024];
        match r.read(&mut tmp).await {
            Ok(0) => return (0, 0, "http_eof"),
            Ok(n) => head.extend_from_slice(&tmp[..n]),
            Err(_) => return (0, 0, "http_read_error"),
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let mut lines = head_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "CONNECT" {
        let _ = w.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n").await;
        return (0, 0, "http_method_not_allowed");
    }
    // 入站认证
    if pcfg.auth_user.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        let mut authed = false;
        for line in lines {
            if line.to_ascii_lowercase().starts_with("proxy-authorization:") {
                let val = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                if let Some(b64) = val.strip_prefix("Basic ") {
                    use base64::Engine;
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                        let cred = String::from_utf8_lossy(&decoded);
                        let mut kv = cred.splitn(2, ':');
                        if kv.next() == pcfg.auth_user.as_deref()
                            && kv.next() == pcfg.auth_pass.as_deref()
                        {
                            authed = true;
                        }
                    }
                }
            }
            if line.is_empty() {
                break;
            }
        }
        if !authed {
            let _ = w
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
                .await;
            return (0, 0, "http_auth_fail");
        }
    }
    match dial_upstream(pcfg, target).await {
        Ok(outbound) => {
            if w.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
                return (0, 0, "http_write_error");
            }
            let inbound = r.reunite(w).unwrap_or_else(|_| unreachable!());
            match relay_tcp(inbound, outbound).await {
                Ok((u, d)) => (u, d, "ok"),
                Err(_) => (0, 0, "relay_error"),
            }
        }
        Err(e) => {
            tracing::debug!("HTTP CONNECT 出站失败 {target}: {e}");
            let _ = w.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
            (0, 0, "upstream_fail")
        }
    }
}

// ============ 出站拨号 ============

/// 通过上游代理连接到 target（host:port），返回已建立的 TcpStream
async fn dial_upstream(pcfg: &ProxyCfg, target: &str) -> anyhow::Result<tokio::net::TcpStream> {
    match pcfg.upstream_type.as_str() {
        "direct" => tokio::net::TcpStream::connect(target)
            .await
            .map_err(|e| anyhow::anyhow!("直连 {target} 失败: {e}")),
        "http" | "https" => dial_via_http_proxy(pcfg, target).await,
        "socks5" => dial_via_socks5(pcfg, target).await,
        other => anyhow::bail!("不支持的上游类型: {other}"),
    }
}

/// 从 extra（Clash 风格 JSON）取上游认证
fn upstream_creds(pcfg: &ProxyCfg) -> (Option<String>, Option<String>) {
    if let Some(extra) = pcfg.extra.as_deref() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(extra) {
            let u = v.get("username").or(v.get("user")).and_then(|x| x.as_str()).map(|s| s.to_string());
            let p = v.get("password").or(v.get("pass")).and_then(|x| x.as_str()).map(|s| s.to_string());
            return (u, p);
        }
    }
    (None, None)
}

async fn dial_via_http_proxy(pcfg: &ProxyCfg, target: &str) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(&pcfg.upstream_addr)
        .await
        .map_err(|e| anyhow::anyhow!("连接上游 {} 失败: {e}", pcfg.upstream_addr))?;
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    let (u, p) = upstream_creds(pcfg);
    if let (Some(u), Some(p)) = (u, p) {
        use base64::Engine;
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    // 读响应头
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("上游过早关闭连接");
        }
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 16384 {
            break;
        }
    }
    let status = String::from_utf8_lossy(&head);
    let code: u16 = status
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    if code != 200 {
        anyhow::bail!("上游 CONNECT 返回 {code}");
    }
    Ok(s)
}

async fn dial_via_socks5(pcfg: &ProxyCfg, target: &str) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(&pcfg.upstream_addr)
        .await
        .map_err(|e| anyhow::anyhow!("连接上游 {} 失败: {e}", pcfg.upstream_addr))?;
    let (u, p) = upstream_creds(pcfg);
    if u.is_some() {
        s.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] == 0xff {
        anyhow::bail!("上游 SOCKS5 握手失败");
    }
    if resp[1] == 0x02 {
        let (u, p) = (u.unwrap_or_default(), p.unwrap_or_default());
        let mut req = vec![0x01, u.len() as u8];
        req.extend_from_slice(u.as_bytes());
        req.push(p.len() as u8);
        req.extend_from_slice(p.as_bytes());
        s.write_all(&req).await?;
        let mut aresp = [0u8; 2];
        s.read_exact(&mut aresp).await?;
        if aresp[1] != 0x00 {
            anyhow::bail!("上游 SOCKS5 认证失败");
        }
    }
    // CONNECT 请求（域名形式）
    let (host, port) = target.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("目标地址格式错误"))?;
    let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("目标端口错误"))?;
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        anyhow::bail!("上游 SOCKS5 CONNECT 失败: {}", hdr[1]);
    }
    // 跳过 BND.ADDR
    let skip = match hdr[3] {
        0x01 => 6,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        0x04 => 18,
        _ => anyhow::bail!("上游返回未知 ATYP"),
    };
    let mut junk = vec![0u8; skip];
    s.read_exact(&mut junk).await?;
    Ok(s)
}

// ============ 中转隧道：TCP 中转 / WebSocket 隧道 ============

async fn run_tunnel(ctx: TaskCtx, spec: EntrySpec) -> anyhow::Result<(Vec<JoinHandle<()>>, String)> {
    let (ttype, local_addr, remote_addr) = match &spec.kind {
        SpecKind::Tunnel { tunnel_type, local_addr, remote_addr } => {
            (tunnel_type.clone(), local_addr.clone(), remote_addr.clone())
        }
        _ => anyhow::bail!("内部错误：隧道任务收到非隧道 spec"),
    };
    // remote 黑名单检查（取 host 部分）
    if let Some(host) = remote_addr.split('/').next().and_then(|h| h.split('@').last()) {
        let host = host.trim_start_matches("ws://").trim_start_matches("wss://");
        let (hip, hport) = match host.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<i64>().unwrap_or(0)),
            None => (host, 0),
        };
        if let Some(reason) = target_blocked(hip, hport, mgmt_port_of(&ctx.cfg)) {
            anyhow::bail!("{reason}");
        }
    }
    match ttype.as_str() {
        "tcp" => {
            let listener = tokio::net::TcpListener::bind(&local_addr)
                .await
                .map_err(|e| anyhow::anyhow!("监听 {local_addr} 失败: {e}"))?;
            let h = tokio::spawn(tunnel_tcp_loop(ctx, listener, remote_addr));
            Ok((vec![h], "running".into()))
        }
        "ws" => {
            let listener = tokio::net::TcpListener::bind(&local_addr)
                .await
                .map_err(|e| anyhow::anyhow!("监听 {local_addr} 失败: {e}"))?;
            let h = tokio::spawn(tunnel_ws_loop(ctx, listener, remote_addr));
            Ok((vec![h], "running".into()))
        }
        other => anyhow::bail!("暂不支持的隧道类型: {other}"),
    }
}

/// TCP 中转：本地监听 → 连接远端 → 双向转发
async fn tunnel_tcp_loop(ctx: TaskCtx, listener: tokio::net::TcpListener, remote_addr: String) {
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            accepted = listener.accept() => {
                let (inbound, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!("隧道 accept 失败: {e}"); continue; }
                };
                let ctx2 = ctx.clone();
                let remote2 = remote_addr.clone();
                tokio::spawn(async move {
                    let started = chrono::Local::now();
                    ctx2.begin_conn();
                    let client_ip = peer.ip().to_string();
                    let (up, down, status) = match tokio::net::TcpStream::connect(&remote2).await {
                        Ok(outbound) => match relay_tcp(inbound, outbound).await {
                            Ok((u, d)) => (u, d, "ok"),
                            Err(_) => (0, 0, "relay_error"),
                        },
                        Err(_) => (0, 0, "remote_refused"),
                    };
                    ctx2.finish_conn(Some(client_ip), started, up, down, status).await;
                });
            }
        }
    }
}

/// WebSocket 隧道：本地 TCP 监听 → 每条连接拨一条 WS 到远端 → TCP 流桥接到 WS 二进制帧
async fn tunnel_ws_loop(ctx: TaskCtx, listener: tokio::net::TcpListener, remote_addr: String) {
    // remote_addr 规范化为 ws:// URL
    let url = if remote_addr.starts_with("ws://") || remote_addr.starts_with("wss://") {
        remote_addr.clone()
    } else {
        format!("ws://{remote_addr}")
    };
    if url.starts_with("wss://") {
        tracing::warn!("隧道 {} 的 wss 远端暂不支持，任务空转", ctx.key.1);
        ctx.cancel.cancelled().await;
        return;
    }
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            accepted = listener.accept() => {
                let (inbound, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => { tracing::warn!("WS 隧道 accept 失败: {e}"); continue; }
                };
                let ctx2 = ctx.clone();
                let url2 = url.clone();
                tokio::spawn(async move {
                    let started = chrono::Local::now();
                    ctx2.begin_conn();
                    let client_ip = peer.ip().to_string();
                    let (up, down, status) = bridge_tcp_ws(inbound, &url2).await;
                    ctx2.finish_conn(Some(client_ip), started, up, down, status).await;
                });
            }
        }
    }
}

async fn bridge_tcp_ws(
    inbound: tokio::net::TcpStream,
    url: &str,
) -> (u64, u64, &'static str) {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;

    let (ws_stream, _) = match tokio_tungstenite::connect_async(url).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("WS 拨号 {url} 失败: {e}");
            return (0, 0, "ws_dial_fail");
        }
    };
    let (mut ws_sink, mut ws_src) = ws_stream.split();
    let (mut tcp_r, mut tcp_w) = inbound.into_split();
    let (mut up, mut down) = (0u64, 0u64);

    // tcp → ws
    let t2w = async {
        let mut buf = [0u8; 16384];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    up += n as u64;
                    if ws_sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = ws_sink.send(Message::Close(None)).await;
    };
    // ws → tcp
    let w2t = async {
        while let Some(msg) = ws_src.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    down += data.len() as u64;
                    if tcp_w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    };
    tokio::join!(t2w, w2t);
    (up, down, "ok")
}

// ============ 条目变更通知入口 ============

/// 条目 CRUD / 启停后调用：触发运行时热更新对齐
pub async fn on_entries_changed(state: &crate::state::AppState) {
    state.runtime.sync().await;
}
