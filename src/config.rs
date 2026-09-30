use serde::Deserialize;

fn d_bind() -> String {
    "0.0.0.0:8080".into()
}
fn d_db() -> String {
    "sqlite://data/data.db".into()
}
fn d_true() -> bool {
    true
}
fn d_session_hours() -> i64 {
    24
}
fn d_tz() -> i64 {
    8
}
fn d_rate() -> i64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerCfg,
    #[serde(default)]
    pub db: DbCfg,
    #[serde(default)]
    pub auth: AuthCfg,
    #[serde(default)]
    pub time: TimeCfg,
    #[serde(default)]
    pub log: LogCfg,
    #[serde(default)]
    pub stats: StatsCfg,
    #[serde(default)]
    pub nodes: NodesCfg,
    #[serde(default)]
    pub subscription: SubCfg,
    #[serde(default)]
    pub import: ImportCfg,
    #[serde(default)]
    pub templates: TplCfg,
    #[serde(default)]
    pub lifecycle: LifecycleCfg,
    #[serde(default)]
    pub alerts: AlertsCfg,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerCfg {
    #[serde(default = "d_bind")]
    pub bind: String,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "d_session_hours")]
    pub session_hours: i64,
    #[serde(default)]
    pub cookie_secure: bool,
    #[serde(default)]
    pub public_base_url: String,
    /// P13：告警渠道密钥 AES-256-GCM 加密密钥（未配置则渠道密钥明文存储）
    #[serde(default)]
    pub secret_key: Option<String>,
}
impl Default for ServerCfg {
    fn default() -> Self {
        Self {
            bind: d_bind(),
            trusted_proxies: vec!["127.0.0.1".into()],
            session_hours: 24,
            cookie_secure: false,
            public_base_url: "http://127.0.0.1:8080".into(),
            secret_key: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbCfg {
    #[serde(default = "d_db")]
    pub url: String,
}
impl Default for DbCfg {
    fn default() -> Self {
        Self { url: d_db() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthCfg {
    #[serde(default)]
    pub init_username: String,
    #[serde(default)]
    pub init_password: String,
    #[serde(default = "d_rate")]
    pub login_max_fail: i64,
    #[serde(default)]
    pub login_lock_minutes: i64,
}
impl Default for AuthCfg {
    fn default() -> Self {
        Self {
            init_username: "admin".into(),
            init_password: "ChangeMe123!".into(),
            login_max_fail: 5,
            login_lock_minutes: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TimeCfg {
    #[serde(default = "d_tz")]
    pub timezone_offset_hours: i64,
}
impl Default for TimeCfg {
    fn default() -> Self {
        Self {
            timezone_offset_hours: 8,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogCfg {
    #[serde(default)]
    pub level: String,
    #[serde(default = "d_true")]
    pub access_log_enabled: bool,
    #[serde(default)]
    pub access_log_sample_rate: f64,
    #[serde(default)]
    pub access_log_retention_days: i64,
    #[serde(default)]
    pub audit_log_retention_days: i64,
    #[serde(default)]
    pub subscription_log_retention_days: i64,
}
impl Default for LogCfg {
    fn default() -> Self {
        Self {
            level: "info".into(),
            access_log_enabled: true,
            access_log_sample_rate: 1.0,
            access_log_retention_days: 14,
            audit_log_retention_days: 180,
            subscription_log_retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatsCfg {
    #[serde(default)]
    pub aggregate_interval_secs: i64,
    #[serde(default)]
    pub hourly_retention_days: i64,
    #[serde(default)]
    pub daily_retention_days: i64,
}
impl Default for StatsCfg {
    fn default() -> Self {
        Self {
            aggregate_interval_secs: 60,
            hourly_retention_days: 60,
            daily_retention_days: 730,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodesCfg {
    #[serde(default)]
    pub heartbeat_interval_secs: i64,
    #[serde(default)]
    pub heartbeat_timeout_secs: i64,
    #[serde(default)]
    pub config_pull_interval_secs: i64,
    #[serde(default)]
    pub report_interval_secs: i64,
}
impl Default for NodesCfg {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 10,
            heartbeat_timeout_secs: 30,
            config_pull_interval_secs: 15,
            report_interval_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubCfg {
    #[serde(default = "d_rate")]
    pub rate_limit_per_min: i64,
    #[serde(default)]
    pub default_expire_preset: String,
}
impl Default for SubCfg {
    fn default() -> Self {
        Self {
            rate_limit_per_min: 30,
            default_expire_preset: "30d".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportCfg {
    #[serde(default)]
    pub fetch_timeout_secs: i64,
    #[serde(default)]
    pub max_body_mb: i64,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub parse_cache_minutes: i64,
}
impl Default for ImportCfg {
    fn default() -> Self {
        Self {
            fetch_timeout_secs: 15,
            max_body_mb: 5,
            user_agent: "RustProxyAdmin/1.0".into(),
            parse_cache_minutes: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TplCfg {
    #[serde(default)]
    pub max_size_kb: i64,
    #[serde(default)]
    pub regex_max_len: i64,
}
impl Default for TplCfg {
    fn default() -> Self {
        Self {
            max_size_kb: 256,
            regex_max_len: 200,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LifecycleCfg {
    #[serde(default)]
    pub tick_secs: i64,
    #[serde(default)]
    pub expired_sub_cleanup_days: i64,
}
impl Default for LifecycleCfg {
    fn default() -> Self {
        Self {
            tick_secs: 60,
            expired_sub_cleanup_days: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertsCfg {
    #[serde(default)]
    pub dispatch_interval_secs: i64,
    #[serde(default)]
    pub max_attempts: i64,
    #[serde(default)]
    pub node_check_interval_secs: i64,
    #[serde(default)]
    pub event_retention_days: i64,
}
impl Default for AlertsCfg {
    fn default() -> Self {
        Self {
            dispatch_interval_secs: 10,
            max_attempts: 5,
            node_check_interval_secs: 15,
            event_retention_days: 60,
        }
    }
}

impl Config {
    /// 从 config.toml 读取；环境变量 RPA__SECTION__KEY 可覆盖。
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let mut cfg: Config = match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e.into()),
        };
        // 环境变量覆盖（仅覆盖常用项）
        macro_rules! ov {
            ($env:expr, $set:expr) => {
                if let Ok(v) = std::env::var($env) {
                    $set(v);
                }
            };
        }
        ov!("RPA__SERVER__BIND", |v: String| cfg.server.bind = v);
        ov!("RPA__SERVER__PUBLIC_BASE_URL", |v: String| {
            cfg.server.public_base_url = v
        });
        ov!("RPA__SERVER__COOKIE_SECURE", |v: String| {
            cfg.server.cookie_secure = v == "1" || v.eq_ignore_ascii_case("true")
        });
        ov!("RPA__SERVER__SECRET_KEY", |v: String| {
            cfg.server.secret_key = if v.trim().is_empty() { None } else { Some(v) }
        });
        ov!("RPA__DB__URL", |v: String| cfg.db.url = v);
        ov!("RPA__AUTH__INIT_USERNAME", |v: String| {
            cfg.auth.init_username = v
        });
        ov!("RPA__AUTH__INIT_PASSWORD", |v: String| {
            cfg.auth.init_password = v
        });
        ov!("RPA__TIME__TIMEZONE_OFFSET_HOURS", |v: String| {
            if let Ok(n) = v.parse() {
                cfg.time.timezone_offset_hours = n
            }
        });
        ov!("RPA__LOG__LEVEL", |v: String| cfg.log.level = v);
        Ok(cfg)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerCfg::default(),
            db: DbCfg::default(),
            auth: AuthCfg::default(),
            time: TimeCfg::default(),
            log: LogCfg::default(),
            stats: StatsCfg::default(),
            nodes: NodesCfg::default(),
            subscription: SubCfg::default(),
            import: ImportCfg::default(),
            templates: TplCfg::default(),
            lifecycle: LifecycleCfg::default(),
            alerts: AlertsCfg::default(),
        }
    }
}
