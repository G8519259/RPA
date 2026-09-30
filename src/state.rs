use crate::config::Config;
use crate::middleware::LoginGuard;
use sqlx::SqlitePool;
use std::sync::Arc;
use tera::Tera;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub cfg: Config,
    pub tera: Tera,
    pub http: reqwest::Client,
    /// 登录失败计数（IP 维度防爆破）
    pub login_guard: Arc<Mutex<LoginGuard>>,
    /// 导入解析缓存（parse_token → 解析结果，10 分钟过期）
    pub import_cache: Arc<Mutex<std::collections::HashMap<String, crate::services::importer::CachedParse>>>,
    /// P13：订阅导出缓存（60 秒，key 含条目集合版本）
    pub sub_export_cache: Arc<
        Mutex<
            std::collections::HashMap<
                crate::handlers::subscribe_public::SubExportKey,
                crate::handlers::subscribe_public::CachedExport,
            >,
        >,
    >,
    /// P8 运行时管理器（转发/代理/隧道任务）
    pub runtime: Arc<crate::services::runtime::RuntimeManager>,
}
