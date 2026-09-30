mod audit;
mod cli;
mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;
mod seed;
mod services;
mod state;
mod util;
mod worker;

use actix_files::Files;
use actix_web::{middleware::from_fn, web, App, HttpResponse, HttpServer};
use clap::{Parser, Subcommand};
use state::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "rust_proxy_admin", version)]
struct Args {
    /// 运行模式: master | worker
    #[arg(long, default_value = "master")]
    mode: String,
    /// Worker 模式: Master 地址，如 https://admin.example.com
    #[arg(long)]
    master: Option<String>,
    /// Worker 模式: 节点 api_token
    #[arg(long)]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 重置用户密码（旧会话全部失效）
    ResetPassword {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = config::Config::load("config.toml")?;

    if let Some(Cmd::ResetPassword { username, password }) = args.cmd {
        return cli::reset_password(&cfg.db.url, &username, &password).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cfg.log.level).unwrap_or_else(|_| "info".into()),
        )
        .init();

    match args.mode.as_str() {
        "worker" => {
            let master = args.master.ok_or_else(|| anyhow::anyhow!("worker 模式需要 --master"))?;
            let token = args.token.ok_or_else(|| anyhow::anyhow!("worker 模式需要 --token"))?;
            worker::run_worker(cfg, master, token).await
        }
        _ => run_master(cfg).await,
    }
}

async fn run_master(cfg: config::Config) -> anyhow::Result<()> {
    std::fs::create_dir_all("data").ok();

    let pool = db::connect(&cfg.db.url).await?;
    db::migrate(&pool).await?;
    seed::ensure_seed(&pool, &cfg).await?;

    let tera = tera::Tera::new("templates/**/*").unwrap_or_default();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let runtime = crate::services::runtime::RuntimeManager::new(pool.clone(), cfg.clone());

    let state = AppState {
        pool,
        cfg: cfg.clone(),
        tera,
        http,
        login_guard: Arc::new(Mutex::new(middleware::LoginGuard::default())),
        import_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        sub_export_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        runtime: runtime.clone(),
    };

    // P8：初始同步运行时（启动已有启用条目的监听）
    runtime.sync().await;

    // 后台任务：日志清理（P7）
    {
        let pool = state.pool.clone();
        let log_cfg = cfg.log.clone();
        tokio::spawn(async move {
            crate::services::cleaner::run_cleaner(pool, log_cfg).await;
        });
    }

    // P9：统计聚合 + 本机指标采集
    {
        crate::services::aggregator::spawn_aggregator(state.pool.clone());
        crate::services::aggregator::spawn_metrics(state.pool.clone(), runtime.clone());
    }

    // P11：生命周期任务（到期/配额/自动停用/即将到期），每 60 秒一轮
    {
        let pool = state.pool.clone();
        let lc = cfg.lifecycle.clone();
        let tz = cfg.time.timezone_offset_hours;
        let base = cfg.server.public_base_url.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::services::lifecycle::lifecycle_tick(&pool, &lc, tz, &base).await {
                tracing::warn!("生命周期任务失败: {e:#}");
            }
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                lc.tick_secs.max(10) as u64,
            ));
            loop {
                tick.tick().await;
                if let Err(e) = crate::services::lifecycle::lifecycle_tick(&pool, &lc, tz, &base).await {
                    tracing::warn!("生命周期任务失败: {e:#}");
                }
            }
        });
    }

    // P12：告警投递器（每 10 秒一轮）+ 节点离线巡检（每 15 秒一轮）
    {
        let pool = state.pool.clone();
        let http = state.http.clone();
        let sk = cfg.server.secret_key.clone();
        tokio::spawn(async move {
            crate::services::alert::dispatcher_loop(pool, http, sk).await;
        });
    }
    {
        let pool = state.pool.clone();
        let tz = cfg.time.timezone_offset_hours;
        let base = cfg.server.public_base_url.clone();
        let hb_timeout = cfg.nodes.heartbeat_timeout_secs;
        tokio::spawn(async move {
            crate::services::node_watch::node_watch_loop(pool, tz, base, hb_timeout).await;
        });
    }

    // P0 验收：能启动并建库；后台任务在后续阶段接入
    tracing::info!("RustProxyAdmin 启动，监听 {}", cfg.server.bind);
    let bind = cfg.server.bind.clone();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(from_fn(middleware::auth_middleware))
            .route("/health", web::get().to(|| async { HttpResponse::Ok().body("ok") }))
            .service(Files::new("/static", "./static").prefer_utf8(true))
            .configure(handlers::routes)
    })
    .bind(&bind)?
    .run()
    .await?;
    Ok(())
}

