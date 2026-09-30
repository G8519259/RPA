//! 公开订阅接口 GET /sub/{token}（文档 §9.4）
//!
//! - 不存在 / 停用 / 过期 → 统一 404（不泄露具体原因）
//! - max_ips 超限 → 403
//! - 同一 IP 每分钟 30 次限速 → 429
//! - 头：Content-Type 由 render 决定；Profile-Update-Interval: 6；Subscription-Userinfo
//! - result 字段：ok / expired / disabled / ip_limit / not_found / rate_limited

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::error::AppResult;
use crate::models::Subscription;
use crate::services::export::render_subscription;
use crate::state::AppState;
use crate::util::{client_ip, now_str};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/sub/{token}", web::get().to(serve));
}

#[derive(Deserialize)]
struct SubQ {
    format: Option<String>,
}

// ============ P13：订阅导出 60 秒内存缓存 ============

/// 缓存 key = (subscription_id, format, template_id, 条目集合版本)
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct SubExportKey {
    pub sub_id: i64,
    pub format: String,
    pub template_id: Option<i64>,
    pub entries_ver: String,
}

#[derive(Clone)]
pub struct CachedExport {
    pub content: String,
    pub content_type: String,
    pub ext: String,
    pub at: std::time::Instant,
}

const EXPORT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const EXPORT_CACHE_MAX: usize = 500;

/// 条目集合版本：任一张条目表 / 订阅本身 / 模板有更新都会变化
async fn entries_version(pool: &sqlx::SqlitePool, sub: &Subscription) -> String {
    let v: Option<String> = sqlx::query_scalar(
        "SELECT MAX(u) FROM (
           SELECT MAX(updated_at) AS u FROM proxy_rules UNION ALL
           SELECT MAX(updated_at) FROM port_forwards UNION ALL
           SELECT MAX(updated_at) FROM tunnels UNION ALL
           SELECT updated_at FROM subscriptions WHERE id = ? UNION ALL
           SELECT MAX(updated_at) FROM sub_templates
         )",
    )
    .bind(sub.id)
    .fetch_one(pool)
    .await
    .unwrap_or(None);
    v.unwrap_or_default()
}

async fn serve(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
    q: web::Query<SubQ>,
) -> AppResult<HttpResponse> {
    let token = path.into_inner();
    let sub: Option<Subscription> = sqlx::query_as("SELECT * FROM subscriptions WHERE token = ?")
        .bind(&token)
        .fetch_optional(&state.pool)
        .await?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let sub = match sub {
        Some(s) => s,
        None => return Ok(plain_404()),
    };
    let fmt = q
        .format
        .as_deref()
        .unwrap_or(&sub.default_format)
        .to_string();

    // 同一 IP 每分钟 30 次限速
    let recent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscription_logs
         WHERE subscription_id = ? AND client_ip = ?
           AND accessed_at > datetime('now', '-1 minute')",
    )
    .bind(sub.id)
    .bind(&ip)
    .fetch_one(&state.pool)
    .await?;
    if recent >= 30 {
        log_access(&state, sub.id, &ip, &user_agent, &fmt, "rate_limited").await;
        return Ok(HttpResponse::TooManyRequests()
            .content_type("text/plain; charset=utf-8")
            .body("请求过于频繁，请稍后再试"));
    }

    // 不存在 / 停用 / 过期 → 统一 404，不泄露具体原因
    let now = now_str();
    if sub.enabled != 1 {
        log_access(&state, sub.id, &ip, &user_agent, &fmt, "disabled").await;
        return Ok(plain_404());
    }
    if let Some(ea) = &sub.expires_at {
        if ea.as_str() < now.as_str() {
            log_access(&state, sub.id, &ip, &user_agent, &fmt, "expired").await;
            return Ok(plain_404());
        }
    }

    // max_ips 检查：24h 内不同 IP（排除当前 IP）>= max_ips → 403
    if let Some(max_ips) = sub.max_ips {
        let ips: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT DISTINCT client_ip FROM subscription_logs
             WHERE subscription_id = ? AND result = 'ok'
               AND accessed_at > datetime('now', '-1 day')",
        )
        .bind(sub.id)
        .fetch_all(&state.pool)
        .await?;
        let others = ips
            .into_iter()
            .flatten()
            .filter(|x| x != &ip)
            .count() as i64;
        if others >= max_ips {
            log_access(&state, sub.id, &ip, &user_agent, &fmt, "ip_limit").await;
            // P12：触发 IP 限制告警（冷却在规则内，默认 1 小时）
            let base = state.cfg.server.public_base_url.clone();
            let _ = crate::services::alert::emit(
                &state.pool,
                crate::services::alert::AlertDraft::sub_ip_limit(sub.id, &sub.name, max_ips, &base),
            )
            .await;
            return Ok(HttpResponse::Forbidden()
                .content_type("text/plain; charset=utf-8")
                .body(format!("该订阅同时在线 IP 数已达上限（{max_ips}）")));
        }
    }

    let rendered = {
        let key = SubExportKey {
            sub_id: sub.id,
            format: fmt.clone(),
            template_id: sub.template_id,
            entries_ver: entries_version(&state.pool, &sub).await,
        };
        let hit = {
            let cache = state.sub_export_cache.lock().await;
            cache.get(&key).filter(|c| c.at.elapsed() < EXPORT_CACHE_TTL).cloned()
        };
        match hit {
            Some(c) => c,
            None => {
                let r = match render_subscription(&state.pool, &sub, &fmt).await {
                    Ok(r) => r,
                    Err(_) => {
                        log_access(&state, sub.id, &ip, &user_agent, &fmt, "render_error").await;
                        return Ok(HttpResponse::BadRequest()
                            .content_type("text/plain; charset=utf-8")
                            .body("订阅渲染失败"));
                    }
                };
                let cached = CachedExport {
                    content: r.content,
                    content_type: r.content_type,
                    ext: r.ext,
                    at: std::time::Instant::now(),
                };
                let mut cache = state.sub_export_cache.lock().await;
                if cache.len() >= EXPORT_CACHE_MAX {
                    // 简单淘汰最旧的一批
                    let mut keys: Vec<_> = cache.iter().map(|(k, v)| (v.at, k.clone())).collect();
                    keys.sort_by_key(|(at, _)| *at);
                    for (_, k) in keys.into_iter().take(EXPORT_CACHE_MAX / 2) {
                        cache.remove(&k);
                    }
                }
                cache.insert(key, cached.clone());
                cached
            }
        }
    };

    // 访问统计 + 日志（失败不影响响应）
    let pool = state.pool.clone();
    let (sid, lip, ua, f) = (sub.id, ip.clone(), user_agent.clone(), fmt.clone());
    tokio::spawn(async move {
        let _ = sqlx::query(
            "UPDATE subscriptions SET access_count = access_count + 1, last_access_at = datetime('now') WHERE id = ?",
        )
        .bind(sid)
        .execute(&pool)
        .await;
        let _ = sqlx::query(
            "INSERT INTO subscription_logs (subscription_id, client_ip, user_agent, format, result) VALUES (?, ?, ?, ?, 'ok')",
        )
        .bind(sid)
        .bind(&lip)
        .bind(ua.chars().take(300).collect::<String>())
        .bind(&f)
        .execute(&pool)
        .await;
    });

    let filename = format!("{}.{}", sanitize_filename(&sub.name), rendered.ext);
    let userinfo = userinfo_header(&state.pool, &sub).await;
    Ok(HttpResponse::Ok()
        .content_type(rendered.content_type)
        .insert_header(("Profile-Update-Interval", "6"))
        .insert_header(("Subscription-Userinfo", userinfo))
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{filename}\""),
        ))
        .body(rendered.content))
}

async fn userinfo_header(pool: &sqlx::SqlitePool, sub: &Subscription) -> String {
    let expire = sub
        .expires_at
        .as_deref()
        .and_then(|s| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc().timestamp())
        })
        .unwrap_or(0);
    // 有配额的条目才计入 upload/download/total（§13.6）
    let refs = crate::services::export::resolve_entries(pool, sub)
        .await
        .unwrap_or_default();
    let mut upload = 0i64;
    let mut download = 0i64;
    let mut total = 0i64;
    for r in &refs {
        let q: Option<(i64, i64)> = sqlx::query_as(
            "SELECT used_bytes, quota_bytes FROM entry_quotas
              WHERE entry_type = ? AND entry_id = ? AND quota_bytes > 0",
        )
        .bind(&r.entry_type)
        .bind(r.entry_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        if let Some((used, quota)) = q {
            download += used;
            total += quota;
        }
    }
    format!("upload={upload}; download={download}; total={total}; expire={expire}")
}

async fn log_access(
    state: &web::Data<AppState>,
    sub_id: i64,
    ip: &str,
    ua: &str,
    fmt: &str,
    result: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO subscription_logs (subscription_id, client_ip, user_agent, format, result) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(sub_id)
    .bind(ip)
    .bind(ua.chars().take(300).collect::<String>())
    .bind(fmt)
    .bind(result)
    .execute(&state.pool)
    .await;
}

fn plain_404() -> HttpResponse {
    HttpResponse::NotFound()
        .content_type("text/plain; charset=utf-8")
        .body("订阅不存在或已失效")
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .chars()
        .take(60)
        .collect()
}
