use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::state::AppState;
use crate::util::verify_password;
use actix_web::{web, HttpRequest, HttpResponse};
use tera::Context;

/// 渲染后台页面（注入通用变量）
pub async fn render(
    state: &AppState,
    req: &HttpRequest,
    tpl: &str,
    active: &str,
    mut ctx: Context,
) -> AppResult<HttpResponse> {
    let user = auth_user(req).ok();
    ctx.insert("active", active);
    ctx.insert(
        "csrf",
        &user.as_ref().map(|u| u.csrf_token.clone()).unwrap_or_default(),
    );
    ctx.insert(
        "username",
        &user.as_ref().map(|u| u.username.clone()).unwrap_or_default(),
    );
    ctx.insert(
        "role",
        &user.as_ref().map(|u| u.role.clone()).unwrap_or_default(),
    );
    ctx.insert(
        "public_base_url",
        &state.cfg.server.public_base_url.trim_end_matches('/'),
    );
    ctx.insert("tz_offset", &state.cfg.time.timezone_offset_hours);
    // 默认密码提示
    let mut is_default = false;
    if let Some(u) = &user {
        let h: Option<String> =
            sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
                .bind(u.id)
                .fetch_optional(&state.pool)
                .await
                .unwrap_or(None);
        if let Some(h) = h {
            is_default = verify_password("ChangeMe123!", &h);
        }
    }
    ctx.insert("is_default_password", &is_default);
    let body = state
        .tera
        .render(tpl, &ctx)
        .map_err(|e| AppError::internal(format!("模板渲染失败: {e}")))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/login", web::get().to(login_page))
        .route("", web::get().to(dashboard))
        .route("/", web::get().to(dashboard))
        .route("/account", web::get().to(account_page))
        .route("/groups", web::get().to(groups_page))
        .route("/tags", web::get().to(tags_page))
        .route("/proxy", web::get().to(proxies_page))
        .route("/forward", web::get().to(forwards_page))
        .route("/tunnel", web::get().to(tunnels_page))
        .route("/subscriptions", web::get().to(subscriptions_page))
        .route("/subscriptions/new", web::get().to(subscriptions_page))
        .route("/templates", web::get().to(templates_page))
        .route("/import", web::get().to(import_page))
        .route("/import/records", web::get().to(import_records_page))
        .route("/logs/audit", web::get().to(logs_audit_page))
        .route("/logs/access", web::get().to(logs_access_page))
        .route("/logs/subscription", web::get().to(logs_subscription_page))
        .route("/stats", web::get().to(stats_page))
        .route("/quotas", web::get().to(quotas_page))
        .route("/alerts", web::get().to(alerts_page))
        .route("/monitor/nodes", web::get().to(monitor_nodes_page))
        .route("/monitor/rules", web::get().to(monitor_rules_page))
        .route("/nodes", web::get().to(nodes_page));
}

async fn login_page(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    let body = state
        .tera
        .render("login.html", &Context::new())
        .map_err(|e| AppError::internal(format!("模板渲染失败: {e}")))?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

async fn dashboard(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/dashboard.html", "dashboard", Context::new()).await
}

async fn account_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/account.html", "account", Context::new()).await
}

async fn groups_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/groups.html", "groups", Context::new()).await
}

async fn tags_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/tags.html", "tags", Context::new()).await
}

async fn proxies_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/proxies.html", "proxies", Context::new()).await
}

async fn forwards_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/forwards.html", "forwards", Context::new()).await
}

async fn tunnels_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/tunnels.html", "tunnels", Context::new()).await
}

async fn subscriptions_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/subscriptions.html", "subscriptions", Context::new()).await
}

async fn templates_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/templates.html", "templates", Context::new()).await
}

async fn import_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/import.html", "import", Context::new()).await
}

async fn import_records_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/import_records.html", "import_records", Context::new()).await
}

async fn logs_audit_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/logs_audit.html", "logs_audit", Context::new()).await
}

async fn logs_access_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/logs_access.html", "logs_access", Context::new()).await
}

async fn logs_subscription_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/logs_subscription.html", "logs_subscription", Context::new()).await
}

async fn stats_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/stats.html", "stats", Context::new()).await
}

async fn nodes_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/nodes.html", "nodes", Context::new()).await
}

async fn quotas_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/quotas.html", "quotas", Context::new()).await
}

async fn alerts_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/alerts.html", "alerts", Context::new()).await
}

async fn monitor_nodes_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/monitor_nodes.html", "monitor_nodes", Context::new()).await
}

async fn monitor_rules_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    render(&state, &req, "admin/monitor_rules.html", "monitor_rules", Context::new()).await
}
