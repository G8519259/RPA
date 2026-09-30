//! P8 —— 运行时状态 API

use actix_web::{HttpResponse, web};

use crate::error::AppResult;
use crate::models::ApiResp;
use crate::state::AppState;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/runtime")
            .route("/status", web::get().to(status))
            .route("/sync", web::post().to(sync)),
    );
}

/// GET /api/runtime/status —— 各条目运行状态与实时计数
pub async fn status(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    let items = state.runtime.status_snapshot().await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "items": items }))))
}

/// POST /api/runtime/sync —— 手动触发热更新对齐
pub async fn sync(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    state.runtime.sync().await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({ "synced": true }))))
}
