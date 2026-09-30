//! P6 —— 订阅导入 API（§10）

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use actix_web::HttpRequest;

use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::middleware::auth_user;
use crate::models::ApiResp;
use crate::services::importer::{CachedParse, fetch, mark_duplicates, parse_content, take_cached};
use crate::state::AppState;
use crate::util::client_ip;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/import")
            .route("/parse", web::post().to(parse))
            .route("/confirm", web::post().to(confirm))
            .route("/records", web::get().to(records_list))
            .route("/records/{id}", web::get().to(record_detail))
            .route("/records/{id}", web::delete().to(record_delete)),
    );
}

// ============ POST /api/import/parse ============

#[derive(Debug, Deserialize)]
pub struct ParseReq {
    pub url: Option<String>,
    pub content: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ParseOut {
    pub parse_token: String,
    pub source_type: String,
    pub nodes: Vec<serde_json::Value>,
}

pub async fn parse(
    state: web::Data<AppState>,
    body: web::Json<ParseReq>,
) -> AppResult<HttpResponse> {
    let url = body.url.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let content = body
        .content
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if url.is_none() && content.is_none() {
        return Err(AppError::bad("请提供订阅 URL 或粘贴内容"));
    }
    let text = match url {
        Some(u) => {
            fetch::fetch_subscription(&state.http, u, &state.cfg.import.user_agent).await?
        }
        None => content.unwrap().to_string(),
    };
    let (source_type, mut nodes) = parse_content(&text)?;
    mark_duplicates(&state.pool, &mut nodes).await?;

    let token = Uuid::new_v4().to_string();
    let cached = CachedParse {
        nodes: nodes.clone(),
        source_url: url.map(str::to_string),
        source_type: source_type.clone(),
        created: std::time::Instant::now(),
    };
    state.import_cache.lock().await.insert(token.clone(), cached);

    let out: Vec<serde_json::Value> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            serde_json::json!({
                "index": i, "name": n.name, "kind": n.kind,
                "host": n.host, "port": n.port, "duplicate": n.duplicate,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(ApiResp::ok(ParseOut {
        parse_token: token,
        source_type,
        nodes: out,
    })))
}

// ============ POST /api/import/confirm ============

#[derive(Debug, Deserialize)]
pub struct ConfirmReq {
    pub parse_token: String,
    pub target_node_id: i64,
    pub selected: Option<Vec<usize>>,
    pub name_prefix: Option<String>,
}

pub async fn confirm(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<ConfirmReq>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let cached = take_cached(&state.import_cache, &body.parse_token)
        .await
        .ok_or_else(|| AppError::bad("解析结果已过期，请重新解析"))?;

    let node_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM nodes WHERE id = ?)")
        .bind(body.target_node_id)
        .fetch_one(&state.pool)
        .await?;
    if !node_exists {
        return Err(AppError::bad("目标节点不存在"));
    }

    // 选择：None = 全部；否则按下标过滤（去重、越界检查）
    let parsed = &cached.nodes;
    let mut idx_set = std::collections::BTreeSet::new();
    match &body.selected {
        None => {
            for i in 0..parsed.len() {
                idx_set.insert(i);
            }
        }
        Some(idx) => {
            for &i in idx {
                if i < parsed.len() {
                    idx_set.insert(i);
                }
            }
        }
    }
    if idx_set.is_empty() {
        return Err(AppError::bad("未选择任何节点"));
    }

    let prefix = body
        .name_prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let mut tx = state.pool.begin().await?;

    // 1) 先创建导入记录，拿到 id
    let record_id: i64 = sqlx::query_scalar(
        "INSERT INTO import_records
           (user_id, source_url, source_type, target_node_id, parsed_count, imported_count)
         VALUES (?, ?, ?, ?, ?, 0) RETURNING id",
    )
    .bind(user.id)
    .bind(cached.source_url.as_deref())
    .bind(&cached.source_type)
    .bind(body.target_node_id)
    .bind(parsed.len() as i64)
    .fetch_one(&mut *tx)
    .await?;

    // 2) 逐条插入 proxy_rules，写入 source_import_id；重复项跳过
    let (mut ok, mut skipped) = (0i64, 0i64);
    for i in idx_set {
        let n = &parsed[i];
        let addr = format!("{}:{}", n.host, n.port);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM proxy_rules WHERE upstream_type = ? AND upstream_addr = ?)",
        )
        .bind(&n.kind)
        .bind(&addr)
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            skipped += 1;
            continue;
        }
        let name = if prefix.is_empty() {
            n.name.clone()
        } else {
            format!("{prefix}{}", n.name)
        };
        sqlx::query(
            "INSERT INTO proxy_rules
               (node_id, name, upstream_type, upstream_addr,
                auth_user, auth_pass, extra, source_import_id, enabled)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
        )
        .bind(body.target_node_id)
        .bind(name)
        .bind(&n.kind)
        .bind(&addr)
        .bind(n.username.as_deref())
        .bind(n.password.as_deref())
        .bind(serde_json::to_string(&n.extra).ok())
        .bind(record_id)
        .execute(&mut *tx)
        .await?;
        ok += 1;
    }

    // 3) 回写导入数量
    sqlx::query("UPDATE import_records SET imported_count = ? WHERE id = ?")
        .bind(ok)
        .bind(record_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    audit(
        &state.pool, Some(user.id), &user.username, "import_confirm",
        Some("import_records"), Some(record_id), None,
        serde_json::json!({"imported": ok, "skipped": skipped}), &ip,
    )
    .await;

    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "record_id": record_id, "imported": ok, "skipped": skipped,
    }))))
}

// ============ GET /api/import/records ============

#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

pub async fn records_list(
    state: web::Data<AppState>,
    q: web::Query<RecordsQuery>,
) -> AppResult<HttpResponse> {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_records")
        .fetch_one(&state.pool)
        .await?;
    let rows: Vec<serde_json::Value> = sqlx::query_as::<
        _,
        (
            i64,
            Option<i64>,
            Option<String>,
            String,
            Option<i64>,
            i64,
            i64,
            String,
            Option<String>,
        ),
    >(
        "SELECT r.id, r.user_id, r.source_url, r.source_type, r.target_node_id,
                r.parsed_count, r.imported_count, r.created_at, n.name
         FROM import_records r LEFT JOIN nodes n ON n.id = r.target_node_id
         ORDER BY r.id DESC LIMIT ? OFFSET ?",
    )
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|(id, uid, url, stype, nid, pc, ic, ca, nname)| {
        serde_json::json!({
            "id": id, "user_id": uid, "source_url": url, "source_type": stype,
            "target_node_id": nid, "target_node_name": nname,
            "parsed_count": pc, "imported_count": ic, "created_at": ca,
        })
    })
    .collect();
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "total": total, "page": page, "page_size": page_size, "items": rows,
    }))))
}

// ============ GET /api/import/records/{id} ============

pub async fn record_detail(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> AppResult<HttpResponse> {
    let id = path.into_inner();
    let rec: Option<serde_json::Value> = sqlx::query_as::<
        _,
        (
            i64,
            Option<i64>,
            Option<String>,
            String,
            Option<i64>,
            i64,
            i64,
            String,
            Option<String>,
        ),
    >(
        "SELECT r.id, r.user_id, r.source_url, r.source_type, r.target_node_id,
                r.parsed_count, r.imported_count, r.created_at, n.name
         FROM import_records r LEFT JOIN nodes n ON n.id = r.target_node_id
         WHERE r.id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .map(|(rid, uid, url, stype, nid, pc, ic, ca, nname)| {
        serde_json::json!({
            "id": rid, "user_id": uid, "source_url": url, "source_type": stype,
            "target_node_id": nid, "target_node_name": nname,
            "parsed_count": pc, "imported_count": ic, "created_at": ca,
        })
    });
    let rec = rec.ok_or_else(|| AppError::not_found("导入记录不存在"))?;
    let entries: Vec<serde_json::Value> = sqlx::query_as::<_, (i64, String, String, String, i64)>(
        "SELECT id, name, upstream_type, upstream_addr, enabled FROM proxy_rules
         WHERE source_import_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|(eid, name, kind, addr, en)| {
        serde_json::json!({
            "id": eid, "name": name, "upstream_type": kind,
            "upstream_addr": addr, "enabled": en,
        })
    })
    .collect();
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "record": rec, "entries": entries,
    }))))
}

// ============ DELETE /api/import/records/{id} ============

#[derive(Debug, Deserialize)]
pub struct RecordDeleteQuery {
    #[serde(default)]
    pub with_entries: Option<String>,
}

impl RecordDeleteQuery {
    fn with_entries(&self) -> bool {
        matches!(self.with_entries.as_deref(), Some("1") | Some("true"))
    }
}

pub async fn record_delete(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    q: web::Query<RecordDeleteQuery>,
) -> AppResult<HttpResponse> {
    let user = auth_user(&req)?;
    let id = path.into_inner();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM import_records WHERE id = ?)")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    if !exists {
        return Err(AppError::not_found("导入记录不存在"));
    }
    let mut tx = state.pool.begin().await?;
    let mut deleted_entries = 0i64;
    if q.with_entries() {
        // 连带删除：先找出该记录导入的条目，用统一删除函数清理多态关联
        let ids: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM proxy_rules WHERE source_import_id = ?")
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        if !ids.is_empty() {
            deleted_entries =
                crate::handlers::entries_common::delete_entries_tx(&mut tx, "proxy", &ids).await? as i64;
        }
    } else {
        // 仅删记录：条目保留，source_import_id 置空
        sqlx::query("UPDATE proxy_rules SET source_import_id = NULL WHERE source_import_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM import_records WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let ip = client_ip(&req, &state.cfg.server.trusted_proxies);
    audit(
        &state.pool, Some(user.id), &user.username, "import_record_delete",
        Some("import_records"), Some(id), None,
        serde_json::json!({"with_entries": q.with_entries(), "deleted_entries": deleted_entries}), &ip,
    )
    .await;
    Ok(HttpResponse::Ok().json(ApiResp::ok(serde_json::json!({
        "deleted_entries": deleted_entries,
    }))))
}
