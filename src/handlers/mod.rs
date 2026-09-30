pub mod alerts;
pub mod auth;
pub mod entries_common;
pub mod forward;
pub mod groups_tags;
pub mod import;
pub mod internal;
pub mod logs;
pub mod metrics;
pub mod monitor;
pub mod nodes;
pub mod pages;
pub mod proxy;
pub mod quotas;
pub mod runtime;
pub mod stats;
pub mod subscribe_public;
pub mod subscriptions;
pub mod templates;
pub mod tunnel;
pub mod users;

use actix_web::web;

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/auth").configure(auth::routes));
    cfg.service(web::scope("/api/proxy").configure(proxy::routes));
    cfg.service(web::scope("/api/forward").configure(forward::routes));
    cfg.service(web::scope("/api/tunnel").configure(tunnel::routes));
    cfg.service(web::scope("/api/entries").configure(entries_common::entries_routes));
    cfg.service(web::scope("/api/groups").configure(groups_tags::group_routes));
    cfg.service(web::scope("/api/tags").configure(groups_tags::tag_routes));
    cfg.configure(subscriptions::routes);
    cfg.configure(subscribe_public::routes);
    cfg.configure(templates::routes);
    cfg.configure(import::routes);
    cfg.configure(logs::routes);
    cfg.configure(runtime::routes);
    cfg.configure(stats::routes);
    cfg.configure(monitor::routes);
    cfg.configure(nodes::routes);
    cfg.configure(quotas::routes);
    cfg.configure(alerts::routes);
    cfg.configure(users::routes);
    cfg.configure(metrics::routes);
    cfg.configure(internal::routes);
    // P6–P13 在后续阶段接入
    cfg.service(web::scope("/admin").configure(pages::routes));
}
