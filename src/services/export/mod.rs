//! P4 订阅导出服务

pub mod base64;
pub mod clash;
pub mod json;
pub mod resolve;
pub mod singbox;
pub mod template;

pub use resolve::resolve_entries;
pub use template::{render_subscription, validate_format};
