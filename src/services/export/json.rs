//! JSON 导出：ExportNode 数组，供自研客户端或脚本使用。不使用模板。

use crate::models::ExportNode;

pub fn render(nodes: &[ExportNode], _sub_name: &str) -> (String, &'static str, &'static str) {
    (
        serde_json::to_string_pretty(&nodes).unwrap_or_default(),
        "application/json; charset=utf-8",
        "json",
    )
}
