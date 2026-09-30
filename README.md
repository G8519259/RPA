# RustProxyAdmin v7

多节点代理/端口转发/隧道管理面板（Rust + actix-web + SQLite）。

## 构建

```bash
# 需要 Rust 1.88+
cargo build --release
```

## 运行

```bash
# 复制并修改配置
cp config.toml config.local.toml   # 按需修改 [server]/[auth] 等
./target/release/rust_proxy_admin
# 浏览器访问 http://127.0.0.1:8080/admin
```

常用环境变量覆盖（`RPA__` 前缀 + `__` 分隔层级）：

- `RPA__SERVER__BIND=127.0.0.1:8080`
- `RPA__DB__URL=sqlite://data/rust_proxy_admin.db`
- `RPA__SERVER__SECRET_KEY=...`（渠道密钥 AES-256-GCM 加密密钥，不设则明文存储）
- `RPA__AUTH__USERNAME` / `RPA__AUTH__PASSWORD`（初始管理员）

## 其他命令

```bash
./target/release/rust_proxy_admin reset-password --username admin --password '新密码'
```

完整功能说明见需求文档 `RustProxyAdmin______v7.md`（P0–P13）。
