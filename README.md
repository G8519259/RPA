![image.png](https://img.111451444.xyz/files/QWdBRFlpZ0FBa1Q4NkZVOrYC_BX5ctu6ok-_68Jt91W-6MV1ltfuclHyluB7QBnu.png)
![image.png](https://img.111451444.xyz/files/QWdBRDJCOEFBcUFfNkZVOgMSgD9ooetHuvSZbdqv66lBJ-9MkCdsiiAGNbHJ4IBh.png)
![image.png](https://img.111451444.xyz/files/QWdBRElDTUFBZzRjNlZVOswtQVSGZYaX8731J65TGFpSeAlWOpUIdWGCjw37aBCy.png)

# RustProxyAdmin v7

多节点代理 / 端口转发 / 隧道管理面板（Rust + actix-web + SQLite），带订阅分发、流量配额、告警中心与 Web 管理后台。

## 功能一览

- **条目管理**：落地代理（socks5 / http / ss）、端口转发（tcp / udp）、中转隧道（relay+tls / ws / wss），支持分组、标签、批量操作
- **多节点**：Master + Worker 架构，节点心跳监控、配置自动下发、流量上报
- **订阅分发**：为每条订阅生成 token 链接，支持 clash / sing-box / v2ray / ss / base64 等多种输出格式与自定义模板
- **导入订阅**：从 URL 导入第三方订阅并解析成条目，导入记录可查
- **流量配额与生命周期**：按条目/订阅设置流量配额与到期时间，超限或到期自动停用，支持手动延期/恢复、月度配额重置
- **统计**：流量、连接数、在线节点、Top 条目（近 7 天）、节点/条目监控
- **日志**：操作日志、访问日志、订阅访问日志，均可检索
- **告警中心**：节点离线、配额预警、到期提醒；通知渠道支持 Telegram Bot / Webhook（HMAC 签名）/ SMTP 邮件，失败自动退避重试
- **多用户**：admin / viewer 角色，viewer 只读；渠道密钥 AES-256-GCM 加密存储
- **可观测**：Prometheus `/metrics` 端点




## 快速开始

### 1. 构建

需要 Rust 1.88+：

```bash
cargo build --release
# 二进制位于 ./target/release/rust_proxy_admin
```

### 2. 配置

复制 `config.toml` 按需修改（见下节），或直接用环境变量覆盖：

```bash
RPA__SERVER__BIND=127.0.0.1:8080 \
RPA__DB__URL="sqlite://data/data.db" \
RPA__SERVER__SECRET_KEY="换成你自己的随机密钥" \
./target/release/rust_proxy_admin
```

> 环境变量规则：`RPA__` 前缀 + `__` 分隔层级，例如 `RPA__AUTH__INIT_PASSWORD` 对应 `[auth] init_password`。
> 首次启动会自动创建管理员账号（`[auth] init_username` / `init_password`），**上线前务必修改默认密码**。

### 3. 打开后台

浏览器访问 `http://127.0.0.1:8080/admin`，用管理员账号登录。

## 配置说明（config.toml）

| 段 | 关键项 | 说明 |
|---|---|---|
| `[server]` | `bind` | 监听地址，如 `0.0.0.0:8080` |
| | `public_base_url` | 对外访问地址，用于生成订阅链接 |
| | `secret_key` | 渠道密钥加密密钥（AES-256-GCM），不设则明文存储密钥 |
| | `session_hours` / `cookie_secure` | 会话有效期 / 是否仅 HTTPS 传输 Cookie |
| `[db]` | `url` | SQLite 路径，如 `sqlite://data/data.db` |
| `[auth]` | `init_username` / `init_password` | 初始管理员（仅首次启动时创建） |
| | `login_max_fail` / `login_lock_minutes` | 登录失败锁定策略 |
| `[time]` | `timezone_offset_hours` | 时区偏移（默认 8，东八区），影响配额重置与到期判断 |
| `[nodes]` | `heartbeat_timeout_secs` | 心跳超时秒数，超限判节点离线并可触发告警 |
| `[subscription]` | `rate_limit_per_min` | 订阅接口每分钟限流 |
| `[alerts]` | `dispatch_interval_secs` / `max_attempts` | 告警投递间隔 / 最大重试次数 |
| `[lifecycle]` | `tick_secs` | 到期/配额检查周期 |

数据库迁移在启动时自动执行（`migrations/`）。

## Worker 节点接入

1. 在后台「服务器节点」页新建节点，拿到该节点的 **api_token**。
2. 在节点机器上运行：

```bash
./rust_proxy_admin --mode worker \
  --master https://admin.example.com \
  --token <节点的 api_token>
```

Worker 会自动向 Master 注册心跳、拉取属于自己的条目配置并启动监听，上报流量与负载。

## 后台使用指南

| 页面 | 用途 |
|---|---|
| 仪表盘 | 今日/昨日流量、连接数、在线节点、Top 条目、提醒一览 |
| 落地代理 / 端口转发 / 中转隧道 | 条目的增删改查、启用/停用、批量操作、到期与配额设置 |
| 分组与标签 | 条目分组、标签管理 |
| 服务器节点 / 节点监控 / 条目监控 | 节点状态、心跳、流量监控 |
| 操作日志 / 访问日志 / 订阅访问日志 | 审计与排查 |
| 统计 | 流量趋势与汇总 |
| 订阅管理 | 创建订阅、复制订阅链接、查看访问统计 |
| 输出模板 | 自定义订阅输出模板（变量替换/正则处理） |
| 导入订阅 / 导入记录 | 从 URL 导入第三方订阅 |
| 流量配额 | 配额总览 |
| 告警中心 | 通知渠道、告警规则、事件历史 |
| 账户设置 | 修改密码、多用户管理（admin 可增删用户、重置他人密码） |

## 订阅分发

在「订阅管理」新建订阅并勾选要包含的条目/分组，得到形如：

```
http://<public_base_url>/sub/<token>?format=clash
```

- `format` 可选：`clash` / `sing-box` / `v2ray` / `ss` / `base64` 等（可用模板自定义）
- 订阅支持到期时间与流量配额；超限/到期自动停用并返回提示
- 响应带 `Subscription-Userinfo` 头（upload/download/total/expire），客户端可显示剩余流量
- 订阅输出有 60 秒服务端缓存，高频刷新不打爆数据库

## 告警配置

1. 「告警中心 → 通知渠道」新建渠道：
   - **Telegram**：填 Bot Token 与 Chat ID（支持 socks5 代理）
   - **Webhook**：填 URL 与签名密钥，投递时带 HMAC-SHA256 签名
   - **SMTP**：填服务器、账号、收件人
   - 渠道密钥入库前 AES-256-GCM 加密（需配置 `[server] secret_key`）
2. 「告警规则」新建规则：选择事件类型（节点离线 / 配额预警 / 到期提醒 / 条目异常）、阈值、冷却时间，绑定渠道。
3. 「事件历史」查看 pending / sent / failed 状态；投递失败按 60s / 120s / 240s / 480s 退避重试，5 次后标记失败。

## 多用户与权限

- `admin`：全部权限，可管理用户。
- `viewer`：只读，所有写接口返回 403；订阅 token 与渠道密钥对 viewer 不可见。
- 在「账户设置」中增删用户、重置密码（重置后该用户所有会话立即失效）。
- 禁止删除自己、禁止把自己降级、禁止删除最后一个 admin。

## 安全建议

- 修改 `[auth] init_password` 默认密码；生产环境设置 `[server] cookie_secure = true` 并使用 HTTPS。
- 设置 `[server] secret_key`（或 `RPA__SERVER__SECRET_KEY`），使渠道密钥加密存储；**更换密钥前先备份数据库**。
- 如需公网暴露，建议放在反向代理后并配置 `[server] trusted_proxies`。
- 忘记密码时可用命令行重置（旧会话全部失效）：
  ```bash
  ./target/release/rust_proxy_admin reset-password --username admin --password '新密码'
  ```

## 常用接口

- 管理后台：`GET /admin`
- Prometheus 指标（需登录）：`GET /metrics`
- 订阅拉取：`GET /sub/<token>?format=clash`

## 目录结构

```
src/            # Rust 源码（handlers / services / models / worker …）
templates/      # Tera 模板（管理后台页面）
static/         # CSS / JS
migrations/     # SQLite 迁移（启动自动执行）
config.toml     # 默认配置
```

## 排错

- 端口被占用：改 `[server] bind` 或 `RPA__SERVER__BIND`。
- Worker 连不上 Master：检查 `--master` 地址与节点 `api_token` 是否正确，Master 日志看握手报错。
- 订阅返回空：检查订阅是否过期/超配额，或条目是否被停用。
- 页面数据不加载：打开浏览器开发者工具看 Console 与 Network 的报错信息。
