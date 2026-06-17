# qp2p �?QUIC P2P 边缘节点代理

> 基于 QUIC 协议�?P2P 打洞网络，通过 Cloudflare Worker 作为信令通道和隧道回落，�?NAT 后的节点之间建立加密直连�?
```
节点 A  ──── QUIC 打洞 ────�? 节点 B
  �?                             �?  └──── Cloudflare Tunnel ──────�?         （信�?+ 回落中继�?```

## 目录

- [架构概览](#架构概览)
- [组件说明](#组件说明)
- [快速开始](#快速开�?
- [配置参考](#配置参�?
- [Worker 部署](#worker-部署)
- [qp2p 部署](#qp2p-部署)
- [连接流程](#连接流程)
- [API 参考](#api-参�?
- [CDN 分发](#cdn-分发)
- [TUN 虚拟网卡](#tun-虚拟网卡)
- [平台支持](#平台支持)
- [开发与测试](#开发与测试)

---

## 架构概览

```
┌─────────────────────────────────────────────────────────�?�?                  Cloudflare 网络                        �?�?                                                         �?�?  ┌──────────────────────────────────────────────────�? �?�?  �? Worker (信令服务)                                �? �?�?  �? �?POST /token     换取 Bearer Token             �? �?�?  �? �?POST /register  节点注册 / 心跳续约            �? �?�?  �? �?POST /connect   发起打洞，推送通知给对�?      �? �?�?  �? D1 数据库存储节点状�?                           �? �?�?  └──────────────────────────────────────────────────�? �?�?          �?Bearer Token 鉴权                            �?└───────────┼──────────────────────────────────────────────�?            �?HTTPS
    ┌───────┴────────────────────────────────────�?    �?        cloudflared Tunnel                  �?    �? �?暴露本地 HTTP 服务到公�?HTTPS endpoint  �?    �? �?接收 Worker 推送的打洞通知 POST /notify  �?    └────────────┬───────────────────────────────�?                 �?    ┌────────────▼───────────────────────────────�?    �?         qp2p (本进�?                       �?    �?                                            �?    �? auth      Token 获取 & 定时续签            �?    �? holepunch STUN 探测 + QUIC 打洞引擎        �?    �? tun       TUN 虚拟网卡 (IP 路由)           �?    �? cdn       CDN 规则热重�?                  �?    �? http      axum HTTP 服务 (127.0.0.1:8080)  �?    └─────────────────────────────────────────────�?```

打洞成功后，节点间通过 QUIC 直连传输数据；打洞失败时自动回落�?Cloudflare Tunnel 中继，后台持续重试升级为直连�?
---

## 组件说明

| 组件 | 语言 | 说明 |
|------|------|------|
| `worker.js` | JavaScript | Cloudflare Worker，信令服务，存储节点信息，协调打洞时�?|
| `qp2p` | Rust | 运行在各节点的守护进程，负责打洞、TUN 路由、文件分�?|

### qp2p 模块

| 模块 | 文件 | 职责 |
|------|------|------|
| auth | `auth.rs` | 换取 Bearer Token，定时续签（过期�?1h），连续失败触发 shutdown |
| config | `config.rs` | 配置加载（TOML + 环境变量），`AppState` 构建 |
| tunnel | `tunnel.rs` | cloudflared 子进程管理，就绪检测，指数退避重�?|
| holepunch | `holepunch/` | STUN 探测、QUIC 打洞核心、后台重打洞、注册心�?|
| tun | `tun.rs` | TUN 虚拟网卡，IP 包路由（`virtual_ip` �?QUIC 连接�?|
| cdn | `cdn/` | CDN 规则解析，热重载，`/files/*` 分发决策 |
| http | `http/` | axum HTTP 服务：`/notify` `/files/*` `/health` `/reload` |
| types | `types.rs` | 全局共享类型，无业务逻辑 |

---

## 快速开�?
### 前置依赖

- Rust 1.75+（`rustup install stable`�?- `cloudflared`（[下载页](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)�?- Cloudflare 账号（用�?Worker + Tunnel + D1�?- `wrangler` CLI（`npm install -g wrangler`�?
### 1. 部署 Worker

```bash
# 创建 D1 数据�?wrangler d1 create quic-signal

# 建表（将 database_id 填入 wrangler.toml 后执行）
wrangler d1 execute quic-signal --file=schema.sql

# 部署
wrangler deploy worker.js
```

### 2. 编译 qp2p

```bash
cargo build --release
# 产物位于 target/release/qp2p（Windows �?qp2p.exe�?```

### 3. 配置并启�?
```bash
cp config.toml.example /etc/qp2p/config.toml
# 编辑配置（见下方配置参考）
nano /etc/qp2p/config.toml

sudo ./qp2p
```

---

## 配置参�?
`config.toml` 所有字段均可通过环境变量覆盖（优先级更高）�?
```toml
# Worker API 地址
worker_url = "https://quic-signal.example.workers.dev"

# 换取 Token 的密钥，�?Worker �?AUTH_SECRET 一�?auth_secret = "your-auth-secret-32-bytes-or-more"

# cloudflared Tunnel Token（从 Cloudflare Dashboard 获取�?tunnel_token = "eyJhI..."

# cloudflared 二进制路径（留空则在 PATH 中自动查找）
# cloudflared_path = "/usr/local/bin/cloudflared"

# STUN 服务器（默认 Cloudflare STUN�?stun_server = "stun.cloudflare.com:3478"

# 数据目录（存�?edge_id、cdn_list.toml、files/�?data_dir = "/etc/qp2p"

# CDN 规则清单路径（可选，默认 {data_dir}/cdn_list.toml�?# cdn_manifest = "/etc/qp2p/cdn_list.toml"

# 本节点虚�?IP（CIDR 格式，同组节点需在同一子网�?virtual_ip = "10.0.0.1/24"

# 组名称：只有相同 group_name 的节点才能互�?group_name = "my-network"

# 组密码（留空 = 开放组，只需 group_name 相同；非�?= 私有组）
group_password = "your-group-password"
```

### 环境变量覆盖

| 环境变量 | 对应字段 |
|----------|----------|
| `EDGE_WORKER_URL` | `worker_url` |
| `EDGE_AUTH_SECRET` | `auth_secret` |
| `EDGE_EDGE_ID` | `edge_id`（仅调试覆盖，正常由 Worker 管理�?|
| `EDGE_TUNNEL_TOKEN` | `tunnel_token` |
| `EDGE_CLOUDFLARED_PATH` | `cloudflared_path` |
| `EDGE_STUN_SERVER` | `stun_server` |
| `EDGE_CDN_MANIFEST` | `cdn_manifest` |
| `EDGE_AGENT_DATA_DIR` | `data_dir` |
| `EDGE_VIRTUAL_IP` | `virtual_ip` |
| `EDGE_GROUP_NAME` | `group_name` |
| `EDGE_GROUP_PASSWORD` | `group_password` |

---

## Worker 部署

### wrangler.toml 最小配�?
```toml
name = "quic-signal"
compatibility_date = "2024-01-01"

[[d1_databases]]
binding = "DB"
database_name = "quic-signal"
database_id = "<your-d1-id>"

[vars]
AUTH_SECRET = "<your-secret-32-bytes>"

[triggers]
crons = ["0 2 * * *"]   # 每日 02:00 UTC 清理过期节点
```

### D1 建表 SQL

```sql
CREATE TABLE IF NOT EXISTS edges (
  edge_id             TEXT PRIMARY KEY,
  tunnel_url          TEXT NOT NULL UNIQUE,
  virtual_ip          TEXT,
  candidates          TEXT NOT NULL,
  quic_conn_id        TEXT NOT NULL,
  group_name          TEXT NOT NULL DEFAULT '',
  group_password_hash TEXT NOT NULL DEFAULT '',
  status              TEXT NOT NULL DEFAULT 'online',
  last_seen           INTEGER NOT NULL,
  registered_at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_status_last_seen ON edges (status, last_seen);
CREATE INDEX IF NOT EXISTS idx_group_name       ON edges (group_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnel_url ON edges (tunnel_url);
```

### 节点清理策略

Worker 通过 Cron Trigger 每日自动清理�?
- 超过 **24 小时**未活跃的节点标记�?`offline`
- 超过 **7 �?*未活跃的节点物理删除

---

## qp2p 部署

### Linux / OpenWrt

```bash
# 需�?CAP_NET_ADMIN 权限创建 TUN 设备
sudo ./qp2p

# 或通过 systemd 管理
sudo cp qp2p.service /etc/systemd/system/
sudo systemctl enable --now qp2p
```

### systemd 单元文件示例

```ini
[Unit]
Description=qp2p edge-agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/qp2p
Restart=on-failure
RestartSec=10
AmbientCapabilities=CAP_NET_ADMIN
EnvironmentFile=/etc/qp2p/env

[Install]
WantedBy=multi-user.target
```

### 日志级别

通过环境变量 `RUST_LOG` 控制�?
```bash
RUST_LOG=qp2p=debug ./qp2p   # 详细日志
RUST_LOG=qp2p=info  ./qp2p   # 默认
RUST_LOG=qp2p=warn  ./qp2p   # 仅警告和错误
```

---

## 连接流程

### 启动序列

```
1. 加载配置 + 生成 quic_conn_id (UUID)
2. 启动 cloudflared，等�?Tunnel 就绪（轮�?/metrics，最�?60s�?3. �?Worker 换取 Bearer Token（最多重�?3 次）
4. STUN 探测，获取公�?IP:Port（srflx 候选地址�?5. 注册�?Worker（tunnel_url 作为身份锚，首次生成 edge_id�?6. 启动 Token 续签任务（过期前 1h 自动刷新�?7. 启动打洞引擎、CDN 模块、HTTP 服务、TUN 设备
```

### P2P 打洞流程

```
节点 A                    Worker                    节点 B
  �?                         �?                         �?  │── POST /connect ────────▶│                          �?  �?  (from=A, target=B,     �?                         �?  �?   candidates=[...])     │── POST B/notify ────────▶│
  �?                         �?  (from=A, t=T,          �?  │◀── {t, B_candidates} ───�?   from_candidates=[...]) �?  �?                         �?                         �?  �? 等待至时�?T             �?           等待至时�?T  �?  �?                         �?                         �?  │──────── QUIC Initial ──────────────────────────────▶│
  │◀─────── QUIC Handshake ─────────────────────────────�?  �?                         �?                         �?  │═════════�?QUIC 直连已建�?════════════════════════════�?```

打洞失败时双方均进入 `Relay`（Tunnel 中继）状态，后台重打洞任务每 15 秒扫描一�?Relay 节点，指数退避（30s �?60s �?120s + ±10s jitter）重试�?
### 分组规则

| 场景 | 是否允许连接 |
|------|-------------|
| 相同 group_name，双方均无密�?| �?开放组 |
| 相同 group_name，一方无密码 | �?开放组 |
| 相同 group_name，双方密码相�?| �?私有�?|
| 相同 group_name，双方密码不�?| �?|
| 不同 group_name | �?|

---

## API 参�?
所有接口均�?Worker 提供，qp2p 在内部调用。`/health` 免鉴权，其余接口均需 `Authorization: Bearer <token>`�?
### `POST /token`

换取 Bearer Token�?
```json
// 请求
{ "tunnel_url": "https://xxx.cfargotunnel.com", "secret": "your-auth-secret" }

// 响应
{ "token": "eyJ...", "expires_in": 86400 }
```

### `POST /register`

注册节点或续约（�?`tunnel_url` 为身份锚）。首次注册时 Worker 生成并返�?`edge_id`，qp2p 持久化到 `data_dir/edge_id`�?
```json
// 请求
{
  "tunnel_url":    "https://xxx.cfargotunnel.com",
  "quic_conn_id":  "550e8400-e29b-41d4-a716-446655440000",
  "candidates":    [{ "type": "host", "addr": "192.168.1.100:4433" },
                    { "type": "srflx", "addr": "203.0.113.5:4433" }],
  "virtual_ip":    "10.0.0.1",
  "group_name":    "my-network",
  "group_password": "password123"
}

// 响应
{ "ok": true, "edge_id": "uuid-...", "registered_at": 1700000000 }
```

### `POST /connect`

A 节点发起连接，Worker �?B 节点推送打洞通知，返回协调后的打洞时间戳 `t` �?B 的候选地址列表�?
```json
// 请求
{
  "from": "edge-id-of-A",
  "target": "edge-id-of-B",
  "candidates": [{ "type": "srflx", "addr": "203.0.113.5:4433" }]
}

// 响应
{
  "ok": true,
  "t": 1700000000500,
  "target_candidates": [{ "type": "host", "addr": "192.168.1.200:4433" }],
  "target_conn_id": "uuid-...",
  "target_virtual_ip": "10.0.0.2"
}
```

### `POST /notify`（qp2p 接收端）

�?Worker 通过 Tunnel 推送，不由客户端直接调用�?
```json
{
  "type": "hole_punch",
  "from": "edge-id-of-A",
  "from_candidates": [{ "type": "srflx", "addr": "203.0.113.5:4433" }],
  "from_virtual_ip": "10.0.0.1",
  "t": 1700000000500
}
```

### `GET /health`（qp2p 本地�?
```json
{
  "ok": true,
  "status": "running",
  "tunnel_ready": true,
  "peer_count": 3,
  "token_exp": 1700086400,
  "version": "0.1.0"
}
```

---

## CDN 分发

qp2p 内置 CDN 感知文件服务。通过 `cdn_list.toml` 配置规则，对 `GET /files/*` 请求进行路由决策�?
- **本地网络请求** �?直接从磁盘读取并返回文件�?- **外网请求 + CDN 模式** �?302 跳转�?Cloudflare CDN URL，利用边缘缓存加�?
### cdn_list.toml 示例

```toml
[local_network]
# 本地网络 CIDR，命中时强制走本地，不跳�?CDN
cidrs = ["192.168.0.0/16", "10.0.0.0/8"]

[[rules]]
path     = "/files/videos/"
mode     = "cdn"
max_age  = 86400
cdn_url  = "https://xxx.cfargotunnel.com/files/videos/"

[[rules]]
path    = "/files/docs/"
mode    = "direct"   # 始终本地返回，不跳转

[[rules]]
path     = "/files/assets/large/*.mp4"
mode     = "cdn"
max_age  = 3600
cdn_url  = "https://xxx.cfargotunnel.com/files/assets/large/"
# 覆盖全局 local_network
local_cidrs = ["10.0.0.0/8"]
```

### 规则匹配逻辑

采用**最长前缀匹配**，`path` 必须�?`/` 开头，�?`/` �?`/*` 结尾。`mode = "cdn"` �?`cdn_url` 为必填字段�?
### 热重�?
修改 `cdn_list.toml` 后，无需重启，向本地 HTTP 服务发送：

```bash
curl -X POST http://localhost:8080/reload
```

### 协商缓存

文件服务支持 `ETag`（基�?mtime + size �?SHA-256）和 `Last-Modified`，客户端可使�?`If-None-Match` / `If-Modified-Since` 获得 304 响应�?
---

## TUN 虚拟网卡

qp2p 创建 TUN 虚拟网卡，将 `virtual_ip` 绑定到本机，�?P2P 节点网络对上层应用透明�?
### 工作原理

```
应用层发�?IP �?    �?TUN 设备�?0.0.0.1/24�?    �?�?VirtualIpRegistry（dst_ip �?peer_id�?    �?�?ConnRegistry（peer_id �?QUIC Connection�?    �?发送至对端 QUIC 单向�?```

对端收到后写回自己的 TUN 设备，应用层感知不到网络层的存在�?
### 配置示例

节点 A：`virtual_ip = "10.0.0.1/24"`  
节点 B：`virtual_ip = "10.0.0.2/24"`

打洞成功后，A 可以直接 `ping 10.0.0.2`，流量通过 QUIC 加密传输�?
---

## 平台支持

| 平台 | TUN 设备 | 状�?|
|------|----------|------|
| Linux | `/dev/tun` + `tun` crate | �?支持 |
| OpenWrt | `/dev/tun` + `tun` crate | �?支持 |
| Windows | WinTun 驱动 | �?支持 |
| macOS | `/dev/tun` | �?计划�?|
| Android | VpnService（需 JNI�?| �?暂不支持 |

---

## 开发与测试

```bash
# 运行所有单元测�?cargo test

# 运行特定模块测试
cargo test --test-thread=1   # 避免全局 STUN 缓存竞争

# 检查编译（不运行）
cargo check

# 格式�?cargo fmt

# Lint
cargo clippy -- -D warnings
```

### 本地开发环�?
可以不启动真�?cloudflared，用环境变量指向本地 mock Worker�?
```bash
EDGE_WORKER_URL=http://127.0.0.1:8787 \
EDGE_AUTH_SECRET=dev-secret \
EDGE_TUNNEL_TOKEN=fake-token \
EDGE_VIRTUAL_IP=10.0.0.1/24 \
EDGE_GROUP_NAME=dev \
EDGE_GROUP_PASSWORD=devpasswd \
RUST_LOG=qp2p=debug \
cargo run
```

---

## 许可�?
MIT
