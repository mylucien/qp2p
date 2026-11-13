# qp2p

私有打洞组网：节点向 Cloudflare Worker 上报连通信息，Worker 只做撮合，
节点之间 QUIC 直连后互访。**业务流量不经过服务器**。

没有公网 IP 也能用，不需要端口映射，也不需要一台公网中转机。

## 能做什么

- 多台机器组成一个虚拟网络，每台分到 `10.x.y.z` 的虚拟地址，互相 `ping` 通
- 三端：Linux（TUN）、Windows（原生图形界面 + 系统托盘）、Android（VpnService）
- 换网自愈（WiFi ↔ 4G 几秒恢复）、虚拟地址手填并预留
- 信令走 WebSocket 长连接，事件即时推送；连不上自动退回轮询，服务端恢复后自动切回
- 「直连保持」可选 10 / 30 / 60 分钟，或开「保持在线」不断；「启动连接」开关打开后打开 App 自动入网；桌面端默认不断
- 信令面是单文件 Worker + 每网络一个 Durable Object（SQLite）。免费额度下单网络最多 256 节点，
  百台量级的常开设备仍在额度内

## 快速开始

```bash
# 建网的机器（一次性，需要部署时设的 ADMIN_SECRET）
qp2p init https://p2p.example.com --admin <ADMIN_SECRET>
qp2p create home          # 打印一行 qp2p join qp2p1_home_...

# 其它每一台机器
qp2p join qp2p1_home_...

# 所有人
sudo qp2p up              # Windows 用管理员终端；或直接双击 exe 开图形界面
```

Android 不用敲命令：装 APK，填信令地址和这行令牌，点「连接」即可；打开「启动连接」开关后，
每次打开 App 会自动入网（默认关，打开 App 需要手动点「连接」）。

看到 `✓ 直连已建立：bob (10.78.156.207)` 后，`ping` 这个地址就通了。

## 下载与安装

当前最新版：[v0.1.8](https://github.com/mylucien/qp2p/releases/tag/v0.1.8)。
每个 Release 有 10 个附件：5 个客户端、4 个服务端部署器、1 个 `SHA256SUMS.txt`。

**客户端**（照着下表选一个）：

| 平台 | 文件 |
|---|---|
| Windows 10/11 x64 | `qp2p-<版本>-windows-x86_64.exe`，单文件，双击即用，不用另放 dll |
| Linux x64（glibc ≥ 2.39） | `qp2p-<版本>-linux-x86_64` |
| Linux x64（老系统 / 容器） | `qp2p-<版本>-linux-x86_64-static`，静态链接 |
| Linux arm64（路由器 / 开发板） | `qp2p-<版本>-linux-aarch64-static`，静态链接 |
| Android 8+ | `qp2p-<版本>-android.apk`，debug 签名 |

下载后先 `sha256sum -c SHA256SUMS.txt` 校验。

**`qp2p-deploy` 不是客户端**，是一键部署工具：把 Worker
上传到你的 Cloudflare 账号（建 D1、绑定 Durable Object、生成 `ADMIN_SECRET`、跑冒烟），
以后升级用 `qp2p-deploy up`。按你操作的机器选一个平台即可。

## 部署信令服务

### 1. 准备

- Cloudflare 账号；API Token 需要 `Workers Scripts:Edit` + `D1:Edit` 两个权限
- 账号 ID（控制台右侧栏）
- 自己的域名（建议）

### 2. 下载并校验

从 [v0.1.8](https://github.com/mylucien/qp2p/releases/tag/v0.1.8) 下
`qp2p-deploy`，下面用 Linux 静态版举例，换成你下载的文件名即可。

### 3. 首次部署

```bash
export CLOUDFLARE_API_TOKEN=...      # Windows PowerShell：$env:CLOUDFLARE_API_TOKEN="..."
export CLOUDFLARE_ACCOUNT_ID=...

./qp2p-deploy-0.1.8-linux-x86_64-static init --dry-run   # 先看要上传什么（密钥已脱敏）
./qp2p-deploy-0.1.8-linux-x86_64-static init             # 真正部署
```

验收：依次打印「① 校验令牌 → ② 准备 D1 → ③ 上传 Worker → ④ 启用 workers.dev → ⑤ 冒烟」，
最后给出 `地址`、`管理页`、迁移标签和 **只显示一次的 `ADMIN_SECRET`**。把密钥存好，
丢了只能用 `rotate-admin` 重设。默认 Worker 名和 D1 名都是 `qp2p`，可用 `--worker` / `--db` 改。

用自己的域名：在控制台给这个 Worker 加一条路由（例如 `p2p.example.com/*`），
之后客户端一律填这个域名。

### 4. 验收部署

```bash
qp2p init https://p2p.example.com --admin <ADMIN_SECRET>
```

期望看到 `✓ Worker 可达`，且 `引擎 room（支持 WebSocket 长连接）`、`存储 D1`、
`管理密钥 已配置` 三项都在，版本 2.8.x。再核对两条：

```bash
curl https://p2p.example.com/v1/health     # 匿名只回 {"ok":true}
```

`https://p2p.example.com/admin` 能打开管理页；根路径 `/` 返回 404，不提供接口清单。

### 5. 以后升级

```bash
./qp2p-deploy-0.1.8-linux-x86_64-static status   # 先看当前迁移标签与线上状态
./qp2p-deploy-0.1.8-linux-x86_64-static up       # 升级，密钥与 D1/DO 数据都保留
```

验收：输出 `✓ 已升级到标签 ...`，再跑一次 `qp2p init --admin` 确认 `引擎 room`、
`管理密钥 已配置` 没变；节点不用重新 `join`。

| 命令 | 用途 |
|---|---|
| `init` | 首次部署：建 D1 → 上传 → 启用子域 → 冒烟 |
| `up` | 升级代码、按迁移链补步骤 |
| `status` | 看本地记录 + 探一次线上 |
| `rotate-admin` | 重设 `ADMIN_SECRET` |
| `destroy` | 删 Worker，**Durable Object 数据一起销毁，不可恢复** |

注意：

- 状态文件在 `~/.qp2p/deploy.json`（可用 `QP2P_DEPLOY_STATE` 改）。换机器或删了它，
  `up` 认不出当前迁移标签，要用 `--tag <标签>` 显式指定，别猜。
- 部署器用 `include_str!` 把 `signal/worker.js` 编进了可执行文件：**正式版部署器内嵌的是
  发版当时的 Worker 源码**，之后改了 Worker 不会自动生效，要用新发布的部署器 `up` 一次。

建网、加入、日常命令与排障见 [USAGE.md](USAGE.md)。

## 架构

```
crates/core     协议核心：STUN、打洞、QUIC、TUN、身份（无前端依赖）
crates/cli      命令行 + Windows 原生图形界面
crates/android  VpnService 外壳（JNI）
crates/deploy   信令部署器：Cloudflare API、迁移链、冒烟
signal/         单文件 Worker + D1（控制面）+ 每网络一个 Durable Object（数据面）
```

- **信令面**：登记候选地址、撮合打洞、维持在线状态；不转发业务流量
- **数据面**：STUN 探测 → 服务端撮合 → QUIC 直连，端到端加密
- **身份**：Ed25519，`node_id` 由公钥派生，虚拟地址由身份派生；重启不变
- **认证**：每条直连建立后双方交换签名，签名绑定这条 TLS 会话，复放/反射/冒充都会失败


## 命令

日常：`init` `create` `join` `up` `status` `token` `rotate` `leave` `config`
管理：`nets` `delete`（需要 `ADMIN_SECRET`）
调试：`punch` `forward` `tun` `doctor`（不需要信令服务器）

完整选项看 `qp2p --help` 和 `qp2p up -h`。

## 平台要求

| 平台 | 虚拟网卡 | 要求 |
|---|---|---|
| Linux | `/dev/net/tun` | root 或 `CAP_NET_ADMIN` |
| Windows 10/11 | WinTun（已内嵌） | 管理员，exe 清单会自动提权 |
| Android 8+ | VpnService | 无需 root；Android 13+ 不给通知权限不影响连接 |
