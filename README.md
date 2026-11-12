# qp2p

私有打洞组网：节点向 Cloudflare Worker 上报连通信息，Worker 只做撮合，
节点之间 QUIC 直连后互访。**业务流量不经过服务器**。

没有公网 IP 也能用，不需要端口映射，也不需要一台公网中转机。

## 能做什么

- 多台机器组成一个虚拟网络，每台分到 `10.x.y.z` 的虚拟地址，互相 `ping` 通
- 三端：Linux（TUN）、Windows（原生图形界面 + 系统托盘）、Android（VpnService）
- 换网自愈（WiFi ↔ 4G 几秒恢复）、虚拟地址手填并预留
- 信令走 WebSocket 长连接，事件即时推送；连不上自动退回轮询，服务端恢复后自动切回
- 空闲断链省电：Android 可选 10 / 30 / 60 分钟，或直接开「保持在线」；桌面端默认不断
- 信令面是单文件 Worker + 每网络一个 Durable Object（SQLite）。免费额度下单网络最多 256 节点，
  百台量级的常开设备仍在额度内（估算见 [v3 设计文档](docs/signal-v3-design.md) §11）

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

Android 不用敲命令：装 APK，填信令地址和这行令牌，点「自动连接」即可。

看到 `✓ 直连已建立：bob (10.78.156.207)` 后，`ping` 这个地址就通了。

## 下载与安装

当前最新版：[v0.1.6](https://github.com/mylucien/qp2p/releases/tag/v0.1.6)。
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

**`qp2p-deploy-<版本>-<平台>` 不是客户端**，是自建信令服务用的一次性部署工具：把 Worker
上传到你的 Cloudflare 账号（建 D1、绑定 Durable Object、生成 `ADMIN_SECRET`、跑冒烟），
以后升级用 `qp2p-deploy up`。用别人架好的地址、只填令牌就连的话，**一个都不用下**；
自建时按你操作的机器选一个平台即可，跑一次就完事，Worker 之后在云端运行。
手工在 Dashboard 粘贴源码已经不适用（缺 DO 绑定，业务接口会返回 503）。

详细步骤（部署信令、建网、加入、排障）见 [USAGE.md](USAGE.md)。

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

设计取舍与协议细节见 [DESIGN.md](DESIGN.md)，当前信令架构见
[signal-v3-design.md](docs/signal-v3-design.md)。

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

## 文档

| 文档 | 内容 |
|---|---|
| [USAGE.md](USAGE.md) | 部署、安装、建网、加入、上线、日常命令、配置、管理页、排障、安全模型 |
| [DESIGN.md](DESIGN.md) | 架构、协议、设计决策 |
| [signal-v3-design.md](docs/signal-v3-design.md) | 当前信令架构：Durable Object、WebSocket、配额与容量模型 |
| [signal/README.md](signal/README.md) | 信令服务源码、接口与本地测试脚本 |
