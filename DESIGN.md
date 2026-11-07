# qp2p 设计说明

把多台机器组成私有虚拟网络：节点向 Worker 上报连通信息，Worker 只做撮合，
节点之间打洞直连后互相访问，**业务数据不经过服务器**。
一个 Worker 承载多个互相隔离的网络（多租户），每个节点同一时刻只归属其中一个。

三端交付：Linux（CLI + TUN）、Windows（原生图形界面 + WinTun）、Android（APK + VpnService）。

## 1. 边界

**做**

- 节点身份与命名、密钥即入、上下线、在线状态、节点列表
- 建网络、网络间隔离、每网络独立 `/16` 网段、密钥轮换
- 虚拟地址自动分配、可手填并预留、重启不变
- STUN 探测 + 服务端撮合 + QUIC 打洞、失败重试与诊断、换网自愈
- 虚拟地址互 ping、访问对端 TCP/UDP 端口、端口映射、访问对端背后网段
- Windows 图形界面与托盘、Android 前台服务

**明确不做**

- 文件中转、CDN、静态托管
- 公网中继（对称 NAT 直接失败，不假装成功）
- 多跳路由（A 经 B 访问 C）
- 反向代理、公网端口暴露
- 云端账号体系、应用商店上架
- 一个节点同时归属多个网络（要跨网络就跑两个实例）

## 2. 三个面

| 面 | 协议 | 职责 |
|---|---|---|
| 信令面 | HTTPS 短请求 + 事件轮询 | 登记、发现、撮合、在线状态、网络管理 |
| 打洞面 | UDP（QUIC Initial / 裸探针） | 在 NAT 上开孔，建立直连 |
| 数据面 | QUIC（裸 QUIC，非 HTTP/3） | 承载互访流量，per-flow 流复用 |

三个约束：

1. 三个面之间只传「地址」这一种信息。信令面挂掉，已建立的直连不受影响。
2. 多租户只影响信令面和地址分配；每个节点一条事件轮询。
3. **core 是库，不是守护进程**。三个外壳各自内嵌 core，不做跨进程数据转发。

## 3. 模块结构

```
crates/core/src/
  identity.rs    Ed25519 身份、node_id、虚拟地址派生、TLS 证书与钉扎
  config.rs      TOML 配置、取值顺序（命令行 > 文件 > 默认）
  candidate.rs   候选地址：收集、优先级、去重
  stun.rs        STUN Binding 编解码
  stun_watch.rs  STUN 探测调度（换网后重探）
  socket.rs      单 UDP socket + quinn 端点
  upnp.rs        UPnP 端口映射
  path.rs        时钟偏移估计（EWMA）、打洞窗口调度
  peer/          每对端状态机（fsm）、身份互验（auth）、角色化打洞（punch）
  signal/        信令客户端：join / register / connect / events
  link/          per-flow QUIC 流复用、TUN 数据面
  session.rs     会话生命周期
  engine.rs      端点生命周期、打洞入口
  route/         TUN 与端口映射：tun_linux / tun_windows / tun_android / flow / ip
crates/cli/src/  命令行（main）、图形界面（win_gui）、共用 UI（gui）
crates/android/  VpnService 外壳（JNI 调 core）
signal/          单文件 Cloudflare Worker + 本地冒烟测试
```

## 4. 关键设计决策

| 决策 | 做法 | 理由 |
|---|---|---|
| 单 socket 两个消费者 | 一个 UDP socket 包成 `AsyncUdpSocket`，STUN 与 QUIC 共用 | STUN 观测到的映射**就是** QUIC 用的那条五元组 |
| 角色确定 | `node_id` 小的当 dialer，大的当 listener | 双侧同时当客户端会得到两条连接和一堆没人取的 accept |
| 身份来自密钥 | `node_id = sha256(pubkey)[:32]`，注册时上报 TLS 指纹 | 身份不能由 URL 或昵称决定 |
| 打洞是纯函数状态机 | `step(state, event, now) -> (state, Vec<Effect>)` | 可用虚拟时钟单测，不必真起网络 |
| 时钟用 RTT 估算 | 响应带 `server_ms`，按 `server_ms - (t0 + rtt/2)` 做 EWMA | 不依赖本机绝对时间 |
| 数据面按 flow 复用 | 一条 QUIC 连接承载全部流量，每个 flow 一条双向流 | 每包开新流会撞上并发流上限 |
| 地址由身份派生 | 每网络独立 `/16`，节点地址由 `node_id` 哈希派生，碰撞服务端加盐重算 | 客户端与服务端算同一套结果 |
| 额度优先 | 事件轮询分档：刚发生事 3 秒、有未连上的对端 20 秒、全连上 60 秒 | 免费额度按节点数线性消耗 |
| 无中继且诚实 | 打不通就报失败，对称 NAT 明确标注 | 假装成功比失败更难排查 |
| 多租户横向扩展 | 一个 Worker 多网络，节点不做多归属 | 多归属要引入多地址/多路由/多连接表，收益极小 |
| 启动先试 UPnP | 映射成功就多一个 `upnp` 候选，租约过半续租 | 家用路由器命中率高，省掉打洞的不确定性 |

## 5. 协议

### 令牌

```
qp2p1_<network_id>_<secret>
```

`network_id` 让客户端联网前就知道找哪个网络；`secret` 只用于 HMAC 鉴权，
服务端只存 `sha256(secret)`。`ADMIN_SECRET` 推不出任何网络的加入密钥。

### 信令接口

除 `/v1/health` 与 `/v1/admin/*` 外，全部按网络密钥签名。

| 方法 | 路径 | 鉴权 | 用途 |
|---|---|---|---|
| GET | `/v1/health` | 无 | 健康检查，返回版本、存储类型、是否配了管理密钥 |
| POST | `/v1/join` | 加入密钥 | 校验密钥，返回网络信息与网段 |
| POST | `/v1/register` | 网络密钥 | 上报节点信息，返回虚拟地址与节点列表 |
| POST | `/v1/connect` | 网络密钥 | 撮合：带自身候选，取回对端候选与打洞时刻 |
| POST | `/v1/leave` | 网络密钥 | 主动下线 |
| GET | `/v1/events` | 网络密钥 | 按游标拉取待处理事件 |
| POST | `/v1/admin/*` | 管理密钥或会话 | 建网、改网段、换密钥、删网、成员与预留、审计 |

### 事件

`register` 返回节点列表；`/v1/events` 只推「有人要和你打洞」这类时效性事件。
列表类变化（谁上线了）不走事件，避免每次变化都给全网发通知。

### 打洞与数据面

- 打洞探针复用 QUIC Initial；listener 长时间 accept 并周期性发探针，dialer 只发一条连接、重传交给 QUIC
- 双方在流上交换 `HELLO`/`ACK`，再做一次带 **TLS 会话导出值** 的 Ed25519 互签
- 数据面：`u16 len + IP 包`，一条流承载一个 flow 的全部包，双向；TCP 半关闭后 60 秒回收

## 6. 信令服务的存储与限额

单文件 `signal/worker.js`，粘进 Cloudflare Dashboard 就能部署；绑一个 D1 存
网络、节点、事件、IP 预留、登录审计五类数据（表自动创建），不绑则退化为内存、重启即清空。

- 一次往返撮合 + 增量拉事件，`last_seen` 节流写入
- 客户端自适应轮询（3 / 20 / 60 秒）+ 对端上线广播，稳态下 50 台常开设备约在免费额度内
- 超额度返回 `429`：已建立连接保持、用缓存候选继续重试、暂停列表刷新

## 7. 平台差异

| 平台 | 虚拟网卡 | 要求 | 交付 |
|---|---|---|---|
| Linux x86_64 | `/dev/net/tun` | root 或 `CAP_NET_ADMIN` | 单二进制 |
| Windows 10/11 x64 | WinTun（内嵌 dll） | 管理员，exe 清单自动提权 | 单 exe，原生界面 + 托盘 |
| Android 8+ arm64/armv7/x86_64 | VpnService | 无需 root | 自签 APK |

我们是 L3 隧道，而 VpnService 和 WinTun 给的都是 L3 TUN，两端能 1:1 对接，
不需要伪造以太网头或装 TAP 驱动。
