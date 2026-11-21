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
  tls.rs         传输参数（窗口 / MTU / 拥塞控制 / ACK 策略 / 忙轮询）+ 进程级 LinkTuning
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
| 发送队列按字节计 | 单流 256 KB、全局 32 MB 预算，满则丢新包 | 按包数算时 64 KB 大包与 40 字节 ACK 共用一个上限；`256 流 × 64 包 × 64 KB` 最坏 1 GB，能打死 438 MB 的设备 |
| 超 MTU 就分片 | 按 IPv4 规则切 8 字节对齐的片，复制原头重算校验和、清 DF | 直接丢包的故障表现是「小包通、大包不通」，用户只会认为"网络时通时不通" |
| BBR 默认关 | `congestion = cubic`，开了才切 BBR 并打 warn | BBRv1 丢包只进 `Conservation`、每 8 RTT 周期性过冲；共享家庭上行时会挤占同链路 TCP，浅缓冲下反而更差。quinn 自己标注 Experimental |
| 收包零拷贝切帧 | `read_chunk` + `BytesMut` + `split_to().freeze()`，`to_tun` 传 `Bytes` | 原来每帧一次 `Vec` 分配 + 一次 `copy_from_slice`，2000 pps 下就是每秒 2000 次 malloc |
| 忙轮询默认关 | `busy_poll_us = 0`；Linux 上按配置设 `SO_BUSY_POLL`，失败只记 info | 拿 CPU 换几十微秒延迟，默认打开会让小主机的低功耗核持续升温 |

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
| GET | `/v1/health` | 无 / 管理密钥 | 匿名只回 `{"ok":true}`；带管理密钥才返回版本、存储、节点数、限额。根路径返回 404 |
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

### 数据面调优

传输参数集中在 `crates/core/src/tls.rs` 的 `transport()`，进程级开关在 `LinkTuning`
（`OnceLock`，`cli` 启动时 `tls::configure()` 灌入，Android 走默认值）。

| 参数 | 值 | 理由 |
|---|---|---|
| `stream_receive_window` | 2 MB | 40 ms RTT 下单流上限约 400 Mbps；1.25 MB 只有 250 Mbps |
| `receive_window` | 16 MB | **连接级必须有上限**：原来是 `VarInt::MAX`，`256 流 × 2 MB` 理论最坏 512 MB，能打死 256 MB 的设备。按「8 条满窗流」设计，10 个对端最坏 160 MB |
| `initial_mtu` / `min_mtu` | 1400 / 1200 | PMTUD 被 ICMP 过滤阻断时不会退化到 1200；上限 1424 在 `TunConfig::for_network` 夹紧 |
| `keep_alive_interval` | 15 秒 | 空闲链路上也要周期性发出**需要对端回应**的 PING，`tun.rs` 的失效判据才有依据，同时兼顾 NAT 映射不被回收 |
| ACK 频率阈值 | 10 | 收到 10 个包才回一次 ACK，省对端中断；`max_ack_delay` **刻意保持默认**——放宽它会直接抬高本端观测到的 RTT |
| `initial_rtt` | 20 ms（内网候选）/ 默认 333 ms | 两个私网地址之间的 RTT 不可能几百毫秒，333 ms 会让 PTO 白等 1 秒 |
| 发送队列 | 单流 256 KB / 全局 32 MB | 按字节而非包数，跨流共享一份预算；`Mutex<VecDeque>` + `AtomicUsize` + `Notify`，`Drop for FlowQueue` 兜底归还预算 |
| MTU 溢出处理 | IPv4 分片 | `ip::fragment()`：载荷 8 字节对齐、偏移 `offset/8`、`MF` 除末片置 1、重算校验和、清 `DF` |

`LinkTuning` 只有三个字段，全部**默认保守**：

- `bbr: bool`（默认 `false` → Cubic）。开时打 warn，因为 quinn 把 BBR 标为 Experimental。
- `ack_threshold: u32`（默认 10）。走 `ack_frequency_config`，由 `peer_supports_ack_frequency()`
  守卫，老对端收不到这个帧，向后安全。
- `busy_poll_us: u32`（默认 0）。linux-only `setsockopt(SOL_SOCKET, SO_BUSY_POLL)`，
  失败只 `info`——需要 `CAP_NET_ADMIN` 与 `CONFIG_NET_RX_BUSY_POLL`，缺了也照常工作。

刻意**没做**的两项：FlowTable 换哈希（实测查找只占 3% 的转发耗时，改哈希要动 key
语义）；`dispatch` 同步化（会阻塞主循环，与懒打洞的 await 语义冲突，等于回到"一条流
卡死整条隧道"的老问题）。

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
