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
  tls.rs         传输参数（窗口 / MTU / ACK 策略 / 忙轮询）+ 进程级 LinkTuning
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
| 发送队列按字节计 | 单流 256 KB、全局 32 MB 预算，满则丢新包；队列句柄两端各持一个，谁丢谁关 | 按包数算时 64 KB 大包与 40 字节 ACK 共用一个上限；`256 流 × 64 包 × 64 KB` 最坏 1 GB，能打死 438 MB 的设备。句柄必须带 `Drop`：只用 `Arc` 共享时 writer 退出后流表那份还在，`Drop for FlowQueue` 永远等不到，队列不关 → `dispatch` 等不到 `Closed` → 那条流永久黑洞 |
| 超 MTU 就分片 | 按 IPv4 规则切 8 字节对齐的片，复制原头重算校验和、清 DF | 直接丢包的故障表现是「小包通、大包不通」，用户只会认为"网络时通时不通" |
| 拥塞控制不开放选项 | 固定 Cubic；曾经提供 `congestion = "bbr"`，0.1.16 实测后整条删除 | 不是「BBR 太强势」这种口味问题，是实测连接每分钟被摘一次：quinn 的 BBR 初始窗口 200 包（240 KB）、`calculate_cwnd` 拿增益和字节数比导致 Startup 窗口无上限、`app_limited` 时永不退出 Startup。零散流量的隧道正好踩满这三条，结果是往对端链路灌爆 → 对端 RTO 退避 8 秒 → 被我们自己的失效判据摘掉 |
| 收包按片读、切片/拷贝按方向取舍 | QUIC → TUN 用 `BytesMut` 大块 + `split_to().freeze()`，通道传 `Bytes`；TUN → QUIC 用定长 scratch + `Bytes::copy_from_slice`，每包独立分配 | 原来每帧一次 `Vec` 分配 + 两次 `read_exact`，TUN 读侧还是 `buf[..n].to_vec()`。QUIC → TUN 的包直接写网卡、不会长期滞留，共享大块没有代价；TUN → QUIC 的包会进发送队列，而队列额度按**包长**记账——共享 64 KB 块时一条卡住的小包流能用 256 KB 额度钉住数百 MB 物理内存，光猫只有 438 MB。旧实现的 `resize(max_pkt, 0)` 还每包 memset 1488 字节，省下的 malloc 有限。`read_chunk` 方向仍有一次 `extend_from_slice`，省的是逐包 malloc，不是那次 memcpy |
| 发送侧批量写 | 取到第一个包后把队列里**已经排好**的包一次排空，多帧拼进同一个缓冲（≤64 KB），一次 `write_all`、一个超时 | 每包单独写要付三笔账：队列锁、`tokio::time::timeout` 的定时器注册、一次 `poll_write`；高包率下比拷贝本身还贵。只取不等，所以不会为攒批增加延迟；QUIC 流本来就是字节流，多帧拼一次写与逐帧写在线路上完全等价 |
| 忙轮询默认关 | `busy_poll_us = 0`；Linux 上按配置设 `SO_BUSY_POLL`，失败只记 info | 拿 CPU 换几十微秒延迟，默认打开会让小主机的低功耗核持续升温 |
| 判死阈值按 RTT 自适应 | `silent_limit = clamp(10×srtt, 3s, 8s)`，`suspect_limit = clamp(6×srtt, 1s, 3s)`；RTT 未知传零、落在下限 3 秒 | 固定 8 秒在 20 ms 的局域链路上要多扛 5 秒；固定 3 秒在高 RTT 链路上会误杀——QUIC 的 PTO 本身就是 `3×srtt`，加一次丢包重传就超了 |
| 先建后断 | 到怀疑阈值只发一次"预拨"（30 秒冷却），且**只允许 node_id 小的一侧发起**；旧连接继续承载，新连接建成后以 `dedupe=false` 后到顶替，预拨失败仍按判死阈值走原重建 | 一次真实黑洞的感知是"8 秒检测 + 1~3 秒重拨"；预拨来得及就接近 0 中断。两条硬约束：①预拨不能参与选边（否则可能被判给旧的那条，白跑一趟），②发起方必须与正常拨号一致——预拨侧用 `dedupe=false`、对端仍走选边，两边规则不同就会各留一条又互相关掉，等于亲手制造一次中断。`answer_punch` 因此不再因为"表里连着"拒绝应答：它必须应答预拨。**已知覆盖缺口**：大 id 侧即使先发现问题也不会预拨，只能等自己的判死阈值（3~8 秒）走 forced 重建；forced 拨号不受 node_id 规则限制，所以能收敛，只是那几秒是老路 |
| 接收窗口按内存分级 | `window` 配置项：不填 = auto，物理内存 < 1 GB 用单流 1 MB / 总 8 MB，否则 2 MB / 16 MB；显式值夹在 64 KB~32 MB | 438 MB 的光猫和 32 GB 的 PC 不该用同一个窗口。窗口是"愿意缓冲多少"而非预分配，但慢速对端会把数据压在路上，弱设备仍要收紧 |

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
成员列表的变化（谁在线、有几个）靠 `register` 的返回值和 `peer_online` 广播，
不做「每次变化给全网发一条」——节点一多就会把事件表刷爆。

`peer_online` 只在三种情况广播：节点从离线变在线、候选地址变了、或客户端在
换网重报时显式带 `announce: true`。第三种是必须的：新网络的 NAT 映射可能和旧
的一模一样（端口保留型 NAT），服务端看不出变化，而对端很可能已经因为「在线
却打不通」进了 5 分钟冷却，只有收到上线通知才会清掉。

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
| `initial_mtu` / `min_mtu` | 1280 / 1200 | 1280 是 IPv6 最小 MTU，覆盖面最广。用 1400 时，路径实际只支持 1280 的链路（叠 VPN、部分蜂窝）上大包全丢，要等黑洞检测（连续超过 3 次可疑丢包 burst）才退回 `min_mtu`；期间小包仍能通、不会触发 8 秒判死，只是每条新连接都卡几秒。握手包固定 pad 到 1200，不受这个值影响；MTU 发现会自己往上爬到路径 MTU |
| `keep_alive_interval` | 15 秒 | 空闲链路上也要周期性发出**需要对端回应**的 PING，`tun.rs` 的失效判据才有依据，同时兼顾 NAT 映射不被回收 |
| ACK 频率阈值 | 10 | 收到 10 个包才回一次 ACK，省对端中断；`max_ack_delay` **刻意保持默认**——放宽它会直接抬高本端观测到的 RTT |
| `initial_rtt` | 20 ms（内网候选）/ 默认 333 ms | 两个私网地址之间的 RTT 不可能几百毫秒，333 ms 会让 PTO 白等 1 秒 |
| 发送队列 | 单流 256 KB / 全局 32 MB | 按字节而非包数，跨流共享一份预算；`Mutex<VecDeque>` + `AtomicUsize` + `Notify`。`QueueTx`（流表侧）/ `QueueRx`（writer 侧）各自 `Drop` → `close()`，`run` 从任何路径退出都会关队列 |
| 发送批量 | 每次 `write_all` ≤ 64 KB | 排空队列时一次拿锁、一次归还预算；缓冲随批量尺寸增长并复用，小流仍停在 2 KB 初始容量。超时则整批复用流的 `reset` 语义，对端本来就会丢弃半条流 |
| 流表容量 | 224（对端配额 256） | 流表满会淘汰最旧条目并**立刻** `open_bi`，而对端归还 `MAX_STREAMS` 滞后一个往返；容量等于配额时每次「淘汰 + 重开」都撞配额，挂到 `OPEN_TIMEOUT`（3 秒） |
| 帧结束边界 | 半个帧头算协议错误 | 只剩 1 字节帧头说明对端算错长度或中途崩了；静默当成正常结束会把截断埋进日志 |
| MTU 溢出处理 | IPv4 分片 | `ip::fragment()`：载荷 8 字节对齐、偏移 `offset/8`、`MF` 除末片置 1、重算校验和、清 `DF` |

`LinkTuning` 只有两个字段，都**默认保守**：

- `ack_threshold: u32`（默认 10）。走 `ack_frequency_config`，由 `peer_supports_ack_frequency()`
  守卫，老对端收不到这个帧，向后安全。`max_ack_delay` 不动。
- `busy_poll_us: u32`（默认 0）。linux-only `setsockopt(SOL_SOCKET, SO_BUSY_POLL)`，
  失败只 `info`——需要 `CAP_NET_ADMIN` 与 `CONFIG_NET_RX_BUSY_POLL`，缺了也照常工作。

**为什么没有拥塞控制开关**：见决策表「拥塞控制不开放选项」。简单说，quinn 0.11 的
`BbrConfig` 初始窗口是 `K_MAX_INITIAL_CONGESTION_WINDOW(200) × BASE_DATAGRAM_SIZE = 240 KB`，
而 `calculate_cwnd()` 里判断是否继续增长写的是
`self.cwnd_gain < target_window as f32`——拿增益（2.885）和字节数比，恒为真，于是 Startup
阶段每个 ACK 都 `cwnd += bytes_acked`；同时 `check_if_full_bw_reached()` 在
`app_limited = 发送缓冲空 && 未被拥塞卡住` 时直接返回，而隧道转发的流量恰好长期就是这个状态，
永远退不出 Startup。三处叠加 = 窗口无上限 + 丢包不压窗口，对着有损链路就是一轮轮自伤。
这些都在 quinn 内部，改不了，所以不对外暴露这个选项。

**MTU 必须在配置源头夹，不能只夹在建卡处**：同一个 MTU 值有两个消费者——内核按它决定
组多大的包，数据面按它判断要不要分片。只在 `route::open()` 里夹，会出现「内核发 1500、
数据面也拿到 1500，`len > mtu` 不成立」的情况，于是每个满包在 QUIC 流里被切成两段，
丢一段就要重传整个内层包。所以 `route::clamp_mtu()` 在三个源头各调一次：
CLI（`up` 与 `tun` 两条路径）、Android（`prepared.mtu`，同时喂给
`VpnService.setMtu()`）、Windows GUI（保存前）。`route::open()` 里再兜一次，
防止以后新增调用方漏掉。

历史上这处夹紧只写在 `TunConfig::for_network()` 里，而那个函数**没有任何调用点**，
等于三端都没夹过——2026-11-22 核实后删掉死代码、改成上面的写法。

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
