# qp2p 重构方案

> 版本：v1.4（2026-11-03 修订：信令面改为单文件 Worker + D1 + 轮询，去掉 Durable Object 与 WebSocket）
> 状态：设计冻结，待评审。本文只定方案，不含实现代码。
> 基线：`mylucien/qp2p`（Rust 4926 行 / Worker 589 行 / 文档 555 行）

---

## 0. 一句话

把多台机器组成私有虚拟网络：节点向 Worker 上报连通信息，Worker 只做撮合，节点之间打洞直连后互相访问，任何业务数据都不经过服务器。一个 Worker 可承载多个互相隔离的网络（多租户），每个节点归属其中一个。

三端交付，效果对齐 n2n（hin2n / EasyN2N）：**装完就有一块虚拟网卡，能和同网络的其他机器互相 ping 通、访问端口**。

---

## 1. 为什么要重写而不是改

旧版的三个致命问题（均有代码证据）：

| # | 问题 | 证据 |
|---|---|---|
| 1 | **数据面不存在** | `TunHandle::send_packet` 零调用者；`tun.rs:327` 每包 `open_uni` 开新流；全仓库无 `accept_uni`/`accept_bi` |
| 2 | **STUN 测的不是 QUIC 的映射** | `stun.rs:94-113` 用另一随机端口探测，再把端口替换成 QUIC 端口；NAT 映射按五元组计，二者无关 |
| 3 | **双方同时当客户端** | `punch.rs:65-82` 两侧都 `ep.connect()`；`endpoint.accept()` 从未调用，入站连接堆在队列里 |

后果就是用户看到的现象：**打洞"成功"了，但 ping 不通、端口访问不了**。

外围功能反而写得很完整：CDN 703 行、cloudflared 管理 517 行、Token 生命周期 275 行。**重心放错了地方**，所以重写而不是打补丁。

---

## 2. 范围

### 2.1 保留

- QUIC 打洞（重写）
- STUN 候选收集（重写）
- 信令（Worker，瘦身 + 多租户）
- 重试与退避（重写为客户端状态机）
- 网络准入（密钥即入，修漏洞）
- TUN 路由与端口映射（重写，旧版是空转）
- 三端交付：CLI、Windows 桌面、Android App

### 2.2 删除

| 删除项 | 行数 | 原因 |
|---|---|---|
| cloudflared 全套管理 | 517 | 通知改走事件轮询，不再需要入站隧道 |
| HTTP 服务（axum） | 256 | 没有任何入站 HTTP 需求 |
| 文件分发 `/files/*` | 303 | 不是本产品职责 |
| CDN 规则引擎 | 703 | 同上 |
| Token 换取/续签 | 275 | 改请求签名，无长生命周期凭证 |
| `virtual_ip` 手工配置 | — | 改为由节点身份派生 |
| `quic_conn_id` | — | 从未被真正使用，quinn 不读它 |
| `Relay` 状态 | — | 没有任何中继实现，只是让失败看起来像成功 |

### 2.3 明确不做

- 文件中转 / CDN / 静态托管
- 公网中继（对称 NAT 直接失败，见 §12）
- 多跳路由（A 经 B 访问 C）
- 反向代理、公网端口暴露
- 云端账号体系、Web 控制台
- 应用商店上架（APK 自签分发）
- 一个节点同时归属多个网络（要跨网络请跑两个实例）

---

## 3. 功能范围（v1 冻结）

### A. 节点与在线

| # | 功能 | 版本 |
|---|---|---|
| F01 | 节点身份，持久化，重启不变 | v1 |
| F02 | 节点命名（人类可读，可改） | v1 |
| F03 | 用密钥加入网络 | v1 |
| F04 | 上线 / 下线 | v1 |
| F05 | 在线状态（在线 / 离线 / 失联），粒度 ≤60s | v1 |
| F06 | 网络内节点列表 | v1 |
| F07 | 节点详情（名称、虚拟地址、状态、版本、最后活跃） | v1 |
| F08 | 主动离开网络 | v1 |
| F09 | 管理员移除成员 | v1.1 |
| F10 | 一个节点同一时刻只归属一个网络 | v1 |

### B. 网络管理

| # | 功能 | 版本 |
|---|---|---|
| F42 | 创建网络，返回一次性密钥 | v1 |
| F43 | 密钥即入（无审批、无申请流程） | v1 |
| F44 | 网络间完全隔离 | v1 |
| F45 | 每个网络独立网段，创建时自动分配，永不重叠 | v1 |
| F46 | 密钥轮换 | v1.1 |

### C. 地址

| # | 功能 | 版本 |
|---|---|---|
| F11 | 自动分配虚拟地址，零配置 | v1 |
| F12 | 地址稳定 | v1 |
| F13 | 地址冲突检测（哈希碰撞自动加盐重算） | v1 |
| F14 | 自定义网段 | v1.1 |

### D. 连接

| # | 功能 | 版本 |
|---|---|---|
| F15 | 按需建连（访问时自动触发） | v1 |
| F16 | 手动连接 / 断开 | v1 |
| F17 | 状态可见（未连 / 打洞中 / 已直连 / 失败） | v1 |
| F18 | 失败自动重试（指数退避） | v1 |
| F19 | 失败原因诊断（卡在哪一步、对端 NAT 类型） | v1 |
| F20 | 连接质量（RTT、丢包、时长） | v1 |
| F21 | 网络切换 / 休眠唤醒后自动恢复 | v1 |
| F22 | 启动预热常用节点 | v1.1 |

### E. 互访

| # | 功能 | 版本 |
|---|---|---|
| F23 | 虚拟地址互 ping | v1 |
| F24 | 访问对端 TCP 端口 | v1 |
| F25 | 访问对端 UDP 端口 | v1 |
| F26 | 端口映射，双向（`-L` / `-R`） | v1 |
| F27 | 访问对端背后局域网（advertise 网段） | v1 |
| F28 | 反向访问（同网络内默认可达） | v1 |
| F29 | 访问控制列表 | v1.1 |
| F30 | 只出不进开关 `--deny-inbound` | v1 |
| F31 | 服务发现 | 不做 |

### F. 运维

| # | 功能 | 版本 |
|---|---|---|
| F32 | 状态总览 | v1 |
| F33 | 自检诊断 | v1 |
| F34 | 日志与级别 | v1 |
| F35 | 后台常驻 + 开机自启 | v1 |
| F36 | 配置文件（CLI/服务） | v1 |
| F37 | 流量统计 | v1.1 |

### G. 安全

| # | 功能 | 版本 |
|---|---|---|
| F38 | 传输加密（默认开，不可关） | v1 |
| F39 | 节点身份认证（证书钉扎） | v1 |
| F40 | 网络密钥准入 + 可选指纹白名单 | v1 |
| F41 | 节点指纹核对 | v1 |
| F47 | 审计日志 | v1.1 |

### H. 三端交付

| # | 功能 | 版本 |
|---|---|---|
| F48 | Linux：CLI + systemd，完整 TUN | v1 |
| F49 | Windows：桌面程序 + 服务，WinTun | v1 |
| F50 | Android：APK + VpnService，**无需 root** | v1 |
| F51 | Windows：配置界面（加入码、节点列表、连接开关、日志） | v1 |
| F52 | Windows：托盘常驻 + 开机自启 | v1 |
| F53 | Android：连接开关 + 节点列表 + 前台服务通知 | v1 |
| F54 | Android：开机自启 | v1 |

---

## 4. 架构

三个面彻底分离；三端共用同一个 core 库，只是外壳不同：

```
      Linux CLI           Windows 桌面            Android
   （前台/systemd）      （GUI + 服务）           （APK + VpnService）
          │                    │                       │
          │               内嵌 core               JNI 内嵌 core
          │                    │                       │
          └────────────┬───────┴───────────┬───────────┘
                       │                   │
              ┌────────▼────────┐   ┌──────▼───────┐
              │   qp2p-core     │   │  TUN 设备     │
              │ punch / link    │◀─▶│  fd 由外壳提供 │
              └────────┬────────┘   └──────────────┘
                       │
   ┌───────────────────┼────────────────────┐
   │                   │                    │
┌──▼───────┐    ┌──────▼──────┐    ┌────────▼───────┐
│ 信令面    │    │  打洞面      │    │   数据面        │
│ HTTPS+WS │    │ UDP 探针     │    │ QUIC 流复用     │
│ Worker   │    │ +Initial    │    │                 │
└──────────┘    └─────────────┘    └────────────────┘
```

| 面 | 协议 | 职责 |
|---|---|---|
| 信令面 | HTTPS 短请求 + 事件轮询 | 登记、发现、撮合、在线状态、网络管理 |
| 打洞面 | UDP（探针 + QUIC Initial） | 在 NAT 上开孔，建立直连 |
| 数据面 | QUIC（裸 QUIC，非 HTTP/3） | 承载互访流量，流复用 |

**三个关键约束**：

1. 三面之间只传递"地址"这一个信息。信令面挂掉，已建立的互访不受影响。
2. 多租户只影响信令面和地址分配。一个节点归属一个网络，每个节点一条轮询流（`/v1/events`）。
3. **core 是库，不是守护进程**。三个外壳各自内嵌，不做跨进程数据转发；只有 Linux 的 CLI 与 systemd 进程之间走一个本地控制 socket（约 150 行），另外两个外壳直接调同进程内的 core。

---

## 5. 模块划分

```
qp2p/
├─ Cargo.toml                       workspace
├─ DESIGN.md
├─ crates/
│  ├─ core/
│  │  └─ src/
│  │     ├─ identity.rs             密钥、node_id、TLS 证书、钉扎      ~130
│  │     ├─ config.rs               配置、校验、默认值                 ~150
│  │     ├─ candidate.rs            候选收集、优先级、去重             ~100
│  │     ├─ socket.rs               PunchSocket，魔数分流              ~220
│  │     ├─ stun.rs                 Binding 请求/响应                  ~150
│  │     ├─ path.rs                 时钟偏移估计、打洞窗口调度         ~120
│  │     ├─ control.rs              本地控制接口（socket / 管道）      ~150
│  │     ├─ peer/
│  │     │  ├─ mod.rs               连接表、生命周期                   ~160
│  │     │  ├─ fsm.rs               纯函数状态机 + Effect              ~220
│  │     │  └─ punch.rs             执行打洞 Effect                    ~180
│  │     ├─ signal/
│  │     │  ├─ mod.rs               join / register / connect / leave  ~190
│  │     │  └─ poll.rs              事件轮询（带游标）、退避重连         ~140
│  │     ├─ link/
│  │     │  ├─ mod.rs               复用层入口                         ~180
│  │     │  ├─ frame.rs             帧编解码                           ~90
│  │     │  └─ flow.rs              flow 表与回收                      ~120
│  │     └─ route/
│  │        ├─ mod.rs               平台无关：路由表、地址管理          ~110
│  │        ├─ forward.rs           双向端口映射                       ~160
│  │        ├─ tun_linux.rs         /dev/net/tun + ip route            ~180
│  │        ├─ tun_windows.rs       WinTun + netsh + 提权检测          ~240
│  │        ├─ tun_android.rs       VpnService fd 接管                 ~60
│  │        └─ icmp.rs              远端应答 echo                      ~60
│  ├─ cli/                          qp2p 二进制（Linux）               ~300
│  ├─ desktop/                      Windows 桌面（egui + 服务模式）     ~600
│  ├─ service/                      Windows 服务与提权安装              ~120
│  └─ jni/                          Android JNI 桥                     ~200
├─ android/                         Kotlin App                         ~700
│  ├─ service/Qp2pVpnService.kt     VpnService + fd 交给 JNI
│  ├─ ui/                           配置页、节点列表、连接开关
│  └─ boot/BootReceiver.kt
├─ signal/                          Worker（单文件，粘贴即可部署）
│  ├─ worker.js                     路由 + 鉴权 + D1/内存双后端         ~600
│  └─ smoke.mjs                     本地测试（内存 + SQLite 冒充 D1）
└─ tests/
   └─ nat_harness/                  NAT 模拟器（UDP 中继）
```

**规模**：

| 层 | 行数 |
|---|---|
| core（协议核心） | ~3520 |
| CLI | ~300 |
| Windows 桌面 + 服务 | ~720 |
| Android JNI | ~200 |
| Kotlin App | ~700 |
| Worker | ~390 |
| **合计** | **~5830** |

对比旧版 5515 行——**几乎持平**。这是这次决策的直接代价：加了 1920 行交付层（GUI、APK、JNI、控制接口），核心从 4926 行降到 3520 行，而旧版那 4926 行里近 2000 行是死功能、1000 行打洞是错实现、410 行 TUN 单向空转。

（上一版说 3760 行，是在"安卓纯二进制、Windows 无界面"的前提下成立的。改为对齐 n2n 的交付形态后，这个数字必须更新。）

---

## 6. 关键设计决策

### D1 单 socket，两个消费者

**决策**：绑一个 UDP socket，包一层 `PunchSocket` 实现 `quinn::AsyncUdpSocket`。首字节 `0x00` 的自定义报文（STUN 响应、打洞探针）走内部逻辑，其余原样交给 quinn。
**理由**：QUIC 报文首字节固定位保证永远不会是 `0x00`，分流无歧义；STUN 观测到的映射**就是** QUIC 用的那条五元组。
**代价**：依赖 quinn 的 `new_with_abstract_socket`，版本升级可能破坏。备选见 §12。

### D2 角色确定，不同时当客户端

**决策**：`node_id` 字典序小的当 dialer（发 QUIC Initial），大的当 listener（发探针、`accept()` 等入站）。
**理由**：QUIC 没有同时打开，双侧客户端只会得到两条连接和一堆没人取的 accept。

### D3 身份来自密钥，不是 URL

**决策**：ed25519 密钥 → `node_id = hex(sha256(pubkey))[:32]`；注册时上报 TLS 公钥指纹，对端用钉扎校验器替代 `SkipVerify`。

### D4 打洞是纯函数状态机

**决策**：`step(state, event, now) -> (state, Vec<Effect>)`，Effect 是 `DialQuic` / `SendProbe` / `RequestPunch` / `WakeAt` 等指令，由 engine 执行。

### D5 时钟用 RTT 估算，不用绝对时间

**决策**：Worker 每个响应带 `server_ms`，客户端按 `offset ≈ server_ms - (t0 + rtt/2)` 做 EWMA 估计，打洞时刻换算成本地单调时钟。
**补充**（借鉴 n2n）：窗口内不只赌一个时刻，每 120ms 重发一次 Initial/探针，抗时钟漂移。

### D6 探针与握手解耦

**决策**：listener 发 `0x00QP2` 魔数的裸 UDP 探针只为开孔；dialer 发 QUIC Initial。两者独立。
**理由**：旧版打洞包就是 Initial，"包被 NAT 丢了"和"握手失败"混成一句 `connection timed out`。

### D7 数据面按 flow 复用

**决策**：一条 QUIC 连接承载全部流量；控制流 1 条，每个 flow 一条双向流；帧格式 `u16 len + IP 包`。
**理由**：旧版每包一条流，流 ID 爆炸且撞上 1000 并发上限。

### D8 端口映射作为补充，不是主力

**决策**：`forward` 双向（`-L`/`-R`）保留，但三端都有 TUN 后它是"只想暴露单个端口"的轻量选项，不再是无权限时的替代品。

### D9 虚拟地址由身份派生

**决策**：每个网络一个独立 `/16`（按网络 id 哈希挑选并跳过已占用的）；节点地址由 `node_id` 哈希派生，碰撞由服务端加盐重算。算法与客户端 `derive_virtual_ip` 完全一致，两边共用一组测试向量。

### D10 额度策略：请求数与节点数解耦

**决策**：一次往返撮合 + 轮询兼心跳（`last_seen` 60s 节流写入）+ 客户端退避 + 事件表按游标增量读取。
**代价**：没有长连接，被动方收到 `punch_request` 会晚 20~60 秒。靠"发起方持续重发"兜住，不靠服务端推送。

### D11 无中继，且诚实

**决策**：不打洞成功就没有路径，不假装有。
**业务后果**：对称 NAT 100% 失败。F19（失败诊断）是必需功能。
**补充**：n2n 有 supernode 转发兜底，我们没有。这是刻意取舍，v1.1 可加"指定节点中继"。

### D12 多租户：横向扩展，不做多归属

**决策**：一个 Worker 承载 N 个互相隔离的网络，每网络一套独立密钥（`HMAC(ADMIN_SECRET, 网络名)`，服务端不存密钥）、一段独立 `/16`。一个节点同一时刻只归属一个网络。
**理由**：多归属要引入多地址、多路由、多连接表，约 +200 行和遍布各处的分支判断，收益只在极少数场景——真要跨网络，跑两个实例即可。

### D13 平台矩阵

| 平台 | 打洞 | 双向映射 | TUN | 交付 |
|---|---|---|---|---|
| Linux x86_64 / aarch64 | ✅ | ✅ | ✅ `/dev/net/tun` | CLI + systemd |
| Windows x86_64 | ✅ | ✅ | ✅ WinTun | exe + 桌面程序 + 服务 |
| Android arm64 / armv7 | ✅ | ✅ | ✅ VpnService（**无需 root**） | 自签 APK |

**关键点**：我们是 L3 隧道，而 VpnService 给的正是 L3 TUN、WinTun 也是 L3——**两端都能 1:1 对接**。n2n 是 L2，所以 Android 上要伪造以太网头（`edge_android_v2.c`），Windows 上必须用 TAP 驱动。我们不需要这些补丁。

### D14 双向映射替代"只能出不能进"

**决策**：`forward` 同时支持 `-L`（本机监听→对端服务）与 `-R`（对端监听→本机服务），供"只想暴露一个端口"的场景。

### D15 core 是库，外壳各自内嵌

**决策**：core 不做成常驻守护进程；CLI、Windows 桌面、Android 各自链接/加载同一份 core。
**理由**：避免为三端各写一套 IPC；Android 本来也只能在进程内通过 JNI 调用；Windows 桌面内嵌 core 后不依赖服务也能独立工作（服务模式是可选）。
**代价**：Linux 多一个约 150 行的控制接口，用于 CLI 与 systemd 进程通信。

### D16 打洞前先试端口映射（借鉴 n2n）

**决策**：启动时尝试 UPnP IGD 与 NAT-PMP，成功则把映射地址作为候选注册。
**理由**：n2n 的日志显示它在打洞前会先敲门（`no IGD UPnP device found`、`NAT-PMP invalid response type`）。家用路由器命中率高，能直接省掉打洞的不确定性，成本约 120 行。

---

## 7. 协议

### 7.1 密钥格式

```
qp2p1_<network_id>_<secret>
```

`network_id` 让客户端联网前就知道找哪个网络，`secret` 只用于 HMAC 鉴权，Worker 端只存 `sha256(secret)`。

### 7.2 信令 API

除 `admin` 外全部签名：`HMAC-SHA256(secret, method + path + body + ts)`，时间戳窗口 ±60s。

| 方法 | 路径 | 鉴权 | 用途 | 频次 |
|---|---|---|---|---|
| GET | `/v1/health` | 无 | 健康检查 | 手动 |
| POST | `/v1/admin/networks` | `ADMIN_SECRET` | 创建网络，**仅此一次返回密钥** | 建网时 |
| POST | `/v1/join` | 密钥 | 校验密钥，返回网络信息与网段 | 加网时 |
| POST | `/v1/register` | 网络密钥 | 上报节点信息，返回虚拟地址与节点列表 | 启动 + 网络变化 |
| POST | `/v1/connect` | 网络密钥 | 撮合：带自身候选，取回对端候选 | 每次打洞 |
| POST | `/v1/leave` | 网络密钥 | 主动下线 | 退出时 |
| GET | `/v1/events` | 网络密钥 | 按游标拉取待处理事件（`$since`） | 在线期间每 20~60s |

`register` 请求体：

```json
{
  "node_id": "3f9a1b2c3d4e5f60718293a4b5c6d7e8",
  "name": "nas",
  "pubkey": "hex(ed25519 公钥, 64 字符)",
  "tls_fp": "hex(sha256(cert_spki))",
  "candidates": ["192.168.1.10:51820", "203.0.113.5:51820"],
  "nat_type": "port_restricted",
  "advertise": ["192.168.1.0/24"]
}
```

- 网络由令牌里的网络 id 决定，请求体不重复携带
- `node_id` 必须等于 `sha256(pubkey)[..32]`，服务端强制校验
- `candidates` 可以是 `"ip:port"` 字符串，也可以是 `{"type": "...", "addr": "..."}`，服务端归一化成字符串
- 没有 `ts`：时间对齐靠响应里的 `server_ms` 加客户端 EWMA 估计

### 7.3 事件（轮询）

`GET /v1/events?node_id=&since=<游标>` 返回 `{cursor, events[]}`，游标取上一批最后一条的 `seq`。

| 类型 | 载荷 |
|---|---|
| `punch_request` | 发起方 node_id、候选、打洞时刻 `t`、`server_ms` |

只保留最近 5 分钟的事件（后台按间隔清理），所以节点离线久了只会拿到"最近有人找你"，
拿不到历史。列表类变化（谁上线了）不走事件，由 `register` 的 `peers` 直接返回。

### 7.4 打洞探针

```
0x00 'Q' 'P' '2' | type:u8 | txid:u32 | ...
type: 0x01 PROBE / 0x02 PROBE_ACK / 0x03 STUN_RESPONSE
```

### 7.5 控制流帧

`u8 type | u16 len | payload`，类型：`HELLO`（版本/能力/MTU/network_id）、`ROUTES`（可达网段）、`PING`。

### 7.6 数据流帧

`u16 len | ip packet`，一条流承载一个 flow 的全部包，双向。

### 7.7 本地控制接口

Linux：`$data_dir/control.sock`；Windows：命名管道 `\\.\pipe\qp2p-<user>`。
命令：`status` / `connect <peer>` / `disconnect <peer>` / `reload` / `quit`，单行 JSON 请求响应，仅本机可访问。

---

## 8. 配置与部署

```toml
node_name = "nas"
data_dir  = "/var/lib/qp2p"
stun      = ["stun.cloudflare.com:3478", "stun.l.google.com:19302"]
listen    = "0.0.0.0:51820"
upnp      = true          # 打洞前先试 UPnP / NAT-PMP

[network]
id           = "home-3f9a"
token        = "qp2p1_home-3f9a_x"
route        = "tun"                # tun | forward | off
advertise    = ["192.168.1.0/24"]
deny_inbound = false

[[forward]]
listen  = "127.0.0.1:8080"
peer    = "nas"
target  = "10.64.1.7:80"

[[forward]]
listen  = "0.0.0.0:3389"
reverse = true
peer    = "b21c..."
target  = "127.0.0.1:3389"
```

| 平台 | 交付与常驻 |
|---|---|
| Linux | 单二进制 + `config.toml` + systemd（`CAP_NET_ADMIN`） |
| Windows | 绿色版目录（exe + `wintun.dll`）→ 桌面程序配置 → 可选注册为服务（SYSTEM）常驻 |
| Android | 自签 APK，前台服务 + 通知，Boot 自启，配置在 App 内 |

Windows 首次运行需管理员权限创建 WinTun 适配器并下发路由；无权限时降级为 `forward` 模式并明确提示。

D1 表结构：

```sql
CREATE TABLE networks (network_id TEXT PRIMARY KEY, name TEXT NOT NULL,
                       token_hash TEXT NOT NULL, cidr TEXT NOT NULL,
                       created_at INTEGER NOT NULL);
CREATE TABLE nodes (node_id TEXT NOT NULL, network_id TEXT NOT NULL,
                    name TEXT NOT NULL, pubkey TEXT NOT NULL, tls_fp TEXT NOT NULL,
                    virtual_ip TEXT NOT NULL, nat_type TEXT, advertise TEXT,
                    last_seen INTEGER NOT NULL, created_at INTEGER NOT NULL,
                    PRIMARY KEY (network_id, node_id));
```

---

## 9. 旧代码处置

| 文件 | 行数 | 处置 | 说明 |
|---|---|---|---|
| `tunnel.rs` | 517 | 删 | 通知改走事件轮询 |
| `auth.rs` | 275 | 删 | 改签名鉴权 |
| `cdn/*` | 703 | 删 | 功能移除 |
| `http/files.rs` | 303 | 删 | 功能移除 |
| `http/notify.rs` | 102 | 删 | 改走 WS |
| `http/health.rs` | 89 | 删 | 状态从内存读 |
| `http/mod.rs` | 65 | 删 | 不再有入站服务 |
| `tun.rs` | 410 | 重写 ~480 | 拆三平台，Windows 换 WinTun，Android 接 VpnService fd |
| `holepunch/*` | 1151 | 重写 ~1000 | STUN 映射错误、双侧客户端 |
| `config.rs` | 521 | 重写 ~150 | 单网络 |
| `types.rs` | 401 | 拆散 | 类型归各自模块 |
| `main.rs` | 389 | 重写 ~300 | 三端入口替代单一 main |
| `worker.js` | 589 | 重写 ~600 | 单网络 → 多租户；DO + D1 + 多文件 → 单文件 + D1 |

依赖变化：删 `axum`、`httpdate`、`base64`、`which`、`nix`；加 `socket2`、`if-addrs`、`ed25519-dalek`、`hmac`、`tokio-tungstenite`、`wintun`、`egui`（桌面）。CI 增加 `aarch64-linux-android` / `armv7-linux-androideabi` 目标（cargo-ndk）与 APK 构建。

---

## 10. 实施阶段

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| **P0** | 打 tag 保留旧版；建 workspace；CI（fmt / clippy / test / 五目标构建） | `cargo test` 绿，旧 tag 可回退 |
| **P1** | 纯逻辑：候选排序去重、STUN 解析、时钟偏移、Peer FSM | 单测覆盖，不碰网络 |
| **P2** | `PunchSocket` + 同 socket STUN + UPnP/PMP + NAT 模拟器 | 模拟 3 类 NAT 行为符合预期 |
| **P3** | link 复用层 + 本机双实例 | `forward -L` 打通 127.0.0.1:8080 |
| **P4** | CLI + 控制接口 + 双向映射 | 两个本机进程互为服务端与客户端 |
| **P5** | Linux TUN + 路由下发 + ICMP 应答 | `ping` 与局域网 IP 可达 |
| **P6** | Windows 核心：WinTun + 提权 + 服务模式 | Windows 与 Linux 互访，双向都通 |
| **P7** | Windows 桌面：配置页、节点列表、托盘、日志 | 非技术用户可完成加入→连接→访问 |
| **P8** | Android：JNI + VpnService + 界面 + APK 打包 | 手机与 PC 互访，无需 root |
| **P9** | 信令 Worker：单文件 + D1，粘贴即可部署 | 同一 Worker 下两个网络并行不串味；`node signal/smoke.mjs` 全绿 |
| **P10** | 真实网络验收（家宽 + 4G）、文档、v1.0 | 指标达标（§13） |

P3 之后每一步都是可独立演示的功能增量。

---

## 11. 额度预算（免费额度 10 万/天）

| 手段 | 效果 |
|---|---|
| 一次往返撮合 + 增量拉事件 | 每节点 60s 一次 ≈ 1,440 次/天，且不含额外通知请求 |
| 一次往返撮合 | 单次打洞从 3 请求 → 1 请求 |
| 热点数据放 DO 内存，`last_seen` 60s 批量刷 D1 | 读次数与请求数解耦 |
| NAT 类型元数据（cone 型免通知） | 通知量减半 |
| 客户端指数退避 | 失败节点不再每 15s 烧一次请求 |
| 列表缓存 60s | 界面刷新不打服务端 |

50 节点、日打洞 500 次：

```
启动 50 + 重连 100 + 打洞 500 + 轮询 50×1,440 ≈ 72,650 次/天（73% 请求额度）
写入 50×1,440 ≈ 72,000 行/天（72% 写额度）
```

额度与**节点数**线性相关，与网络数无关。所以 50 节点是免费额度的上限附近；
要带更多节点就得拉长轮询间隔，或者回到需要 Durable Object 的长连接方案。

**降级**：Worker 返回 429 时进入 signaling-offline 模式——已建立连接保持、用缓存候选继续重试、暂停列表刷新，界面明确提示"信令不可用，直连不受影响"。

---

## 12. 风险与备选

| 风险 | 影响 | 备选 / 缓解 |
|---|---|---|
| quinn `AsyncUdpSocket` 接口变动 | 单 socket 方案受阻 | 启动时先在裸 socket 完成 STUN，再把同一 socket 交给 `Endpoint::new` |
| 免费额度按节点数线性消耗 | 节点数一多就打满 | 60s 轮询为默认；超限后客户端退化为只读缓存，已建连接不受影响 |
| 对称 NAT | 100% 失败，无兜底 | 业务接受；`doctor` 前置告知；v1.1 可加节点中继 |
| WinTun 需管理员权限 | 首次体验断裂 | 无权限时降级 `forward` 并提示；服务模式用 SYSTEM 绕开 |
| APK 自签分发 | 用户需手动允许安装 | 文档 + 应用内检查更新；不上架 |
| Android 后台被杀 | 轮询与打洞都停 | 前台服务 + 通知（F53）+ 重连退避 |
| GUI 维护成本 | Windows 前端长期负担 | 只做三页（配置 / 节点 / 日志），不做皮肤和动画 |
| 多租户网段重叠 | 路由冲突 | 创建网络时从 `10.64.0.0/10` 顺序分配 `/16`，永不重叠 |
| 网络切换后地址漂移 | 连接中断 | 心跳检测 + 重建 endpoint + 重新注册 |

---

## 13. 验收标准

| 项 | 目标 |
|---|---|
| 同 NAT 打洞成功率 | ≥ 95% |
| 双 NAT（cone） | ≥ 85% |
| 对称 NAT | 明确失败 + 可读原因（不假装成功） |
| 建连时延 | p50 < 1.5s，p95 < 3s |
| 空闲资源 | 桌面 CPU < 0.5%，RSS < 80MB（含 GUI）；移动端 RSS < 60MB |
| 资源泄漏 | flow 表、accept 队列、连接表均有上限并可回收 |
| 稳定性 | 所有错误路径零 panic；7×24 无泄漏 |
| 三端互访 | Linux / Windows / Android 三者两两互 ping、互访端口均通过 |
| 安装体验 | Windows 双击可用；Android 安装后三步内连上 |
| 多租户 | 同一 Worker 下 4 个网络并行，成员、地址、流量互不串味 |
| 额度 | 50 节点单网络日请求 < 5,000 |

---

## 14. 默认决策（可推翻）

| 项 | 默认 |
|---|---|
| 网络模型 | 多租户：一个 Worker 承载多个互相隔离的网络 |
| 准入方式 | 密钥即入，无审批；可选指纹白名单 |
| 单节点网络数 | 1，切换网络即离开旧网络 |
| 网段分配 | 创建网络时自动分配 `/16`，不可手工指定（v1.1 开放） |
| 双向访问 | 同网络内默认互达，提供 `--deny-inbound` 单向阀 |
| 交付形态 | Linux CLI / Windows 桌面 + 服务 / Android 自签 APK |
| Windows 前端 | egui 单文件 exe，三页：配置、节点、日志；附带服务模式 |
| Android 前端 | 极简：连接开关 + 节点列表 + 配置页；前台服务通知 |
| 虚拟网卡 | Linux TUN、Windows WinTun、Android VpnService |
| 在线粒度 | 60 秒 |
| 中继 | 不做（v1.1 可选"指定节点中继"） |
| UPnP / NAT-PMP | 默认开启，可关 |
