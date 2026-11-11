# qp2p 信令服务 v3 设计文档

Durable Object + WebSocket 混合架构 · 定稿 v1.1 · 2026-11-11 · 基线：signal 2.5.0、qp2p core、原型验证结果

## 0. 阅读指南

本文按「事实 → 架构 → 数据 → 协议 → 函数规格 → 客户端 → 部署器 → 流程 → 耦合 → 容量/安全/测试 → 路线图」组织。标记约定：**\[现有\]** 已存在，沿用或小改；**\[新增\]** 需要新写；**\[待验证\]** 尚无实测依据，编码前或对应阶段必须验证。

**修订记录**

- **v0.2**（2026-11-09）：①不做在线数据迁移，升级一律由用户重新部署，因此删除了 `setNetworkEngine`、`importState`、逐网络 engine 字段与原 F6 的迁移流程；②新增 Android 端「保存配置」「启动马上连接」两个按钮（§7.3）；③更正降级语义：只有 WebSocket 不可用（代理拦截、握手失败）才退回轮询，DO 额度耗尽时轮询同样不可用。
- **v1.1**（2026-11-11，评审后）：①`sweep` 触发点补 WebSocket 消息入口——B4 之后它是唯一的 GC 来源（§6.3）；②新增「连接代次」规则，解决自己重连时被 4000 误停的问题（§5.2、§7.1）；③V14 确认通过，写入 Free 计划额度（§2）；④V9 的机器验证前移到 P1，并明确它同时决定 §11 的 ping 折算是否成立（§2、§15）；⑤§11 补「多网络放大」与「混合期最坏情况」两个场景；⑥`region_hint` 降级为调试参数（§16）；⑦P6 验收补「固定 IP 预留核对」（B2 未提前的代价），回退场景补数据可见性说明（§8.4、§15）。

**定稿说明**：v1.0（2026-11-09）：V9（保活与自动应答）由用户确认通过，不再作为阻塞项（我没有看到测试日志，未经复核）；原未决问题 1～4 按推荐默认值定稿，见 §16；其余待验证项 V10～V14 在对应阶段验收。

## 1. 目标、非目标与约束

**现状（signal 2.5.0）**：Worker + D1。节点按 HOT 3 秒 / WARM 20 秒 / COLD 60 秒轮询 `GET /v1/events`，轮询兼作心跳（D1 写入按 55 秒节流）；`register` 每 30 分钟一次，约 8 次读 + 3 次写；新节点或打洞请求最长要等 60 秒才被对端看到；Worker 内存模式在多区域下互相不可见。

**目标**

- G1 事件推送：`punch_request`、`peer_online` 的送达延迟降到约一个往返（实测 RTT 约 200 ms）。
- G2 降本：心跳不落库；每节点每天的 Worker 调用从 1,440～4,320 次降到约 60 次。
- G3 免费计划可用；WebSocket 不可用（被代理拦截、握手失败）时自动降级为轮询；DO 额度耗尽时新连接与地址刷新会暂停，靠告警线提前发现。
- G4 兼容：旧客户端、管理页、令牌格式、签名协议不变；服务端升级通过重新部署完成，不提供在线数据迁移。
- G5 一键部署，不依赖 Node 或 wrangler。
- G6 模块边界清晰，可逐块优化升级。

**非目标**：不改 QUIC 数据面与 TUN；不做中继；不改 Ed25519 身份与令牌格式；不做多区域副本；本期不移除 D1。

**设计约束（来自官方文档与实测）**

- 免费计划 DO 额度：请求 10 万/天，时长 1.3 万 GB·秒/天，SQLite 读 500 万行/天、写 10 万行/天；超限该类操作报错，UTC 0 点恢复。
- 休眠不变量：DO 内不得有 setTimeout/setInterval、未完成 I/O、出站 WebSocket/TCP，否则不休眠且持续计时长；闲置约 10 秒后才可能休眠；休眠后内存全部丢失、构造函数重跑，因此**一切需要保留的状态必须在 SQLite 或 WebSocket attachment 里**。
- WebSocket 计费：入站消息按 20:1 折算请求，出站免费；`setWebSocketAutoResponse` 的应答不唤醒对象、不额外计时长。
- 单 DO 单线程，软上限约 1,000 请求/秒；每网络最多 256 节点，余量充足。
- 免费计划只支持 SQLite 后端；类迁移标签线性递增，`old_tag` 必须等于线上当前标签。
- 浏览器原生 WebSocket 不能带自定义请求头，握手需同时支持 `Authorization` 头与 `?token=`。

## 2. 原型验证结论（事实基础）

原型：单 Worker + `Room` 类 + curl 部署脚本 + 内嵌测试页，部署在你的账号（workers.dev 子域 coj）。

| 编号 | 验证项 | 结果 | 数据 | 结论 |
| --- | --- | --- | --- | --- |
| V1 | API 部署含 DO 类 | 通过 | 上传成功；响应含 named\_handlers: Room、migration\_tag | 部署器路线可行 |
| V2 | 迁移标签链 | 通过 | v1→v2 成功；old\_tag=bogus 被拒，错误码 10079 | 部署器必须读取线上当前标签 |
| V3 | 启用 workers.dev | 通过 | 返回 enabled:true；previews\_enabled 默认也是 true | 部署器显式关闭预览 |
| V4 | 握手与定向推送 | 通过 | 握手 441/454 ms；单向约 192/228 ms | 信令场景可接受 |
| V5 | 往返延迟 | 通过 | min/中位/max = 186/198/227 ms | 取决于网络与 DO 所在位置，需做 locationHint 对比 |
| V6 | 休眠且连接不断 | 通过 | 加入 7 分钟后 /debug：bootAt 等于当前时刻，两连接 hibernatedSinceJoin 均为 true，之后广播仍送达；wakes 12→15（每次交互唤醒一次） | 休眠成立 |
| V7 | 握手验签 CPU | 通过 | 面板 p99 1.5 ms（免费 Worker 上限 10 ms） | 验签可放在握手阶段 |
| V8 | 休眠态部署 | 通过 | CODE\_ONLY=1 部署后连接未断 | 符合官方「延迟应用代码更新」 |
| V9 | 保活与自动应答 | 通过（用户确认，**机器验证前移到 P1**） | 用户自测保活正常（未提供日志，我未复核） | 这是在线判定的单点依赖，P1 必须补两条机器验证：① 25 秒一次 ping、60 秒后 `getWebSocketAutoResponseTimestamp` 确实在推进；② ping/pong 自动应答**不产生计费请求**（直接决定 §11 的 173 次折算成不成立）。任一不成立都要按 R1 重估配额 |
| V10 | 活跃态部署 | 未测 | — | 阶段 P4 演练 |
| V11 | 24 小时用量核对 | 未测 | — | 阶段 P3 之后 |
| V12 | keep\_bindings 后密钥仍有效 | 未测 | — | 用原测试链接重连即可确认 |
| V13 | locationHint 对延迟的影响 | 未测 | — | 阶段 P7 |
| V14 | 账号计划确认 | **通过** | 已确认 Free 计划：Requests 100,000/天、Duration 13,000 GB·秒/天；Requests 含 HTTP、RPC、WebSocket 消息与 alarm 调用；只有超出月/日免费额度的部分才计费 | 容量模型的前提成立；瓶颈是请求数而非时长（见 §11） |

**结论**：可以进入设计与实现；V9 已由用户确认通过（日志未提供，未经我复核），其余在对应阶段验收。

**资料来源**（Cloudflare 官方文档，2026-10/11 版）：Durable Objects Pricing、Limits、WebSocket Hibernation API、Code updates 变更日志（2026-10-30）、Workers Limits、Worker 脚本上传 API 的 multipart metadata。

## 3. 总体架构

```
客户端(Rust)
  ├─ HTTPS 签名请求：join / register / leave / health（频率低）
  └─ WebSocket：/v1/ws（事件推送、connect、保活）
        │
Edge Worker（无状态路由）
  ├─ 限流 / CORS / 体积限制 / 令牌鉴权（读 D1 networks，isolate 缓存 15 秒）
  ├─ 管理面 /admin、/v1/admin/*（D1：networks、admin_users、audit、login_attempts）
  └─ 按 network_id → idFromName 转发（附 x-qp2p-net 网络上下文）
        │ 内部请求
NetworkRoom（每网络一个 DO，SQLite）
  ├─ 数据面权威：nodes / reservations / events / nonces
  ├─ 在线判定：WebSocket 存活 + 自动应答时间戳；轮询节点用 last_seen
  └─ 推送：在线 socket 直接 send；离线或轮询节点落 events 供拉取
D1：控制面权威（networks、admin_*）；未绑定 DO 的 Worker 仍走 legacy（D1 数据面）
```

**数据归属**

| 数据 | 权威位置 | 读写方 | 说明 |
| --- | --- | --- | --- |
| networks（名称、网段、join\_hash、region\_hint） | D1 | Worker | isolate 缓存 15 秒；变更后主动失效并通知 DO |
| admin\_users / login\_attempts / admin\_actions | D1 | Worker | 管理面，保持不变 |
| nodes（身份与地址） | 绑定了 DO：DO SQLite；未绑定：D1（legacy） | DO / Worker | 同一网络同一时刻只有一个权威 |
| reservations、events、nonces | 同上 | 同上 | events、nonces 是瞬态，TTL 5 分钟 |
| 在线状态 | room：活跃 WebSocket + 自动应答时间戳；轮询节点用 last\_seen | DO | 心跳不落库 |

**引擎选择**：由 Worker 是否绑定 `ROOM`（DO）决定，与具体网络无关：绑定了就全部网络走 room，没绑定就走 legacy（D1 加轮询，兼容自托管的 Node dev-server）。**不提供在线迁移**：升级到 v3 一律由用户重新部署。节点数据本就是瞬态，节点重新 register 即恢复；网络、令牌、管理员账号保存在 D1，原样保留；手填的固定 IP 预留需要管理员重设（备份恢复见 B2）。

**信任边界**：DO 没有公网路由，只能被同一 Worker 通过绑定调用；`x-qp2p-net` 由 Worker 构造，Worker 入口会先剥离客户端带来的所有 `x-qp2p-*` 头。

## 4. 数据模型

### 4.1 D1 变更（仅增量）

- `networks` 新增列 `region_hint TEXT NOT NULL DEFAULT ''`（DO 首次创建时的 locationHint，如 apac）。
- 其余表不变；绑定 DO 后，nodes、events、nonces、reservations 这几张数据面表不再使用，旧数据闲置在 D1 里，不迁移、不清理。

### 4.2 NetworkRoom 的 SQLite（schema\_version = 1）

| 表 | 列 | 说明 |
| --- | --- | --- |
| nodes | node\_id PK、name、pubkey、tls\_fp、virtual\_ip UNIQUE、nat\_type、advertise、candidates、candidates\_at、last\_seen、first\_seen | candidates\_at 是地址最后上报时间，与 last\_seen 分离 |
| reservations | ip PK、node\_id、kind(user/auto)、note、created\_at | 语义同现有 |
| events | id INTEGER PK AUTOINCREMENT、to\_node（node\_id 或 \*）、type、payload、created\_at；索引 (to\_node, id) | seq 即 id，按网络单调递增 |
| nonces | nonce PK、created\_at | 仅握手、leave、connect 成功路径使用 |
| meta | k PK、v | net（网络上下文 JSON）、schema\_version、epoch、last\_sweep |

### 4.3 WebSocket attachment（不超过 2 KB，休眠后保留）

字段：node（node\_id）、joinedAt、caps（客户端能力列表）、v（协议版本）。

### 4.4 仅内存（休眠即丢，必须可丢）

每 socket 的限流令牌桶、本次唤醒期内的统计计数。除此之外不允许放任何业务状态。

## 5. 协议

### 5.1 HTTP（语义不变）

`/v1/join`、`/v1/register`、`/v1/connect`、`/v1/leave`、`GET /v1/events`、`/v1/health`、`/v1/admin/*` 的请求与响应格式保持不变。仅两处增量：`/v1/health` 追加 `engine`、`features`（含 `ws`）、`room_bound`；新增端点 `GET /v1/ws`。

### 5.2 WebSocket 握手 `GET /v1/ws`

- 查询参数：`node_id`、`ts`、`nonce`、`sig`，可选 `since`（断线重连的游标）、`caps`（逗号分隔）、`token`（无法带头的客户端）。令牌也可用 `Authorization: Bearer`。
- 签名：复用现有规则，签名消息是 `qp2p1`、op、网络 id、ts、nonce、摘要六项用竖线连接；op 固定为 `ws`，摘要是 canonicalJson 化的 node\_id、since、ts、nonce、caps 的 SHA-256。**签名消息格式冻结，只允许追加新 op。**
- 前置条件：节点必须已通过 HTTP join 或 register 登记（pubkey 来自登记记录）。未登记返回 404 `unknown_node`，客户端应先 register 再重连。
- 同一 node 只允许一条 socket：新连接到来时旧连接以 4000 关闭。客户端必须按「连接代次」处理：自己发起重连时把旧连接标为 superseded，旧代次收到的任何 Closed 都丢弃，不上报 Down（见 §7.1）。否则网络切换时旧 socket 半开、客户端先重连、服务端以 4000 关掉旧连接，这条 4000 会落到同一进程里，客户端照表执行就会把自己刚建好的新连接停掉。

握手失败（升级前）沿用现有错误结构 `{ok:false, error, detail}`：401 令牌格式、403 验签/重放/密钥错误、404 未登记、426 缺少 Upgrade、501 未绑定 DO（客户端退回轮询）、429 握手限流、503 `room_unavailable`（DO 异常或额度耗尽；WebSocket 与轮询同样受影响，客户端按 1 到 60 秒退避重试，已建立的隧道不受影响）。

**关闭码**

| 码 | 含义 | 客户端动作 |
| --- | --- | --- |
| 1000 | 正常关闭 | 不重连（用户主动） |
| 1012 | DO 重置或服务重启 | 带抖动重连 |
| 4000 | 被同 node 的新连接替换 | 若来自本端已 superseded 的旧连接（自己重连导致），直接丢弃；只有当前代次收到时才提示可能有多个实例 |
| 4401 | 令牌失效、被踢、密钥已轮换 | 停止并要求重新加入 |
| 4410 | 网络已删除 | 停止 |
| 4429 | 消息限流 | 退避后重连 |
| 4500 | 服务端内部错误 | 带抖动重连 |

### 5.3 WebSocket 消息

文本帧，JSON，字段 `t` 表示类型；保活用裸字符串 `ping` / `pong`，由运行时自动应答。

| 方向 | t | 字段 | 语义 |
| --- | --- | --- | --- |
| 服务端→客户端 | hello | v、server\_ms、cursor、epoch、limits | 握手成功后第一条；cursor 是当前最大 seq；limits 下发 ping 间隔与宽限 |
| 服务端→客户端 | event | seq、type 及原有载荷字段 | type 取 punch\_request、peer\_online，新增 peer\_offline；除 `punch_at` 外字段与 HTTP 事件完全一致（见下方字段名冲突说明） |
| 服务端→客户端 | connect\_ok / error | req、与 HTTP ConnectReply 同构的字段 或 error、detail | 对客户端 connect 的应答；打洞时间同样叫 `punch_at` |
| 服务端→客户端 | resume\_ok | cursor | resume 补发结束的标记（不是逐事件 ack），客户端可忽略 |
| 服务端→客户端 | kick | reason | 随后以 4401 关闭 |
| 客户端→服务端 | connect | req、target | 请求撮合；身份取自 socket，不再逐条签名 |
| 客户端→服务端 | resume | since | 补发 seq 大于 since 的事件（最多 50 条、5 分钟内） |
| 客户端→服务端 | leave | — | 正常下线，随后服务端以 1000 关闭 |

**字段名冲突（实现时发现）**：消息类型占用 `t`，而 `punch_request` 载荷里的 `t` 是打洞时间戳——平铺必然互相覆盖。约定：**WS 侧载荷的 `t` 改名 `punch_at`**，消息类型仍是 `t`；HTTP 的 `/v1/connect` 与 `/v1/events` 字段名不变，客户端只在 WS 解析处读 `punch_at`。`peer_offline` 用 `seq: 0` 表示不占序号、不落库。

**刻意不做**：逐事件 ack（每次都会唤醒 DO 并计入请求）。游标由客户端自己保存，重连时用 `since` 或 `resume` 补齐。

### 5.4 Worker 与 NetworkRoom 的内部路由

| 内部路径 | 调用方 | 作用 |
| --- | --- | --- |
| POST /i/join、/i/register、/i/connect、/i/events、/i/leave | Worker 适配层 | 承接同名 HTTP 业务，DO 内验签并执行 |
| GET /i/ws | Worker wsEntry | WebSocket 升级、握手验签、接入 Hibernation |
| POST /i/init、/i/net-updated、/i/purge | 管理面 | 建网、配置变更、清除 |
| GET /i/admin/nodes、/i/admin/reservations、/i/stats、/i/debug | 管理面、诊断 | 节点与预留查询、统计 |
| POST /i/admin/kick、/i/admin/reserve、/i/admin/release | 管理面 | 踢人、预留、释放 |

## 6. 服务端模块与函数规格

约定：每行给出「函数、状态、职责、入参→交付、依赖与副作用」。除特别说明，函数都在 `signal/worker.js` 内（P7 再拆模块）。

### 6.1 Edge Router（入口层）

| 函数 | 状态 | 职责 | 入参 → 交付 | 依赖 / 副作用 |
| --- | --- | --- | --- | --- |
| `fetch(request, env, ctx)` | 现有·小改 | 总入口：限流 → CORS → 体积限制 → `route`；捕获 DO 异常（含额度耗尽）并转成 503 `room_unavailable` | Request → Response | `limited`、`route` |
| `route(request, url, env, ctx)` | 现有·扩展 | 路径分发；新增 `/v1/ws`；业务端点先判 `roomEnabled` | → Response | 全部处理函数 |
| `authenticate(request, env, url)` | 现有·小改 | 解析令牌、校验 join\_hash（兼容旧令牌）、返回 network | → `{ok, network}` 或错误响应 | `getNetworkCached` |
| `getNetworkCached(env, id)` | 新增 | isolate 内 Map，TTL 15 秒；未命中读 D1 | 网络 id → network 或 null | D1 `networks` |
| `invalidateNetwork(id)` | 新增 | 管理变更后清缓存（同 isolate 即时，其他 isolate 最多滞后 15 秒） | — | 管理面写路径调用 |
| `roomEnabled(env)` | 新增 | 绑定了 `ROOM`（DO）则全部网络走 room，否则走 legacy；与网络无关 | → 布尔 | 纯函数 |
| `roomStub(env, network)` | 新增 | `ROOM.get(ROOM.idFromName(network_id))`；`region_hint` 作为 locationHint（仅 DO 首次创建时生效，**待验证 V13**） | → DO stub | `env.ROOM` |
| `netContext(network)` | 新增 | 构造 `x-qp2p-net`：版本 v、id、name、cidr；**不含 join\_hash** | → JSON 字符串 | — |
| `forwardToRoom(request, env, network, path)` | 新增 | 剥离客户端的 `x-qp2p-*`，附上 net 头，转发到 `/i/*`，透传 body 与查询串，原样返回 DO 响应 | → Response | `roomStub`、`netContext` |
| `wsEntry(request, env, url)` | 新增 | 校验 Upgrade（否则 426）；握手限流；`authenticate`；未绑定 DO 时返回 501（客户端退回轮询）；转发 `/i/ws` | → 101 或错误 | `forwardToRoom` |
| `joinOrRegister` / `connect` / `events` / `leave` | 现有·改造 | 函数开头判 `roomEnabled`：是 → `forwardToRoom`；否 → 原 legacy 逻辑（**保留，不删除**） | — | 现有 D1 逻辑 |
| `health(request, env)` | 现有·扩展 | 追加 engine（room 或 legacy，由绑定决定）、features、room\_bound；带管理密钥时追加网络数、socket 总数（并发查 DO `/i/stats`，上限 8 路） | → JSON | `/i/stats` |
| `limited(request, max)` | 现有 | 每 IP 每分钟限流；WS 握手单独一个桶，每 IP 每分钟 30 次 | → 布尔 | isolate 内存桶 |

### 6.2 控制面（D1 为权威）

| 函数 | 状态 | 职责与交付 |
| --- | --- | --- |
| `createNetwork` | 改 | 新增参数 `region_hint`；绑定了 DO 时调用 `/i/init` 写 meta.net，DO 按 region\_hint 创建 |
| `rotateJoinKey` | 改 | 更新 join\_hash 后调用 `/i/net-updated`（rotated），DO 以 4401 关闭全部 socket，持旧令牌的节点必须重新加入 |
| `updateNetwork` | 改 | 更新名称/网段，`invalidateNetwork` + `/i/net-updated`；网段变化沿用现有语义：下次 register 才重新分配地址 |
| `deleteNetwork` / `purgeNetwork` | 改 | D1 清理后调用 `/i/purge`：以 4410 关闭 socket 并清空 SQLite |
| `listNetworkNodes` / `kickNode` / `kickNodes` / `reserveIp` / `releaseIp` / `listReservationsAdmin` | 改 | 按 `roomEnabled` 分派到 legacy 实现或 `/i/admin/*`；返回字段保持一致，仅新增 `via`（ws 或 poll） |
| `nodeCounts` / `onlineCounts` / `reservationCounts` | 改 | 绑定了 DO 时并发（上限 8）调用 `/i/stats`；失败置 0 并标记 `stale: true`，不拖垮列表接口 |
| `sweep(env)` | 现有 | 未绑定 DO 时清理 legacy 数据面表；绑定 DO 后由 DO 自行清理 |

### 6.3 NetworkRoom（核心）

存储接口说明：原型只验证了 KV 接口（`storage.get/put`）。本设计使用 SQL 接口（`storage.sql.exec` 与 `transactionSync`），**属 \[待验证\]，P1 第一步先在测试 Worker 上跑通**；Node 本地测试用 `node:sqlite` 做替身。

**A. 生命周期**

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `constructor(state, env)` | 注册自动应答（ping→pong）；`blockConcurrencyWhile` 内执行 `initSchema` 并读 meta | 就绪对象；**不得有任何定时器**；不落盘 wakes（原型每次唤醒写一行，生产版取消，仅内存保留 bootAt 供诊断） |
| `initSchema()` | 幂等建表；读 `schema_version`，按序执行内部迁移 | DO 类名冻结为 `NetworkRoom`，结构演进靠内部迁移，避免走类迁移 |
| `fetch(request)` | 按 §5.4 分发；统一错误体 `{ok:false, error, detail}`；未知路径 404 | 先调 `loadNet` |
| `loadNet(request)` | 读取并校验 `x-qp2p-net`；与 meta.net 不同则写入；缺失时回退 meta.net（WebSocket 唤醒后处理消息需要） | → 网络上下文 |

**B. 鉴权与防重放**

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `verifyReq(op, body, pubkey, {trackReplay})` | 复用 `canonicalJson`、`bodyDigest`、`signingMessage`、`verifySignature`；ts 窗口 ±120 秒 | → null 或错误文本；与现有 `verifySignedRequest` 行为逐字一致 |
| `consumeNonce(nonce, now)` | `INSERT … ON CONFLICT DO NOTHING`，返回是否首次 | 1 行写入 |

**C. 业务（HTTP 适配与共享核心）**

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `handleJoinRegister(body, needCandidates)` | 移植 `joinOrRegister`：校验 node\_id 等于 sha256(pubkey) 前 32 位、验签（幂等不占 nonce）、容量与僵尸淘汰、IP 分配与预留、upsert、状态变化时 emit peer\_online | → 与现有一致的 JSON（network、node、peers、durable、server\_ms）；原先约 8 读 3 写的 D1 往返变成本地调用 |
| `allocateIp(net, nodeId, others, reservations)` | 移植 `validateVirtualIp` 与 `assignIp`；优先级：本次指定 > 已有 > 自己的预留 > 自动分配 | → ip 或错误；纯 SQLite |
| `matchmake(fromId, targetId, now)` | 撮合核心：目标存在、在线、地址未过期（candidates\_at 与 STALE\_MS）、有候选；通过则 emit punch\_request | → `{ok, reply}` 或 `{error, status}`；HTTP 与 WS 共用 |
| `handleConnect(body)` | HTTP 入口：先验签（暂不占 nonce）→ `matchmake` → 成功路径再占 nonce | → ConnectReply JSON |
| `handleEvents(url)` | HTTP 轮询入口：验签；`touch`；wasOffline 时补发 peer\_online；`pullEvents`（首次 since=0 只给近 30 秒） | → `{ok, cursor, events, server_ms}` |
| `handleLeave(body)` | 验签（占 nonce）→ 删节点 → 关闭其 socket（1000）→ emit peer\_offline | → `{ok}` |

**D. 事件与在线判定**

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `emit(to, type, payload)` | 写 events 一行，并向目标在线 socket 直接 send（to 为 `*` 表示广播） | → seq。v3.0 一律落库，「目标有存活 socket 时不落库」留作优化 B1 |
| `deliver(ws, msg)` | 安全发送，异常吞掉并记日志 | 避免一个坏连接影响广播 |
| `pullEvents(nodeId, since, limit, minCreatedAt)` | 读 `to_node` 为该节点或 `*` 且 id 大于 since 的事件 | 与现有语义一致 |
| `liveness(node, now)` | 有 socket：取 `getWebSocketAutoResponseTimestamp`（无则 joinedAt），now 减它不超过 WS\_GRACE（75 秒）即存活；无 socket：看 last\_seen 是否在 OFFLINE\_MS（150 秒）内 | → `{online, via, idleMs}`；**依赖 V9** |
| `isOnline(node, now)` | `liveness().online` | — |
| `publicNode(node, now)` | 对外节点视图，字段与现有一致；`idle_secs` 取 `liveness.idleMs`；新增 `via` | 供 peers 列表与管理面 |
| `touch(node, now)` | 仅轮询节点：距上次写入满 55 秒才更新 last\_seen | WS 节点不写 |

**E. WebSocket**

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `acceptWs(request)` | 握手：参数校验 → 节点存在 → `verifyReq('ws', …, 占 nonce)` → 关闭同 node 旧 socket（4000）→ `acceptWebSocket(server, [nodeId])` 并写 attachment → 若此前离线则 emit peer\_online → 发 hello，并按 `since` 补发事件 | → 101 或错误 |
| `webSocketMessage(ws, raw)` | 解析（上限 4 KB）→ 令牌桶限流（每 socket 20 条/10 秒，超限 4429）→ 分发 connect、resume、leave | 非法 JSON 静默忽略 |
| `onConnectMsg(ws, m)` | 以 socket 身份调 `matchmake`；回 connect\_ok 或 error，带 req | 不再逐条验签 |
| `onResumeMsg(ws, m)` | 补发 seq 大于 since 的事件（最多 50 条） | — |
| `webSocketClose(ws, code)` | 按合法码回关；非 leave 时写 `last_seen=now`（给轮询侧一个离线宽限）；对声明 `offline_evt` 能力的 socket 推送 peer\_offline | 对 1005、1006 要转成 1000 再回关，否则抛异常（原型已踩过） |
| `webSocketError(ws, err)` | 记日志，不抛 | — |
| `closeAll(code, reason)` | 关闭全部 socket | 换密钥、删网络、迁移使用 |

**F. 管理与维护**

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `adminListNodes` / `adminKick` / `adminKickMany` / `adminReserve` / `adminRelease` / `adminListReservations` | 移植同名 legacy 逻辑；踢人时先发 kick 消息再 4401 关闭，并删除该节点的 events | 返回字段与 legacy 一致 |
| `stats()` | 节点数、在线数（ws 与 poll 分列）、socket 数、events 行数、预留数 | 管理面与 health 使用 |
| `sweep(now)` | 惰性 GC：在 **HTTP 入口与 WebSocket 消息入口都**顺带调用，距上次满 5 分钟才执行；删过期 events、nonces（各 5 分钟）、10 分钟无心跳且无 socket 的节点、孤儿 auto 预留 | **不使用 alarm**，避免破坏休眠。WS 消息入口不能省：B4 取消定时 register 后，纯 WS 网络就没有别的 HTTP 入口，漏掉这一处会让 events 与僵尸节点永不回收（WS 消息本来就要唤醒 DO，不额外增加唤醒） |
| `debug()` | 诊断：bootAt、socket 列表（node、joinedAt、lastPingAt、alive）、schema\_version | 仅内部路由可达，管理接口代理 |

### 6.4 常量集中

全部阈值收敛到一个 `LIMITS` 对象，并通过 hello 与 health 下发给客户端（客户端据此校准 ping 间隔等），避免两端各写一份不一致。取值见附录 A。

## 7. 客户端模块与函数规格（Rust，crates/core）

### 7.1 模块与函数

| 模块 / 函数 | 状态 | 职责 | 交付 / 耦合 |
| --- | --- | --- | --- |
| `signal/client.rs` 的 `SignalClient` | 现有 | 保留 `register`、`join`、`connect`、`events`、`leave`、`health`，降级与注册仍用 HTTP | 不改签名协议 |
| `SignalClient::features()` | 新增 | 调 `health` 并缓存，判断 features 是否含 `ws` | → `Features`；旧 Worker 无此字段即视为仅轮询 |
| `SignalClient::ws_request(identity, since, caps)` | 新增 | 生成握手请求：`Authorization` 头 + 签名查询参数；复用 `body_digest`、`signing_message`，op 为 `ws` | → 握手请求；与 JS 端摘要必须逐字节一致，沿用现有互验用例 |
| `signal/ws.rs` 的 `WsLink::open(client, identity, since)` | 新增 | 建立连接并等待 hello（10 秒超时） | → `WsLink`，带 cursor、epoch、limits |
| `WsLink::next()` | 新增 | 事件流，产出三类：Event（seq、kind 及载荷，与 HTTP `Event` 同构）、Closed（code、reason）、Down（错误） | 与 `handle_event` 对接 |
| `WsLink::connect_peer(target)` | 新增 | 分配 req id → 发 connect → 用 oneshot 等 connect\_ok 或 error，超时 10 秒 | → `ConnectReply`，与 HTTP 版返回同构，调用方无需区分 |
| `WsLink::close(code)` | 新增 | 主动关闭 | 休眠、退出时调用 |
| keepalive 任务 | 新增 | 每 25 秒发 `ping`；10 秒内无 `pong` 判定半开，主动关闭并上报 Down | 在线判定的客户端侧，对应服务端 `liveness` |
| 连接代次 | 新增 | `WsLink` 每次重连递增 generation；发起重连时把旧连接标 superseded，旧代次 `next()` 产出的任何 Closed 一律丢弃、不上报 Down | 防止自己的重连被服务端 4000 回推时误判成「本机有另一个实例」而停止；与 §5.2 的关闭码处理配套 |
| `Backoff` | 新增 | 1 秒到 60 秒指数退避，±50% 抖动；连接稳定 60 秒后复位 | 避免发布期惊群 |
| `session.rs` 的 `handle_event(event, ctx)` | **重构** | 把现在内联在轮询循环里的事件分发（punch\_request、peer\_online 及其热窗口、拨号触发）抽成函数，供两个事件源共用 | **耦合最紧的一步，先做纯重构、不改行为，靠现有测试兜底** |
| `TransportMode` 与 `TransportCtl` | 新增 | 三态：Probing、Ws、Poll(until)；决定本轮使用哪个事件源 | 配置 `signal_transport` 为 auto、ws 或 poll |
| 主循环 | 改造 | `select!` 监听 ws 事件、`wake_rx`（TUN 唤醒）、register 定时、休眠定时；Poll 模式沿用 `poll_interval`，POLL\_HOT/WARM/COLD 常量不动 | 降级路径零改动 |
| 断路器 | 新增 | 120 秒内握手失败达 3 次转 Poll 并持续 10 分钟；Poll 期间每 5 分钟探测一次 WS | 代理拦截、握手失败时自动退回轮询；DO 额度耗尽时轮询同样返回 503，客户端慢速退避重试，已建立的隧道不受影响 |
| 源切换 | 新增 | Ws→Poll：用 `events(since=cursor)`；Poll→Ws：握手带 `since`；按 seq 去重 | cursor 由 session 统一持有 |
| 休眠联动 | 改造 | `sleeping` 为真满 60 秒后关 WS；`wake_rx` 触发重连 | 省电，Android 重点 |
| epoch 校验 | 新增 | hello.epoch 与本地不同（服务端数据被重置或重建）则立即 register 重取 peers | 防止拿着旧 cursor 漏事件 |

### 7.2 配置、依赖与兼容

- 配置：`signal_transport` 取 auto（默认）、ws、poll，来源为命令行、环境变量、配置文件；Android 同样支持。
- 依赖：WebSocket 客户端库（候选 `tokio-tungstenite` + rustls）。对静态二进制体积的影响**待测**。
- 兼容：旧 Worker（health 无 ws）→ 自动 Poll；事件分发对未知类型必须走默认分支忽略，**\[待验证\]** 需读一遍现有 match 的默认分支；peer\_offline 只推给声明 `offline_evt` 能力的 socket 且不落库，旧客户端永远看不到。
- 测试：Rust 单测起本地 mock WS 服务，覆盖握手失败码、半开检测、退避、断路器、源切换去重。

### 7.3 Android：保存配置与启动马上连接

**现状（`android/` 工程）**：界面由 `MainActivity.kt` 用代码生成，只有一个「连接/断开」按钮；点击时先隐式 `saveSettings()`，再 `ensurePermissionThenConnect()`；配置存放在本地 SharedPreferences（含加入令牌，目前是明文）。连接流程：经 Intent 把配置交给 `Qp2pVpnService` → `Native.prepare(configJson)`（向信令 register，换回 node\_id、virtual\_ip、cidr、mtu）→ `VpnService.establish()` → `Native.start(fd)`（阻塞运行会话）；界面靠约 800 ms 一次的轮询读取 `Qp2pVpnService.status` 更新状态。

**新增两个按钮**

| 按钮 | 行为 | 交付 |
| --- | --- | --- |
| 保存配置 | 只保存、不连接：校验（信令地址为 https 地址、令牌非空、可选的虚拟 IP 合法）→ 写入本地配置 → 提示「已保存」；连接中也可点击，提示「下次连接生效」 | `saveSettings()` 拆成独立动作并返回结果；失败时指出具体字段与原因 |
| 启动马上连接 | 一键：校验 → 保存 → 申请 VPN 权限（仅首次）→ 立即建立连接，不等任何定时；连接后同一位置变为「断开」 | `quickConnect()`：分阶段状态「注册中 → 建立隧道 → 连接信令 → 已连接」；失败给出可区分的原因（令牌无效、网络不通、服务端不可用、权限被拒） |

**「马上」在技术上做什么**

1. 校验通过后不做任何等待，直接 `Native.prepare` 注册；`features()`（health）与 register 并发发出，省一个往返。
2. `prepare` 一返回就 `establish` 并 `Native.start(fd)`；核心在 register 之后立刻 `WsLink::open`，不等轮询档位。
3. 服务端不支持 WS（旧版）时，立即进入 HOT 档（3 秒）轮询，相当于现有行为的加速版。
4. 状态字符串增加阶段取值，界面沿用现有轮询读取，不引入新的回调通道。

**配置存储（建议）**：令牌改用 Android Keystore 加密存储（具体库选型待定），其余字段保持普通配置；这是安全增强，不影响按钮行为。

**与休眠策略的关系**：沿用 §7.1「休眠联动」（休眠满 60 秒断开 WS，唤醒后重连并立即 register）；是否提供「保持在线」开关仍是未决问题 4。

**验收**：保存不触发连接；良好网络下一键连接 5 秒内到「已连接」；令牌无效、网络不通、服务端不可用（含 503）三类失败提示各不相同；连接中点「保存配置」不影响当前连接。

**待确认**：「启动马上连接」我按「点一下按钮就立即连接」设计。如果你想要的是「打开 App 就自动连接」，只需再加一个偏好开关 `auto_connect_on_launch`（默认关）：App 启动且已有保存配置时自动执行 `quickConnect()`；两种可以同时存在。

## 8. 部署器规格（独立二进制，推荐 `crates/deploy`）

### 8.1 定位与命令

推荐做成**独立二进制**，而不是并入 qp2p 客户端：持有 API 令牌的代码不应放进带 root 或 TUN 权限的 VPN 客户端里。Worker 源码用 `include_str!` 编入二进制，保证 Worker 与客户端版本一致。

| 命令 | 作用 |
| --- | --- |
| `deploy init` | 建 D1 → 首次上传（含迁移 v1 与 ADMIN\_SECRET）→ 启用 workers.dev → 冒烟 → 打印管理页链接，ADMIN\_SECRET 只显示一次 |
| `deploy up` | 升级：读线上迁移标签 → 规划步骤 → 逐步上传，保留绑定 |
| `deploy status` | 读线上版本、迁移标签、各引擎网络数、health 概况 |
| `deploy rotate-admin` | 重设 ADMIN\_SECRET |
| `deploy destroy` | 删除 Worker（DO 数据随之销毁）；D1 需显式 `--with-d1` |
| 全局选项 | `--dry-run`（打印脱敏后的 metadata）、`--worker <名称>` |

### 8.2 模块与函数

| 函数 | 职责 | 交付 / 注意 |
| --- | --- | --- |
| `cf::Client::new(token, account_id, base)` | 读环境变量或 stdin；**永不写盘** | reqwest + rustls；`base` 可替换，便于用模拟服务测试（原型已验证这一做法） |
| `cf::Client::call(req)` | 统一解析 `{success, errors[{code,message}], result}`；错误原样带 code 展示；对 429 与 5xx 退避重试 3 次 | → `Value` 或带 code 的错误 |
| `cf::verify_token()` | 令牌有效性与权限预检 | **\[待验证\]** 新版 `cfut_` 令牌对应的校验接口路径 |
| `cf::ensure_d1(name, location)` | 按名字查找，不存在才创建 | → database\_id（注意绑定字段用 `database_id`，旧的 `id` 已废弃） |
| `cf::get_script_info(name)` | 读线上迁移标签与绑定 | 上传响应已含 `migration_tag`（已观测）；纯读取接口 **\[待验证\]** |
| `build::modules()` | 返回待上传的模块列表 | v1 为单文件；B6 之后为多文件 |
| `build::metadata(opts)` | 生成 multipart 的 metadata：main\_module、固定的 compatibility\_date、bindings、migrations 或 keep\_bindings、observability | bindings：D1 为 `DB`，DO 为 `ROOM`→`NetworkRoom`，`ADMIN_SECRET` 仅首次带文本 |
| `migrate::chain()` | 内置**只追加**的迁移链：v1 为 `new_sqlite_classes: [NetworkRoom]`，后续按需追加 | 编译期常量 |
| `migrate::plan(current_tag)` | 返回需要依次执行的步骤；current 为空视为全新；current 不在链中则报错并拒绝，**不猜测** | → `Vec<Step>`，退出码 4 |
| `cf::upload(modules, metadata)` | PUT 脚本；每个迁移步骤一次上传 | → `{deployment_id, migration_tag, startup_time_ms, etag}` |
| `cf::enable_workers_dev(name, previews=false)` | 启用 workers.dev，**显式关闭预览 URL**（原型实测默认会打开） | 先 `account_subdomain()`；账号尚无子域名时提示用户去控制台创建，不替用户起名 |
| `secrets::gen_admin_secret()` | 随机 48 位十六进制，仅首次展示一次 | 丢失后只能 `rotate-admin` |
| `verify::smoke(base_url)` | 请求 `/v1/health`，期望 version、engine、features | 失败给出可操作的诊断（子域名未启用、迁移被拒等），退出码 5 |
| `state::LocalState` | 在用户配置目录保存 worker 名、账号 ID、子域名、最后标签、部署时间 | **不含令牌与密钥** |

### 8.3 安全护栏

- 不自动执行破坏性迁移（`deleted_classes`、`renamed_classes`）；必须 `--force` 并二次确认。
- 日志永不打印令牌与密钥；`--dry-run` 一律脱敏。
- 退出码：2 参数错误、3 API 错误、4 迁移被拒、5 冒烟失败。

### 8.4 幂等与升级矩阵

| 场景 | 行为 |
| --- | --- |
| 首次（脚本不存在） | 建 D1 → 上传 v1 → 启用 workers.dev → 冒烟 |
| 升级（脚本存在） | 读 current\_tag → `plan` → 逐步上传，每步带 `keep_bindings: [secret_text]`；仅改代码时不带 migrations。V12 通过前，提供 `--reset-secret` 作保险 |
| 回滚 | 上传旧版本代码；迁移标签不回退；DO 数据保留 |
| 灾难（Worker 被删） | DO 数据随之销毁；网络需从 D1 控制面重建、节点重新 register。**用户手填的 IP 预留若只在 DO 里会丢**，因此 B2（预留同步备份到 D1）应尽早做 |
| 重新部署（线上是 v2 或更早、没有 DO 的旧 Worker） | 读到的 current\_tag 为空，plan 从 v1 开始；ensure\_d1 复用同名 D1，networks、令牌、管理员账号原样保留，旧数据面表闲置；ADMIN\_SECRET 默认用 keep\_bindings 保留，需要时加 --reset-secret；上传后各节点的下一次请求就落到 DO，节点 register 一次即恢复。不迁移任何数据：手填的固定 IP 预留需在管理页重设（B2 之后自动恢复） |
| 紧急回退（DO 不可用或额度耗尽） | deploy up --no-room：上传不带 ROOM 绑定的版本，Worker 退回 legacy（D1 + 轮询）；DO 里的数据保留但不再使用；节点重新 register 即恢复。**注意**：legacy 读的是 D1 里那份旧 reservations（升级前快照），DO 运行期间新增/释放的预留看不到，回退后要在管理页核对一遍 |

## 9. 关键流程

### F1 首次部署

1. 用户设置 `CF_API_TOKEN`、`CF_ACCOUNT_ID`，运行 `deploy init`。
2. `cf::verify_token` → `ensure_d1` → `build::metadata`（含 ADMIN\_SECRET 与迁移 v1）→ `cf::upload`。
3. `enable_workers_dev(previews=false)`，`verify::smoke` 读取 `/v1/health`。
4. 打印管理页链接与 ADMIN\_SECRET（仅一次）；用户打开 `/admin`，引导创建管理员，建第一个网络（room 引擎）并拿到加入令牌。

### F2 节点启动

1. `SignalClient::features()` 判断服务端是否支持 ws。
2. HTTP `register` → Worker `authenticate` → `forwardToRoom` → DO `handleJoinRegister`，返回 peers 与 virtual\_ip。
3. `WsLink::open(since)` → `/v1/ws` → `acceptWs` 验签 → hello（cursor、epoch）。
4. session 进入 Ws 模式，停止 events 轮询。
5. 稳态：每 25 秒 ping/pong（运行时应答，不唤醒 DO）；每 30 分钟 register；事件由服务端推送。
6. 任一步失败，按 §7.1 的断路器回到 Poll。

### F3 撮合打洞

1. A 的 TUN 发现目标未连接，经 `wake_tx` 通知 session 拨号 B。
2. A 调 `WsLink::connect_peer(B)`（Poll 模式则走 HTTP `connect`）。
3. DO `onConnectMsg` → `matchmake`：B 存在、`liveness` 在线、地址新鲜、有候选。
4. `emit(B, punch_request)`：B 有存活 socket 则立即 send，同时落库。
5. A 收到 connect\_ok（B 的候选、virtual\_ip、tls\_fp、t）；A、B 在约定时刻 t 开始打洞，现有 `peer/punch.rs` 逻辑**不变**。
6. 失败码（target\_offline、target\_stale、target\_no\_candidates）沿用现有退避与冷却。

### F4 断线与降级

1. ping 无 pong 或收到 Closed（1012、4500、网络错误）→ `Backoff` 重连，带 `since=cursor` 补发漏掉的事件。
2. 120 秒内握手失败达 3 次（多为代理拦截 WebSocket）→ 转 Poll 持续 10 分钟，沿用旧三档轮询。
3. 收到 503 `room_unavailable`（DO 异常或额度耗尽）→ 轮询同样会 503，客户端按 1 到 60 秒退避重试；已建立的隧道不受影响，只是新连接与地址刷新暂停。
4. Poll 期间每 5 分钟探测一次 WS，成功则切回 Ws，用握手 `since` 对接游标。
5. 收到 4401 或 4410 → 停止重连并提示（令牌失效、网络被删）。

### F5 踢人与换密钥

1. 踢人：`adminKick` 发 kick 消息 → 4401 关闭该 socket → 删节点与其 events → 写 audit。
2. 换密钥：`rotateJoinKey` 更新 D1 → `/i/net-updated` → `closeAll(4401)` → 节点用新令牌重新加入。

### F6 重新部署升级（旧版 → v3）

1. 用户运行 `deploy up`（旧版 Worker 没有迁移标签，`plan` 从 v1 开始）。
2. `ensure_d1` 复用同名 D1：networks、令牌、管理员账号原样保留。
3. 上传 v3 并带 `ROOM` 绑定；此后所有请求落到 DO，没有逐网络切换。
4. 节点下一次请求（轮询不超过 60 秒）或 register（不超过 30 分钟）后恢复；具备 WS 能力的客户端握手前先 register。
5. 固定 IP 预留需要管理员重设（B2 之后自动恢复）；其余无需操作。
6. 回退：`deploy up --no-room`，Worker 退回 legacy。

### F7 发布升级

1. 休眠态（V8 已验证）：新代码在对象下次唤醒时生效，连接不断。
2. 活跃态（V10 待验证）：对象重置，socket 以 1012 关闭，客户端抖动重连（1～3 秒随机加退避）；目标是 20 节点的网络 10 秒内全部恢复。
3. 含迁移步骤的发布，部署器按 `migrate::plan` 逐步上传。

## 10. 耦合矩阵与实现顺序

| 变更点 | 受影响模块 | 兼容策略 |
| --- | --- | --- |
| 签名消息格式与 `canonicalJson` | legacy Worker、NetworkRoom、Rust 客户端、测试 | **冻结**，只追加 op（新增 `ws`）；跨语言互验用例必须保留 |
| 事件类型与字段 | `emit`、HTTP events、WS event、`handle_event` | 只增不删；新类型必须能被旧客户端安全忽略 |
| 在线判定阈值（OFFLINE\_MS、STALE\_MS、WS\_GRACE、PING\_EVERY） | `liveness`、`matchmake`、客户端 keepalive、idle\_secs 展示 | 集中在 `LIMITS`，经 hello 与 health 下发；WS\_GRACE 至少为 PING\_EVERY 的 3 倍 |
| `x-qp2p-net` 网络上下文 | Worker `netContext`、DO `loadNet` | 带版本字段 v；DO 遇到未知 v 直接拒绝并返回 503 |
| DO SQLite 结构 | NetworkRoom、`importState` | `schema_version` 内部迁移；类名冻结，避免类迁移 |
| 迁移标签链 | 部署器、线上 Worker | 只追加；部署器读线上标签，不匹配即拒绝 |
| cursor 与 seq | DO、HTTP events、WS、Rust session | 每网络单调；服务端数据重置时通过 epoch 通知客户端重新 register |
| 管理面响应字段 | `/admin` 页面、管理 API | 只增不删，新字段给默认值 |
| 额度与 503 | DO、Worker、客户端断路器 | 约定 `room_unavailable` 为退避信号（轮询同样受影响）；紧急回退用 `deploy up --no-room` |
| D1 `networks` 缓存 | `getNetworkCached`、管理面 | 最多滞后 15 秒；kick 与 rotate 直达 DO，不依赖缓存 |

**实现顺序（依赖方向）**：协议冻结与测试替身 → NetworkRoom 的 HTTP 适配（可被旧客户端验证）→ WS 端点 → Rust 重构 `handle_event` → `WsLink` 与 `TransportMode` → 部署器。每一步都能独立上线、独立回滚。

## 11. 配额与容量模型

**假设（每节点每天，偏保守）**：ping 每 25 秒一次，共 3,456 条，按 20:1 折算约 173 次计费请求（若自动应答本身不计费则更少——**这笔折算依赖 V9 的第二条机器验证**）；register 48 次；重连 10 次；connect 与 events 约 20 次。

- Worker 请求约 60 次，DO 请求约 260 次，SQLite 写约 80 行。
- 时长：每节点每天约 100 次唤醒，每次约 40 毫秒、128 MB，合计约 0.5 GB·秒，几乎可忽略。按官方口径，只要对象**处于可休眠状态就不计费**，连运行时尚未真正休眠的那段也不计——所以 40 ms 是上界，实际更低。
- 对照现状：legacy 每节点每天 1,440～4,320 次 Worker 调用并伴随同量 D1 查询，免费 Worker 额度只够约 23～69 个节点。

| 节点数 N | DO 请求/天（占 10 万） | Worker 请求/天 | SQLite 写入/天（占 10 万行） |
| --- | --- | --- | --- |
| 5 | 1,300（1.3%） | 300 | 400（0.4%） |
| 20 | 5,200（5.2%） | 1,200 | 1,600（1.6%） |
| 100 | 26,000（26%） | 6,000 | 8,000（8%） |
| 256（单网络上限） | 66,560（67%） | 15,360 | 20,480（20%） |

整个账号在 DO 请求维度的粗略上限约 385 个节点（10 万除以 260）。

**多网络时的放大**：上表是「单网络、N 个节点」的口径。实际是每网络一个 DO，各 DO 独立唤醒、独立休眠，唤醒次数不能跨网络合并——网络数 M 越多、每网节点越少，**每节点的实际唤醒次数越高**（一个 3 节点的小网络，任何一次交互都会唤醒它那个 DO）。请求数不受影响（仍按每节点 260 计，分散在不同 DO 上但共用账号额度），时长随 M 线性上升，仍远低于 13,000 GB·秒/天：100 个网络各唤醒 100 次/天约 50 GB·秒。

**混合期最坏情况（过渡期必须算）**：升级期间同一个网络里会同时有 WS 客户端和旧版轮询客户端，而 `GET /v1/events` 无法区分新旧，只能统一转发给 DO（v3 下 D1 数据面是空的，转给 legacy 旧客户端会拿到空列表）。此时每个旧客户端节点贡献约 1,440 次/天，而不是 260 次：

| 混合比例（100 节点） | DO 请求/天 | 占 10 万 |
| --- | --- | --- |
| 全部新客户端 | 26,000 | 26% |
| 70% 新 / 30% 旧 | 18,200 + 43,200 = 61,400 | **61%** |
| 全部旧客户端 | 144,000 | **超限** |

所以「385 个节点」只在全部升级完成后才成立。过渡期要么控制网络规模，要么集中几天完成升级；P6 之后应把旧客户端明确挡在门外（`epoch` 或 `caps` 校验），而不是长期共存。

**必须守住的红线**：休眠失效会让单个 DO 一天吃掉约 11,059 GB·秒，只够 1 个网络。因此要有回归检测：发布后空闲 60 秒，DO 时长增量应接近 0；代码里禁止出现定时器、出站连接。

## 12. 可观测性

- **服务端日志**（结构化单行）：`[room] ev=<事件> net=<网络id前8位> node=<节点id前8位> …`。事件包括 ws\_open、ws\_close（带 code）、reject（带原因）、connect（成功或失败码）、emit（类型与目标）、sweep（各表删除数）、quota\_error。**不记录令牌、签名，也不记录带查询串的完整 URL**，因为 query 里可能带 token 与 sig。
- **指标来源**：DO Metrics 页（请求、时长、存储读写行）；Worker 指标（CPU p50 与 p99、错误率）；`/v1/health`（管理员视角）给出版本、各引擎网络数、socket 总数；`/i/debug` 经管理接口代理。注意连接本身的指标要等连接关闭后才出现。
- **客户端**：传输模式切换、握手耗时、ping RTT、重连次数，汇总到 `qp2p status`。
- **告警线**（人工或脚本检查）：DO 请求超 7 万/天；SQLite 写入超 7 万行/天；DO 时长日增超 1,000 GB·秒（休眠失效迹象）；Worker 5xx 率异常。

## 13. 安全

| 威胁 | 缓解 |
| --- | --- |
| 重放握手 | ts 窗口 ±120 秒，加上 nonce 入库（SQLite） |
| 冒充节点 | node\_id 等于 sha256(pubkey) 前 32 位，加上 Ed25519 签名握手；socket 绑定身份，消息体里自称的 from 一律不信 |
| 令牌泄漏 | rotate 后 4401 踢掉全部连接；join 密钥只存哈希 |
| 握手与消息洪泛 | Worker 按 IP 限流（握手 30 次/分钟）；socket 令牌桶；消息 4 KB 上限 |
| 越权访问 DO | DO 无公网路由；Worker 剥离所有 `x-qp2p-*` 请求头 |
| 日志泄漏 | 不记录完整 URL；Rust 客户端用 `Authorization` 头而不是 query 传令牌，query 传令牌仅留给浏览器类客户端 |
| 部署令牌泄漏 | 最小权限、短期有效、不落盘；关闭预览 URL；泄漏后立即删除令牌 |
| 额度耗尽型攻击 | 额度耗尽返回 503，客户端降级；后续按网络加速率上限（B12） |

## 14. 测试策略

- **服务端单元**：扩展现有 `signal/smoke.mjs`；新增 `RoomFake`（用 `node:sqlite` 替身 `storage.sql`，加上假 `WebSocketPair`、`getWebSockets`、`acceptWebSocket`、自动应答时间戳）。原型的 `harness.mjs` 可直接升级为起点。
- **兼容性矩阵**：同一套协议用例对 legacy 与 room 两个引擎各跑一遍，断言响应形状一致（黄金样例）。
- **跨语言签名**：沿用现有 `canonicalJson` 测试向量，JS 与 Rust 互验必须保留。
- **集成**：部署到测试 Worker；新增 `signal/ws-load.mjs`（Node 22 内置 WebSocket），模拟 N 个节点（真实 Ed25519 身份）连接、互相 connect、断线、发布期重连。
- **混沌**：活跃态部署、杀连接、注入 DO 异常模拟额度耗尽、时钟偏移（ts 窗口边界）。
- **休眠回归**：发布后空闲 60 秒，读取 DO 时长增量应接近 0。
- **验收**：每个阶段的验收项见 §15，全部通过才进入下一阶段。

## 15. 发布与路线图

| 阶段 | 内容 | 验收 | 回滚 |
| --- | --- | --- | --- |
| P0 补测 | V12（keep\_bindings 后 TOKEN 仍有效）；V14 已确认通过（Free 计划额度见 §2） | V12 通过；V9 的两条机器验证作为回归断言写进集成测试 | — |
| P1 骨架 | NetworkRoom 骨架 + SQL 接口验证 + 适配层；未绑定 DO 时行为零变化 | smoke.mjs 全绿；线上 legacy 全程无回归 | 重新部署旧版本 |
| P2 room 引擎（HTTP） | join、register、connect、events、leave 全部走 DO，仍为轮询；用全新的测试 Worker 部署（绑定 DO） | 旧客户端零改动联通；D1 读写明显下降 | 部署不带 `ROOM` 绑定的版本（`--no-room`） |
| P3 WS 端点 | `/v1/ws`、hello、event、connect、resume；`ws-load.mjs` | 100 节点稳定 30 分钟；V11 的 24 小时用量符合 §11 | 关闭 features.ws |
| P4 Rust WsLink | 重构 `handle_event`、`WsLink`、`TransportMode`、断路器 | 断线、活跃态部署、额度耗尽、旧 Worker 四类演练通过 | `signal_transport=poll` |
| P4a Android | 「保存配置」与「启动马上连接」两个按钮；saveSettings 与 quickConnect 拆分；分阶段连接状态与失败原因（§7.3） | 保存不触发连接；良好网络下一键连接 5 秒内进入已连接；令牌无效、网络不通、服务端不可用给出不同提示 | 回退上一版 APK |
| P5 部署器 | `deploy init、up、status` | 全新账号 5 分钟内完成 init；迁移链逐步升级；冒烟通过 | 手工粘贴 legacy 流程仍可用 |
| P6 发布 | 自用 Worker 重新部署（`deploy up`），观察 7 天；其余用户按发布说明重新部署，不做在线迁移 | 各网络日志无异常；用量在预期内；**手填的固定 IP 预留已在管理页核对并重设**（B2 未做的代价，见 R8） | `deploy up --no-room` |
| P7 优化 | 见 §17 | 逐项验收 | 逐项回退 |
| P8（可选） | 退役 legacy 数据面 | 全部网络稳定运行超过 1 个月 | 保留 D1 表，只关入口 |

## 16. 风险与未决问题

| 编号 | 风险 | 影响 | 缓解 |
| --- | --- | --- | --- |
| R1 | V9 失败：自动应答时间戳不可用或不刷新（V9 已由用户确认通过，降为回归检测） | 在线判定失准 | 改发 JSON ping（每次唤醒，成本约 20 倍）；或仅依赖 close 事件与短 TTL；重估配额 |
| R2 | DO 位置远，RTT 约 200 ms | 体验 | `region_hint`，V13 对比 |
| R3 | 额度耗尽 | 新连接与地址刷新暂停，已建立的隧道不受影响 | 告警线提前发现；客户端 503 退避重试；紧急回退 `deploy up --no-room`（退回 legacy，节点重新 register） |
| R4 | 休眠失效（混入定时器或出站连接） | 一天烧光时长额度 | 休眠回归检测写进发布流程 |
| R5 | 客户端重构风险（抽取 `handle_event`） | 回归 | 先纯重构，靠现有测试兜底 |
| R6 | Rust 二进制体积与依赖 | 分发 | 提前测量，必要时 feature 门控 |
| R7 | 迁移标签链出错导致无法部署 | 发布受阻 | 部署器读线上标签，不匹配即拒绝，不猜测 |
| R8 | Worker 被删导致 DO 数据丢失 | 手填 IP 预留丢失 | B2：DO 首次初始化时从 D1 恢复 user 预留（同时覆盖重新部署场景） |
| R9 | 发布期惊群重连 | 瞬时请求高峰 | 抖动加退避，握手限流 |
| R10 | 旧客户端误处理新事件类型 | 异常行为 | 默认分支忽略（待验证）；peer\_offline 只推给声明 `offline_evt` 的 socket 且不落库 |

**已定事项（原未决问题，按推荐默认值定稿，可随时调整）**

1. 自托管路径（Node dev-server）：保留 legacy 逻辑并**冻结**——P6 之后只接受安全修复，不再加任何功能（包括顺手优化和字段扩展），避免两套实现长期漂移；B10 的退役条件写死为「全部网络连续 1 个月没有 legacy 请求」。
2. `region_hint`：默认留空，**仅供调试用**，正常不要填。`locationHint` 只在 DO 首次创建时生效、之后不可更改，手填选错就是永久绕远路；留空让 Cloudflare 就近分配更稳。V13 只用来验证「就近分配 vs 强制指定」的差异，不作为日常配置项下发。
3. 管理页：展示连接方式（ws 或 poll）与「最近活动 N 秒前」，手动刷新；自动刷新间隔不少于 30 秒。
4. Android 休眠：默认休眠即断开 WS；提供「保持在线」开关（默认关）。
5. 不做在线迁移，用户重新部署（见 §8.4、§9 F6）。

## 17. 优化与升级 backlog

| 编号 | 项 | 价值 | 成本 | 前置 |
| --- | --- | --- | --- | --- |
| B1 | 目标有存活 socket 时事件只推送、不落库 | 降 SQLite 写入 | 低 | P3 |
| B2 | user 预留以 D1 为备份源，DO 首次初始化时恢复（重新部署后固定 IP 不丢） | 防数据丢失 | 低 | P2 |
| B3 | WS 内 register，省一次 HTTP | 降 Worker 调用 | 中 | P3 |
| B4 | Ws 模式下取消 30 分钟定时 register，只在状态变化时发 | 降请求 | 低 | P4 |
| B5 | locationHint 与就近策略 | 降延迟 | 低 | V13 |
| B6 | 多模块拆分，部署器多文件上传 | 可维护性 | 中 | P5 |
| B7 | 管理页实时视图（订阅 `/i/stats`） | 体验 | 中 | P3 |
| B8 | 自适应心跳：弱网拉长 ping，休眠态拉长 | 省电 | 中 | P4 |
| B9 | Android 省电策略细化 | 移动端体验 | 高 | P4 |
| B10 | 退役 legacy 引擎 | 简化代码 | 中 | P6 之后一个月以上 |
| B11 | 事件批量发送 | 降唤醒 | 低 | P3 |
| B12 | 按网络的速率与配额策略 | 抗滥用 | 中 | P6 |

## 附录 A 常量表

| 常量 | 取值 | 归属 |
| --- | --- | --- |
| OFFLINE\_MS | 150,000 | 现有：轮询节点离线判定 |
| STALE\_MS | 120,000 | 现有：connect 时地址新鲜度 |
| HEARTBEAT\_MS | 55,000 | 现有：轮询心跳落库节流 |
| WS\_GRACE\_MS | 75,000 | 新增：WS 节点存活判定，约 3 个 ping 周期 |
| PING\_EVERY | 25,000 | 新增：客户端保活间隔 |
| PONG\_TIMEOUT | 10,000 | 新增：客户端等待 pong |
| TS\_WINDOW\_MS | 120,000 | 现有：签名时间窗 |
| NONCE\_TTL\_MS、EVENT\_TTL\_MS | 300,000 | 现有 |
| NODE\_TTL\_MS | 600,000 | 现有：无心跳且无 socket 的节点淘汰 |
| MAX\_NODES、MAX\_EVENTS、MAX\_CANDIDATES | 256、50、16 | 现有 |
| 握手限流 | 每 IP 每分钟 30 次 | 新增 |
| socket 限流与消息上限 | 20 条/10 秒；4 KB | 新增 |
| REGISTER\_EVERY | 1,800 秒 | 现有：客户端 |
| POLL\_HOT、WARM、COLD；HOT\_WINDOW | 3、20、60 秒；45 秒 | 现有：仅降级使用 |
| Backoff 与断路器 | 1 到 60 秒，±50%；120 秒内失败 3 次转 Poll 10 分钟，每 5 分钟探测 | 新增 |

## 附录 B 原型到生产的对应

| 原型 | 生产 | 变化 |
| --- | --- | --- |
| `Room` 类 | `NetworkRoom` | 重命名并冻结类名；原型 Worker `qp2p-do-proto` 测完应删除 |
| `/ws` | `/v1/ws` | 加真实令牌鉴权与签名握手 |
| `/debug` | `/i/debug`（管理接口代理） | 不再对外直接暴露 |
| 共享 TOKEN | 真实网络令牌与 Ed25519 身份 | — |
| `verify=N` 参数 | 取消 | 真实握手本身就验签 |
| 每次唤醒写 wakes | 取消 | 避免每次唤醒写一行 |
| `deploy.sh` | 部署器 | 保留作为 P0 阶段的临时手段 |
| 内嵌测试页 | `signal/ws-test.html`（开发工具） | 保留作联调与排障 |
