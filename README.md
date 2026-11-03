# qp2p

私有打洞组网：节点向 Worker 上报连通信息，Worker 只做撮合，节点之间打洞直连后互相访问。任何业务数据都不经过服务器。

设计文档见 [DESIGN.md](DESIGN.md)。

## 当前进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | workspace、CI、工具链 | ✅ |
| P1 | 纯逻辑：候选地址、STUN、时钟偏移、状态机、身份 | ✅ |
| P2 | 单 socket + 同 socket STUN + 角色化打洞 | ✅（探针复用 Initial，D1 魔数分流待补） |
| P3 | link 复用层（per-flow QUIC 流）+ 端口转发 | ✅ |
| P4 | CLI：`punch` / `forward` / `doctor` | ✅（控制接口与信令客户端未接） |
| P5 | Linux TUN + 路由下发 | ⬜ |
| P6–P8 | Windows / Android 前端 | ⬜ |
| P9 | 信令 Worker（单文件 + D1） | 🟡 代码与本地测试完成，未部署联调 |

## 快速开始（当前可用）

两个终端，各自知道对方的 UDP 地址（同一局域网可直接用内网 IP）：

```bash
# 终端 1（A 侧）：把本机 8080 经隧道送到 B 侧能访问的 10.0.0.7:22
#               同时允许 B 经我访问 A 侧的 10.0.0.5:80
qp2p forward --bind 0.0.0.0:51820 --peer 192.168.1.20:51820 \
             --listen 127.0.0.1:8080 --target 10.0.0.7:22 --serve 10.0.0.5:80

# 终端 2（B 侧）：反过来
qp2p forward --bind 0.0.0.0:51820 --peer 192.168.1.10:51820 --dialer \
             --listen 127.0.0.1:9090 --target 10.0.0.5:80 --serve 10.0.0.7:22
```

方向容易搞反，记住两句：

- **`--target` 是对端要去连的地址**：流量经隧道送到对端，由对端发起 TCP 连接。写成本机侧的地址不会报错，只会连到对端的同名地址。
- **`--serve` 是本机允许对端访问的地址**：它必须等于**对端的 `--target`**，两边是交叉对应的。不填就等于拒绝一切入站，命令行会显式警告。

打洞成功后，访问本机 `127.0.0.1:8080` 的流量会经 QUIC 直连送到对端，由对端连它的 `10.0.0.7:22`。
`--stun host:port` 可重复指定，用同一个 UDP socket 探测公网映射。
`--peer` 也可重复：所有候选地址会**并行**打，先通先用。

## 打洞成功率相关的实现

| 手段 | 做法 |
|---|---|
| 不依赖启动对齐 | 守候方长时间 accept 并周期性发探针；发起方每个候选只发一条连接，重传交给 QUIC |
| 建连确认 | 连上后双方在流上交换 HELLO/ACK；守候方先抢占再回 ACK，避免两端落在不同连接上 |
| 端口预映射 | 启动时尝试 UPnP-IGD，成功则多一个 `upnp` 候选（优先级高于 srflx） |
| 并行候选 | 一轮打洞同时拨所有候选地址，先通先用 |
| 重试前刷新 | 每轮重试重建端点、重新 STUN，避免拿过期映射硬打 |
| 失败期保活 | 重试间隔里每 15s 向已知地址发小包，防止 NAT 映射被回收 |
| 多 STUN | `--stun` 可配多个（支持域名），取第一个可用的结果 |

## 安全边界

- **打洞成功后必须完成一次双向身份认证**，否则连接会被丢弃：
  双方各用身份私钥签 `QP2P-AUTH-1|<自己>|<对方>|<nonce_a>|<nonce_b>`，
  签名里同时绑定两个 node_id 和两个本次连接现生成的 nonce。
  复放旧帧、反射、冒充已知 node_id 都会失败。
  日志里的 `[punch] 对端认证通过 peer=...` 就是这一步。
- 用 `--peer-id <32 位十六进制>` 指定"只接受这个对端"；不指定则只验签、不限身份。
  `qp2p doctor` 会打印本机的 `node_id` 和 `pubkey`，可直接比对。
- 接受端只连**白名单（`--serve`）里**的目标，空表拒绝一切。
- 数据面支持 TCP 半关闭；半关闭后若双方都不再有数据往来，60 秒后回收。
- CLI 代码中 `Network` 的 `Debug` 已把 token 打码，避免日志泄漏 secret。
- **QUIC 这一层仍是自签证书 + 跳过校验**：能完成 QUIC 握手不等于通过认证，
  但握手本身仍对任何人开放（有握手成本的 DoS 面）。

## 已知简化（后续补齐）

- 打洞探针复用 QUIC Initial，尚未做 `0x00QP2` 魔数分流（DESIGN D1/D6）
- 证书没有持久化：每次启动重新生成，`tls_fp` 因此不稳定，尚未用于钉扎
  （当前身份认证走应用层签名，不依赖证书）
- 证书每次启动重新生成，钉扎需要先持久化身份
- 只有 UPnP，没有 NAT-PMP / PCP；UPnP 映射不续租、退出不删除
- 只有 L4 端口映射，没有 TUN（P5）
- 没有 NAT 模拟器，跨 NAT 场景只能在真实网络验证
- 信令 Worker 用轮询而不是推送（否则需要 Durable Object），被动方知道连接请求会晚 20~60 秒

## 信令服务

`signal/worker.js` 是**单文件**，粘进 Cloudflare Dashboard 点 Deploy 就能用，
不需要 wrangler、不需要构建、不需要 Durable Object；绑一个 D1 作为存储，表会自动创建。

详细部署步骤、接口、额度估算见 [signal/README.md](signal/README.md)，
本地冒烟测试 `node signal/smoke.mjs`（不需要云环境）。

## 构建与测试

```bash
cargo test --all
cargo clippy --all-targets -- -D warnings
```

P1 部分不依赖网络，全部用例可在无网络环境运行。

### Windows 本地开发

没有安装 Visual Studio（MSVC）时，`cargo` 的默认 msvc 目标无法链接。改用 GNU 工具链：

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
# 需要 MinGW-w64 的 gcc / ld 在 PATH 中（如 MSYS2 的 ucrt64/bin）
```

CI 跑在带有 MSVC 的 runner 上，因此仓库不固定工具链，由开发者按环境选择。

## 目录

```
crates/core      协议核心（无前端依赖）
  candidate.rs   候选地址：优先级、去重、线上格式
  stun.rs        STUN Binding 编解码 + 同 socket 探测
  socket.rs      绑定 socket、STUN、创建 quinn 端点
  tls.rs         自签证书与 ALPN
  path.rs        时钟偏移估计（EWMA）与打洞窗口调度
  peer/fsm.rs    每对端状态机（纯函数，虚拟时钟单测）
  peer/punch.rs  角色化打洞：dialer 拨号、listener 开孔后 accept
  link/mod.rs    per-flow QUIC 流与双向端口映射
  engine.rs      端点生命周期与打洞入口
  identity.rs    Ed25519 身份、node_id、虚拟地址派生
  config.rs      TOML 配置与校验
crates/cli       命令行前端（punch / forward / doctor）
signal           单文件 Cloudflare Worker 信令面 + 本地冒烟测试
```

## 平台计划

| 平台 | 虚拟网卡 | 交付 |
|---|---|---|
| Linux | `/dev/net/tun` | CLI + systemd |
| Windows | WinTun | 桌面程序 + 服务 |
| Android | VpnService（无需 root） | 自签 APK |
