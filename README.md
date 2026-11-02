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
| P9 | 信令 Worker（多租户 + DO + WS） | 🟡 代码完成，未部署联调 |

## 快速开始（当前可用）

两个终端，各自知道对方的 UDP 地址（同一局域网可直接用内网 IP）：

```bash
# 终端 1（listener）
qp2p forward --bind 0.0.0.0:51820 --peer 192.168.1.20:51820 \
             --listen 127.0.0.1:8080 --target 10.0.0.5:80

# 终端 2（dialer）
qp2p forward --bind 0.0.0.0:51820 --peer 192.168.1.10:51820 --dialer \
             --listen 127.0.0.1:9090 --target 10.0.0.7:22
```

打洞成功后，访问本机 `127.0.0.1:8080` 的流量会经 QUIC 直连送到对端侧的目标地址。
`--stun host:port` 可重复指定，用同一个 UDP socket 探测公网映射。
`--peer` 也可重复：所有候选地址会**并行**打，先通先用。

## 打洞成功率相关的实现

| 手段 | 做法 |
|---|---|
| 端口预映射 | 启动时尝试 UPnP-IGD，成功则多一个 `upnp` 候选 |
| 并行候选 | 一轮打洞同时拨所有候选地址，先通先用 |
| 重试前刷新 | 每轮重试重建端点、重新 STUN，避免拿过期映射硬打 |
| 失败期保活 | 重试间隔里每 15s 向已知地址发小包，防止 NAT 映射被回收 |
| 多 STUN | `--stun` 可配多个，取第一个可用的结果 |

## 已知简化（后续补齐）

- 打洞探针复用 QUIC Initial，尚未做 `0x00QP2` 魔数分流（DESIGN D1/D6）
- TLS 仍是自签 + 跳过校验，证书钉扎要等信令面交换指纹（D3）
- 只有 UPnP，没有 NAT-PMP / PCP（需要跨平台取默认网关）
- 只有 L4 端口映射，没有 TUN（P5）
- 没有 NAT 模拟器，跨 NAT 场景只能在真实网络验证
- 收不到 peer-reflexive 地址（依赖魔数分流）

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
signal           Cloudflare Worker 信令面（多租户 + Durable Object）
```

## 平台计划

| 平台 | 虚拟网卡 | 交付 |
|---|---|---|
| Linux | `/dev/net/tun` | CLI + systemd |
| Windows | WinTun | 桌面程序 + 服务 |
| Android | VpnService（无需 root） | 自签 APK |
