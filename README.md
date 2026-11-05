# qp2p

私有打洞组网：节点向 Worker 上报连通信息，Worker 只做撮合，节点之间打洞直连后互相访问。任何业务数据都不经过服务器。

设计文档见 [DESIGN.md](DESIGN.md)。

**要直接用，看 [USAGE.md](USAGE.md)**：从部署信令到两台机器互访的完整流程，每步都有验收判据。

## 当前进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | workspace、CI、工具链 | ✅ |
| P1 | 纯逻辑：候选地址、STUN、时钟偏移、状态机、身份 | ✅ |
| P2 | 单 socket + 同 socket STUN + 角色化打洞 | ✅（探针复用 Initial，D1 魔数分流待补） |
| P3 | link 复用层（per-flow QUIC 流）+ 端口转发 | ✅ |
| P4 | CLI：`init` / `create` / `join` / `up` / `status`，以及 `punch` / `forward` / `doctor` | ✅ |
| P5 | Linux TUN + 路由下发 | ✅ |
| P6 | Windows TUN（WinTun） | ✅ 需管理员 + wintun.dll；非管理员自动降级为只打洞 |
| P7–P8 | Windows 桌面壳 / Android APK | ⬜ |
| P9 | 信令 Worker（单文件 + D1）+ 客户端组网联调 | ✅ |

## 快速开始

一条命令建网，一条命令加入，然后上线：

```bash
# 建网的机器（一次性，需要部署时设的 ADMIN_SECRET）
qp2p init https://p2p.example.com --admin <ADMIN_SECRET>
qp2p create home          # 打印一行 qp2p join qp2p1_home_...

# 其它每一台机器
qp2p join qp2p1_home_...

# 所有人
sudo qp2p up              # Windows：管理员终端里执行 qp2p up
```

看到 `✓ 直连已建立：bob (10.78.156.207)` 之后，直接 `ping` 对方的虚拟地址即可。
`qp2p status` 看成员，`qp2p token` 再看一次邀请令牌，`qp2p rotate` 换令牌。

部署 Worker、平台差异、验收判据和排障表都在 [USAGE.md](USAGE.md)。

## 手工调试（不经过信令服务）

排查"到底能不能打通"时，可以绕过信令，直接指定对端地址和 node_id。
两个终端各自知道对方的 UDP 地址（同一局域网用内网 IP 即可），
对方的 `node_id` 用 `qp2p doctor` 查（同一个 `--data-dir` 下重启不变）：

```bash
# 终端 1（A 侧）：把本机 8080 经隧道送到 B 侧能访问的 10.0.0.7:22
#               同时允许 B 经我访问 A 侧的 10.0.0.5:80
qp2p forward --bind 0.0.0.0:51820 --peer 192.168.1.20:51820 --peer-id <B 的 node_id> \
             --listen 127.0.0.1:8080 --target 10.0.0.7:22 --serve 10.0.0.5:80

# 终端 2（B 侧）：反过来
qp2p forward --bind 0.0.0.0:51820 --peer 192.168.1.10:51820 --dialer --peer-id <A 的 node_id> \
             --listen 127.0.0.1:9090 --target 10.0.0.5:80 --serve 10.0.0.7:22
```

方向容易搞反，记住两句：

- **`--target` 是对端要去连的地址**：流量经隧道送到对端，由对端发起 TCP 连接。写成本机侧的地址不会报错，只会连到对端的同名地址。
- **`--serve` 是本机允许对端访问的地址**：它必须等于**对端的 `--target`**，两边是交叉对应的。不填就等于拒绝一切入站，命令行会显式警告。

只想快速验证连通性、暂时不关心对端是谁，一侧写 `--any-peer` 也行
（它会打印警告，且放开的是"谁能连我"，不要长期这样跑）。

打洞成功后，访问本机 `127.0.0.1:8080` 的流量会经 QUIC 直连送到对端，由对端连它的 `10.0.0.7:22`。
`--stun host:port` 可重复指定，用同一个 UDP socket 探测公网映射。
`--peer` 也可重复：所有候选地址会**并行**打，先通先用。

## TUN 模式（整网段互访）

`forward` 是"一个本地端口 ↔ 一个对端地址"，要访问 20 个服务就得写 20 条。
`tun` 换成虚拟网卡：每台机器在 `10.64.0.0/16` 里有个固定地址，整网段透明可达。

```bash
# A（10.64.x.y），需要 root / 管理员
sudo qp2p tun --bind 0.0.0.0:51820 --peer <B 的地址> --peer-id <B 的 node_id> \
              --any-peer --net 10.64.0.0/16

# B（dialer）
sudo qp2p tun --bind 0.0.0.0:51820 --peer <A 的地址> --dialer --peer-id <A 的 node_id> \
              --net 10.64.0.0/16
```

两边会打印自己的虚拟地址（由 `node_id` 派生，重启不变），然后就能 `ping` 对面。

参数：

| 参数 | 作用 |
|---|---|
| `--net` | 虚拟网段，默认 `10.64.0.0/16`；两边必须一致 |
| `--tun-addr` | 手工指定虚拟地址；不填就按 `node_id` 派生 |
| `--mtu` | 虚拟网卡 MTU，默认 1400；内层 TCP 的 MSS 由它推出来 |
| `--dev` | 网卡名（Linux 最长 15 字节） |
| `--route` | 额外让某个网段走隧道，可重复 |

**平台要求**

- Linux：`/dev/net/tun` + `ip` 命令，需要 root 或 `CAP_NET_ADMIN`
- Windows：管理员权限 + [wintun.dll](https://www.wintun.net/) 放在 `qp2p.exe` 同目录
  （不静态链接，所以升级 dll 不用重编）

**访问对端背后的局域网**

```
A: qp2p tun ... --route 192.168.1.0/24     # 让 192.168.1.0/24 走隧道
B: 需要转发并做 SNAT，否则内网设备不知道怎么回到 10.64/16：
   sysctl -w net.ipv4.ip_forward=1
   iptables -t nat -A POSTROUTING -s 10.64.0.0/16 -o eth0 -j MASQUERADE
```

不做静态 NAT 的时候，**ping 仍然通**：echo 请求由对端直接应答，不经过内核转发。
这也是判断"隧道通没通"最省事的办法。

## 打洞成功率相关的实现

| 手段 | 做法 |
|---|---|
| 不依赖启动对齐 | 守候方长时间 accept 并周期性发探针；发起方每个候选只发一条连接，重传交给 QUIC |
| 窗口宽限 | 守候方窗口到点时不直接返回：先等已在飞的握手收尾（最多 5s），否则会丢掉对端正要完成的连接 |
| 建连确认 | 连上后双方在流上交换 HELLO/ACK；守候方先抢占再回 ACK，避免两端落在不同连接上 |
| 端口预映射 | 启动时尝试 UPnP-IGD，成功则多一个 `upnp` 候选；租约过半自动续租，退出时删除映射 |
| 并行候选 | 一轮打洞同时拨所有候选地址，先通先用 |
| 重试前刷新 | 每轮重试重建端点、重新 STUN，避免拿过期映射硬打 |
| 失败期保活 | 重试间隔里每 15s 向已知地址发小包，防止 NAT 映射被回收 |
| 并行 STUN | `--stun` 可配多个（支持域名），同时发出、先回先用，不再逐个等超时 |

## 安全边界

- **打洞成功后必须完成一次双向身份认证**，否则连接会被丢弃：
  双方各用身份私钥签 `QP2P-AUTH-3|<自己>|<对方>|<nonce_a>|<nonce_b>|<TLS 会话导出值>`，
  签名里同时绑定两个 node_id、两个本次连接现生成的 nonce，以及**这条 TLS 会话的导出值**。
  复放旧帧、反射、冒充已知 node_id 都会失败；路径上的中间人即使终结两段 QUIC 再逐帧转发，
  两段会话的导出值不同，签名在对面必然校验失败（通道绑定）。
  日志里的 `[punch] 对端认证通过 peer=...` 就是这一步；失败时 listener 会记录
  `[punch] 拒绝来自 ... 的连接`。
- **必须明说要连谁**：`--peer-id <32 位十六进制>` 指定"只接受这个对端"。
  不指定会拒绝启动——因为认证只证明"对面持有某把密钥"，不限定身份时任何人生成一把新密钥
  都能通过认证并访问 `--serve` 里的地址。确实要放开（仅限可信网络试验）请显式写 `--any-peer`。
  `qp2p doctor` 会打印本机的 `node_id`、`pubkey` 和 `tls_fp`，可直接比对。
- dialer 有多个候选地址时，某个候选背后是别的节点（比如同网段另一台 qp2p）只会丢弃那个候选，
  不影响其他候选；所有候选都是别人才会立刻失败。
- **认证的最后一步是双方各给一帧结论**：任何一侧拒绝，两侧都失败并说清原因，
  不会出现"自己打印认证通过、实际已被对端关掉"这种假成功。被拒时能看到
  `对端拒绝了本次连接：对端身份不符：期望 …，实际 …`。
  这一帧也保证先返回的一侧不会在对端还等着读的时候就把端点丢掉。
- 身份与证书落在 `--data-dir`（默认 `~/.qp2p`）：重启后 `node_id` 与 `tls_fp` 不变，
  否则钉扎和"记住这台机器"都无从谈起。`--peer-fp` 可以要求对端证书指纹一致，
  不符时连 QUIC 握手都过不去。
- 接受端只连**白名单（`--serve`）里**的目标，空表拒绝一切。
- 数据面支持 TCP 半关闭；半关闭后若双方都不再有数据往来，60 秒后回收。
- CLI 代码中 `Network` 的 `Debug` 已把 token 打码，避免日志泄漏 secret。
- QUIC 那一层默认自签 + 跳过校验；需要更严时可以 `--peer-fp` 钉扎证书，在 TLS 层就拒绝陌生证书。
  无论是否钉扎，能完成 QUIC 握手都不等于通过认证——真正决定"能不能用"的是上面那次带会话绑定的签名交换。

## 已知简化（后续补齐）

- 打洞探针复用 QUIC Initial，尚未做 `0x00QP2` 魔数分流（DESIGN D1/D6）
- 只有 UPnP，没有 NAT-PMP / PCP
- 私钥目录在 Windows 上没有 0600 这类位，依赖目录 ACL
- 只有 L4 端口映射，没有 TUN（P5）
- 没有 NAT 模拟器，跨 NAT 场景只能在真实网络验证
- 信令 Worker 用轮询而不是推送（否则需要 Durable Object），被动方知道连接请求会晚 20~60 秒

## 明确接受的两条风险（不打算修）

这两条都属于"拿到令牌的成员能不能乱来"，是内鬼问题，不是对外开放的攻击面。
按现在的定位（自己部署、发给认识的人），不值得为它加审批流程和配额机制：

- **成员可以注册大量假节点**：每个网络上限 256，超过 10 分钟没心跳会被清掉，
  满了淘汰最久离线的；但没有"踢人"接口，真被刷了只能换 `ADMIN_SECRET` 重新发牌。
- **公网候选可以填第三方地址**：Worker 只挡回环 / `0.0.0.0` / 链路本地 / 组播，
  不比对请求来源 IP。成员可以让整个网络替他向任意公网地址发 QUIC 包。

## 信令服务

`signal/worker.js` 是**单文件**，粘进 Cloudflare Dashboard 点 Deploy 就能用，
不需要 wrangler、不需要构建、不需要 Durable Object；绑一个 D1 作为存储，表会自动创建。

服务端有**两把互不相干的钥匙**：`ADMIN_SECRET` 只用于建网络和换密钥，节点从不接触；
每个网络有自己的加入密钥 `qp2p1_<网络>_<join_key>`，服务端只存它的哈希。
所以泄漏一把加入密钥只影响那一个网络，换 `ADMIN_SECRET` 也不会让节点掉线。

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

## 开发约定

- **编译和测试交给 CI**，本机不编。改完推上去看 Actions：
  `test (ubuntu)` 跑 clippy + 全部测试，`test (windows)` 跑 Windows 侧，
  `build (*)` 产出三个二进制。
- **不要往 C 盘写构建产物**：`CARGO_HOME`、`TMP/TEMP` 都指到 E 盘，
  需要在本机调试时先 `source scripts/dev-env.sh`（里面写了原因）。
- **推送用 `python scripts/push_api.py "说明"`**，不用 `git push`：
  本机到 github.com:443 的代理连接经常 502，`api.github.com` 才是通的。

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
