# qp2p

私有打洞组网：节点向 Cloudflare Worker 上报连通信息，Worker 只做撮合，
节点之间 QUIC 直连后互访。**业务流量不经过服务器**。

没有公网 IP 也能用，不需要端口映射，也不需要一台公网中转机。

## 能做什么

- 多台机器组成一个虚拟网络，每台分到 `10.x.y.z` 的虚拟地址，互相 `ping` 通
- 同一个虚拟地址上直接跑 SSH、HTTP、文件共享，不用再配端口映射
- 三端：Linux（TUN）、Windows（原生图形界面 + 系统托盘）、Android（VpnService）
- 换网自愈（WiFi ↔ 4G 几秒恢复）、空闲断链、虚拟地址手填并预留
- 信令面是单文件 Worker，Cloudflare 免费额度下约够 50 台常开设备

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

看到 `✓ 直连已建立：bob (10.78.156.207)` 后，`ping` 这个地址就通了。

## 下载与安装

[Releases](https://github.com/mylucien/qp2p/releases) 里有四个包，每个版本附 `SHA256SUMS.txt`：

| 平台 | 文件 |
|---|---|
| Windows 10/11 x64 | `qp2p-<版本>-windows-x86_64.exe`，单文件，双击即用，不用另放 dll |
| Linux x64（glibc ≥ 2.39） | `qp2p-<版本>-linux-x86_64` |
| Linux x64（老系统 / 容器） | `qp2p-<版本>-linux-x86_64-static`，静态链接 |
| Android 8+ | `qp2p-<版本>-android.apk`，debug 签名 |

详细步骤（部署信令、建网、加入、排障）见 [USAGE.md](USAGE.md)。

## 架构

```
crates/core     协议核心：STUN、打洞、QUIC、TUN、身份（无前端依赖）
crates/cli      命令行 + Windows 原生图形界面
crates/android  VpnService 外壳
signal/         单文件 Cloudflare Worker + D1 存储
```

- **信令面**：登记候选地址、撮合打洞、维持在线状态；不转发业务流量
- **数据面**：STUN 探测 → 服务端撮合 → QUIC 直连，端到端加密
- **身份**：Ed25519，`node_id` 由公钥派生，虚拟地址由身份派生；重启不变
- **认证**：每条直连建立后双方交换签名，签名绑定这条 TLS 会话，复放/反射/冒充都会失败

设计取舍与协议细节见 [DESIGN.md](DESIGN.md)。

## 命令

日常：`init` `create` `join` `up` `status` `token` `rotate` `leave` `config`
管理：`nets` `delete`（需要 `ADMIN_SECRET`）
调试：`punch` `forward` `tun` `doctor`（不需要信令服务器）

完整选项看 `qp2p --help` 和 `qp2p up -h`。

## 安全边界

- 加入令牌只存 sha256；`ADMIN_SECRET` 推不出加入令牌，换它不会让成员掉线
- 信令服务看得到：谁在线、候选地址、虚拟地址；**看不到**私钥和流量内容
- 已接受但不防的：拿到令牌的成员可以注册大量假节点，也可以让网络替他向任意公网地址发 QUIC 包
  —— 属于内鬼问题，按"自己部署、发给认识的人"的定位不做额外限制

## 平台要求

| 平台 | 虚拟网卡 | 要求 |
|---|---|---|
| Linux | `/dev/net/tun` | root 或 `CAP_NET_ADMIN` |
| Windows 10/11 | WinTun（已内嵌） | 管理员，exe 清单会自动提权 |
| Android 8+ | VpnService | 无需 root |

## 文档

| 文档 | 内容 |
|---|---|
| [USAGE.md](USAGE.md) | 部署、安装、建网、加入、上线、日常命令、配置、管理页、排障、安全模型 |
| [DESIGN.md](DESIGN.md) | 架构、协议、设计决策 |
| [signal/README.md](signal/README.md) | 信令服务的部署、接口、额度 |
