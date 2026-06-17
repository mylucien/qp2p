# qp2p — QUIC P2P Edge Agent

[![Build](https://github.com/mylucien/qp2p/actions/workflows/build.yml/badge.svg)](https://github.com/mylucien/qp2p/actions/workflows/build.yml)

qp2p 是一个基于 QUIC 协议的 P2P 边缘节点代理，通过 Cloudflare Worker 信令、NAT 打洞和 TUN 虚拟网卡实现节点间直连。

## 架构

```
┌─────────────────────────────────────────────┐
│            Cloudflare Worker                │
│    信令服务 /register /connect /token        │
└───┬──────────────┬──────────────────┬───────┘
    │              │                  │
┌───▼─────┐  ┌────▼────┐       ┌────▼────┐
│  Node A  │  │  Node B │  ...  │  Node N │
│ ┌──────┐│  │ ┌──────┐│       │ ┌──────┐│
│ │ TUN  ││  │ │ TUN  ││       │ │ TUN  ││
│ │ QUIC ││  │ │ QUIC ││       │ │ QUIC ││
│ │Tunnel││  │ │Tunnel││       │ │Tunnel││
│ └──────┘│  │ └──────┘│       │ └──────┘│
└─────────┘  └─────────┘       └─────────┘
```

## 快速开始

### 前置条件

1. 部署 Cloudflare Worker（见 `js/worker.js`）
2. 创建 Cloudflare Tunnel 获取 Token
3. 准备 `config.toml`：

```toml
worker_url    = "https://your-worker.workers.dev"
auth_secret   = "<your-auth-secret>"
tunnel_token  = "<your-tunnel-token>"
virtual_ip    = "10.0.0.1/24"
group_name    = "my-network"
group_password = "your-password"
stun_server   = "stun.cloudflare.com:3478"
```

### 运行

```bash
# Linux (推荐，TUN 完整支持)
./qp2p

# Windows (需管理员权限)
qp2p.exe
```

### 首次启动

程序会自动完成：
1. 启动 cloudflared 建立隧道
2. 向 Worker 注册，获取 `edge_id`
3. 等待其他节点连接

## 编译

```bash
# Linux
cargo build --release

# Windows (MSVC)
cargo build --release --target x86_64-pc-windows-msvc
```

## 工作原理

| 步骤 | 描述 |
|------|------|
| 注册 | 节点通过 `/register` 向 Worker 上报自己的地址和隧道信息 |
| 发现 | 查询 `/connect` 获取对端地址和打洞时间窗口 |
| 打洞 | 双方在约定时间同时发送 QUIC Initial 包穿过 NAT |
| 直连 | 打洞成功后通过 QUIC 双向流传输数据 |
| 回落 | 打洞失败时通过 Cloudflare Tunnel 中继 |
| 重试 | 后台持续重试，成功后通过 QUIC 连接迁移无缝切换 |

## License

MIT
