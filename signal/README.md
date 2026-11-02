# qp2p 信令面（Cloudflare Worker）

只做三件事：**登记节点、撮合打洞、维持在线状态**。不转发任何业务数据。

## 部署

```bash
npm i -g wrangler
wrangler d1 create qp2p-signal          # 把返回的 database_id 填进 wrangler.toml
wrangler d1 execute qp2p-signal --file=schema.sql --remote
wrangler secret put ADMIN_SECRET        # 用于创建网络的密钥
wrangler deploy
```

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/health` | 无 | 健康检查 |
| POST | `/v1/admin/networks` | `X-Admin-Secret` | 创建网络，**仅此一次返回密钥** |
| POST | `/v1/join` | 密钥 | 校验密钥，返回网络信息 |
| POST | `/v1/register` | 密钥 | 上报候选、领取虚拟地址 |
| POST | `/v1/connect` | 密钥 | 撮合：返回对端候选并推送通知 |
| POST | `/v1/leave` | 密钥 | 主动下线 |
| GET | `/v1/ws` | 密钥 | 升级长连接，接收 `punch_request` |

密钥格式 `qp2p1_<network_id>_<secret>`，服务端只存 `sha256(secret)`。

## 创建网络

```bash
curl -X POST https://qp2p-signal.example.workers.dev/v1/admin/networks \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"name":"home"}'
```

返回里的 `token` 只出现一次，分发给要加入网络的节点。

## 额度设计

- 长连接替代轮询：日常零请求，只有真正打洞时才有消息
- 撮合一次往返完成：调用方请求里带自己的候选，对端通过长连接收到
- D1 只放冷数据：`last_seen` 每 60 秒批量刷一次
