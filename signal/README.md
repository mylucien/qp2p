# qp2p 信令面（Cloudflare Worker）

只做三件事：**登记节点、撮合打洞、维持在线状态**。不转发任何业务数据。

整份实现就是一个文件 `worker.js`，**不需要 wrangler、不需要构建、不需要 Durable Object**。

## 部署（全在 Dashboard 里点）

1. **Workers & Pages → Create → Worker**，命名随意（例：`qp2p-signal`），Deploy
2. 点 **Edit code**，把 `worker.js` 全选粘贴进去，**Deploy**
3. （强烈建议）**Storage → D1 → Create database**，名字 `qp2p`
   然后回到 Worker → **Settings → Bindings → Add → D1 database**，变量名填 **`DB`**，选刚建的库
4. **Settings → Variables → Add**，名字 **`ADMIN_SECRET`**，值随便一串长随机（这就是你的管理员密钥）
5. 打开 `https://<你的域名>/v1/health`，看到 `"ok": true` 就好了

表结构在第一次请求时自动建立，**不需要手动执行 SQL**。

不绑定 D1 也能跑：状态放在当前 isolate 的内存里，单机试用没问题，
但多地域的节点可能互相看不见（`/v1/health` 会显示 `"storage": "memory"` 并给出警告）。
真正用起来请绑定 D1。

## 创建网络

```bash
curl -X POST https://<你的域名>/v1/admin/networks \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"name":"home"}'
```

返回：

```json
{
  "ok": true,
  "network": { "id": "home", "name": "home", "cidr": "10.97.0.0/16" },
  "token": "qp2p1_home_<40 位十六进制>"
}
```

把这把 `token` 发给要加入网络的节点即可。**同一个名字重复创建会返回同一把密钥**，
所以密钥丢了不用重建网络，再调一次就行（前提是 `ADMIN_SECRET` 没变）。

网段从 `10.64.0.0/16` 起顺序分配，最多 64 个网络，按网络 id 的哈希挑位并跳过已占用的。
需要指定就在请求里加 `"cidr": "10.99.0.0/16"`。

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/health` | 无 | 状态、存储后端、节点数 |
| POST | `/v1/admin/networks` | `X-Admin-Secret` | 创建/取回网络密钥 |
| POST | `/v1/join` | 令牌 | 登记节点、领虚拟地址、拿对端列表 |
| POST | `/v1/register` | 令牌 | 上报候选地址（至少一个） |
| POST | `/v1/connect` | 令牌 | 撮合：返回对端候选，并给对端投一条事件 |
| GET | `/v1/events` | 令牌 | 拉取待处理事件（`?node_id=&since=`） |
| POST | `/v1/leave` | 令牌 | 主动下线 |

令牌走 `Authorization: Bearer <token>`；`/v1/events` 这种 GET 也接受 `?token=`。

### 令牌为什么不用存

`token = qp2p1_<网络>_<HMAC-SHA256(ADMIN_SECRET, "token:<网络>")[:40]>`。

服务端拿到令牌就地重算一遍比对即可，数据库里**不存任何密钥**。
副作用是换 `ADMIN_SECRET` 等于全网重新发牌——这正是想要的行为。

### 身份绑定

`node_id` 必须等于 `sha256(pubkey)[..32]`，否则 403。
这样持有令牌的成员无法用别人的 `node_id` 覆盖其记录，也无法替别人下线。
（更强的做法是让节点对请求签名，现在还没做，见文末。）

`pubkey` 是 32 字节 Ed25519 公钥的十六进制。手算 node_id：

```bash
node -e 'crypto.subtle.digest("SHA-256", Buffer.from("'"$(cat pubkey.hex)'"","hex")).then(d=>console.log(Buffer.from(d).toString("hex").slice(0,32)))'
```

## 虚拟地址

与 `crates/core/src/identity.rs::derive_virtual_ip` 完全同一套算法
（`sha256(node_id_bytes ++ salt_be_u32)`，取前 4 字节套进网段），
两边有共同的一组测试向量，改任意一边都会被抓出来。

所以服务端返回的地址是可验证的，客户端也能自己算——地址不依赖服务端活着。

## 通知是轮询，不是推送

去掉 Durable Object 之后没有 WebSocket，`punch_request` 存在事件表里，节点用
`/v1/events?since=<游标>` 拉。设计上靠两点兜住延迟：

- 发起方**不需要**等通知：`/v1/connect` 的响应里直接带对端候选，可以立刻开打
- 打洞本身是持续重发（dialer 每 150ms 一轮、连打 10s，失败退避重试），
  被动方晚 20~60 秒知道也还在窗口内

建议客户端在线时 20~30 秒拉一次。轮询同时承担心跳，但 `last_seen` 最多 60 秒写一次，
写额度不会被心跳烧光。

## 额度

| 项 | 估算 |
|---|---|
| 每个节点每天请求 | 20s 轮询 ≈ 4,300；30s ≈ 2,900；60s ≈ 1,440 |
| 每个节点每天写行数 | 心跳 1,440 行（60s 节流后与轮询频率无关） |
| 免费额度 | 10 万请求/天、10 万行写/天 |

按 60 秒拉一次算，单 Worker 大约能带 **60~70 个节点**；
30 秒拉一次大约 30~35 个。要带更多，就得换回有长连接的版本（那需要 Durable Object）。

限流：每 IP 每分钟 240 次请求，超了直接 429。这是防误用，不是防攻击。

## 本地测试

```bash
node signal/smoke.mjs
```

不需要 D1、不连 Cloudflare：走内存后端，覆盖建网 → 加入 → 上报 → 撮合 → 拉事件 →
下线 → 地址派生向量，共 39 项断言。

## 还没做的

- **请求签名**：现在只校验 `node_id` 来自 `pubkey`，没校验请求确实由私钥持有人发出。
  拿到令牌的人可以冒充**自己**的 node_id（但不能冒充别人的）。
- **服务端不下发时间对齐信息**：`server_ms` 有了，客户端还没用它做时钟估计。
- **网络删除 / 成员踢除**：没有管理接口，只能换 `ADMIN_SECRET` 全网重来。
- **审计**：没有连接日志。
