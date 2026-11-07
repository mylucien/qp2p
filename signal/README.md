# qp2p 信令面（Cloudflare Worker）

只做三件事：**登记节点、撮合打洞、维持在线状态**。不转发任何业务数据。

整份实现就是一个文件 `worker.js`，不需要 wrangler、不需要构建、不需要 Durable Object。

## 部署

1. **Workers & Pages → Create → Worker**，命名随意（例 `qp2p-signal`），Deploy
2. **Edit code**，把 `worker.js` 全选粘贴进去，**Deploy**
3. （强烈建议）**Storage → D1 → Create database**，名字 `qp2p`；
   回到 Worker → **Settings → Bindings → Add → D1 database**，变量名必须是 **`DB`**
4. **Settings → Variables → Add**：名字 **`ADMIN_SECRET`**，值用一串长随机
   （这是管理密钥，只用来建网络、换加入密钥，节点不接触）
5. 打开 `https://<你的域名>/v1/health`，看到 `{"ok": true}` 即可

匿名访问 `/v1/health` 只会拿到 `{"ok":true}`；根路径 `/` 故意返回 404，
不提供任何接口说明，外部扫描看不出这里跑的是什么服务。

表结构在第一次请求时自动建立，不需要手动执行 SQL。

不绑 D1 也能跑：状态在当前 isolate 的内存里，单机试用没问题，但多地域的节点可能
互相看不见（`/v1/health` 会显示 `"storage": "memory"`）。真正用起来请绑 D1。

## 两把钥匙

| | 谁持有 | 干什么 | 泄漏后果 |
|---|---|---|---|
| `ADMIN_SECRET` | 只有管理员（Worker 环境变量） | 建网络、换某个网络的加入密钥 | 别人能建网络、能重置任意网络的密钥 |
| 加入密钥 `<join_key>` | 该网络的每台节点 | 进入这一个网络 | 只丢这一个网络，换掉即可 |

两者没有任何推导关系：

- 服务端只存 `sha256(join_key)`，不存明文
- 泄漏一把加入密钥，推不出 `ADMIN_SECRET`，也推不出别的网络
- 换 `ADMIN_SECRET`，现有节点**不会**掉线
- 作废某个网络，只影响那一个网络

## 创建网络

```bash
curl -X POST https://<你的域名>/v1/admin/networks \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"name":"home","join_key":"我自己定的一串长密钥"}'
```

```json
{
  "ok": true,
  "network": { "id": "home", "name": "home", "cidr": "10.97.0.0/16" },
  "token": "qp2p1_home_我自己定的一串长密钥"
}
```

- `join_key` 可省略（16~128 字符）：省略时服务端随机生成 48 位十六进制，**只回显这一次**
- **优先让它自动生成**。手写密钥一旦 D1 备份泄漏就能离线爆破；明显可猜的会在响应里
  带一条 `warning`（不拒绝）
- 带**同一个** `join_key` 重复建网是幂等的；网络已存在又不带 `join_key` 时返回 409
- 网段从 `10.64.0.0/16` 起按网络 id 哈希挑位、跳过已占用，最多 64 个网络；
  要指定就加 `"cidr": "10.99.0.0/16"`

## 换掉某个网络的加入密钥

```bash
curl -X POST https://<你的域名>/v1/admin/networks/home/rotate \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"join_key":"换一把新的"}'      # 不填则随机生成
```

旧令牌立刻失效，其他网络不受影响。

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/health` | 无 / 管理密钥 | 匿名只回 `{"ok":true}`；带 `X-Admin-Secret` 才返回版本、存储后端、节点数、限额 |
| GET | `/admin` | 页面登录 | 内置管理页面（网络 / 节点 / 预留 / 审计） |
| POST | `/v1/admin/login` | secret 换 cookie | 签发 2 小时 HttpOnly 会话 |
| POST | `/v1/admin/logout` | cookie | 清掉会话 |
| GET | `/v1/admin/networks` | `X-Admin-Secret` 或 cookie | 网络列表（含在线数、预留数） |
| POST | `/v1/admin/networks` | 同上 | 创建网络，可带 `cidr` / `join_key` |
| PATCH | `/v1/admin/networks/:id` | 同上 | 改名字 / 改网段（网段外的节点自动重分配） |
| DELETE | `/v1/admin/networks/:id` | 同上 | 删除网络（要带 `{"confirm":"<id>"}`），连带清节点/事件/预留 |
| POST | `/v1/admin/networks/:id/rotate` | 同上 | 换掉该网络的加入密钥 |
| GET | `/v1/admin/networks/:id/nodes` | 同上 | 节点列表：在线状态、虚拟地址、NAT、最后心跳 |
| POST | `/v1/admin/networks/:id/nodes/:node/kick` | 同上 | 踢下线（清节点与它的事件，保留预留） |
| GET/POST | `/v1/admin/networks/:id/reservations` | 同上 | 查 / 加 IP 预留 |
| DELETE | `/v1/admin/networks/:id/reservations/:ip` | 同上 | 释放预留 |
| GET | `/v1/admin/audit` | 同上 | 管理操作审计（`?limit=`） |
| POST | `/v1/join` | 令牌 | 校验密钥、登记节点、领虚拟地址、拿对端列表 |
| POST | `/v1/register` | 令牌 | 上报候选地址（至少一个） |
| POST | `/v1/connect` | 令牌 | 撮合：返回对端候选，并给对端投一条事件 |
| GET | `/v1/events` | 令牌 | 拉取待处理事件（`?node_id=&since=`） |
| POST | `/v1/leave` | 令牌 | 主动下线 |

令牌走 `Authorization: Bearer <token>`；`/v1/events` 这类 GET 也接受 `?token=`。

## 签名

`node_id` 必须等于 `sha256(pubkey)[..32]`，否则 403。但只靠这个还不够：持有令牌的成员
能看到别人的 `node_id`，不签名就能用 `from=<受害者>` 提交请求、把受害者的候选改成自己的地址。
所以 **join / register / connect / events / leave 全部要求节点私钥签名**，且覆盖整个请求体：

```
body      = 请求 JSON 去掉 sig
canonical = 键按 Unicode 码点升序、无空白、非 ASCII 转义成 \uXXXX 的 JSON
digest    = sha256_hex(canonical)
message   = qp2p1|<op>|<network>|<ts>|<nonce>|<digest>
sig       = hex(ed25519_sign(私钥, utf8(message)))
```

- `ts` 毫秒时间戳，服务端只接受 ±120 秒内
- `nonce` 16~64 位十六进制，同一网络内一次性；写操作消费它，重复提交 403。
  轮询不消费（幂等），否则每次心跳都要多写一行
- 数字只允许 ±(2^53-1) 以内的整数；`-0` 和超范围值会被拒（`detail` 写「请求体无法规范化」）。
  `1.0`、`1e2` 在 JS 里解析后就是 `1`、`100`，无法区分，所以 Rust 客户端请用 `u64`/`i64`
- 键排序按码点而不是 UTF-16 码元

Rust 侧 `crates/core/src/signal/canonical.rs` 是同一套规则的实现，和 JS 共用测试向量
（含固定种子下的确定性签名），任何一边改了序列化都会在 CI 里失败。

手算 node_id：

```bash
node -e 'crypto.subtle.digest("SHA-256", Buffer.from(process.argv[1],"hex")).then(d=>console.log(Buffer.from(d).toString("hex").slice(0,32)))' <pubkey hex>
```

## IP 预留

`reservations` 表把用户手填的地址固定下来：

| kind | 何时产生 | 生命周期 |
|---|---|---|
| `user` | 用户 join 时指定、或管理员手动预留 | 一直保留，除非管理员释放或删网 |
| `auto` | 服务端自动分配 | 跟着节点走，节点被清理时一起删 |

- 节点离线 10 分钟被清掉后，手填地址仍归它，重连自动拿回
- 别人填这个地址会得到 `409 virtual_ip_reserved`
- 自动分配会跳过所有「别人的预留」
- 改网段时，落在新网段外的节点重新分配，失效的预留一并清理

## 虚拟地址

与 `crates/core/src/identity.rs::derive_virtual_ip` 是同一套算法
（`sha256(node_id_bytes ++ salt_be_u32)`，取前 4 字节套进网段），两边共用测试向量。
服务端返回的地址可验证，客户端也能自己算，不依赖服务端活着。

## 轮询与额度

没有 WebSocket，`punch_request` 存在事件表里，节点用 `/v1/events?since=<游标>` 拉。
延迟靠两点兜住：`/v1/connect` 的响应直接带对端候选，发起方不必等通知；
打洞本身是持续重发（dialer 每 150ms 一轮、连打 10s，失败退避重试）。

| 项 | 估算 |
|---|---|
| 每节点每天请求 | 20s 轮询 ≈ 4,300；30s ≈ 2,900；60s ≈ 1,440 |
| 每节点每天写行数 | 心跳 1,440 行（`last_seen` 60 秒节流，与轮询频率无关） |
| 免费额度 | 10 万请求/天、10 万行写/天 |

按 60 秒拉一次，单 Worker 约能带 **60~70 个节点**；30 秒约 30~35 个。

- 限流：每 IP 每分钟 240 次（`/v1/health` 单独 60 次），超了返回 429
- 僵尸节点：超过 10 分钟没心跳会被清理；网络满（256）时优先淘汰最久离线的
- 首次拉事件（`since=0`）只返回最近 30 秒的 `punch_request`

## 验收线上部署

```bash
ADMIN_SECRET=你的密钥 node signal/smoke.mjs --remote https://你的域名
```

跑完打印每一项 ok/FAIL。它会建两个测试网络（`home-lab`、`lab`）、注册两个随机身份的节点，
结束时清理，不留垃圾数据。
