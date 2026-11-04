# qp2p 信令面（Cloudflare Worker）

只做三件事：**登记节点、撮合打洞、维持在线状态**。不转发任何业务数据。

整份实现就是一个文件 `worker.js`，**不需要 wrangler、不需要构建、不需要 Durable Object**。

## 部署（全在 Dashboard 里点）

1. **Workers & Pages → Create → Worker**，命名随意（例：`qp2p-signal`），Deploy
2. 点 **Edit code**，把 `worker.js` 全选粘贴进去，**Deploy**
3. （强烈建议）**Storage → D1 → Create database**，名字 `qp2p`
   然后回到 Worker → **Settings → Bindings → Add → D1 database**，变量名填 **`DB`**，选刚建的库
4. **Settings → Variables → Add**，名字 **`ADMIN_SECRET`**，值随便一串长随机
   （这是**管理密钥**，只用来建网络、换加入密钥；节点不用它）
5. 打开 `https://<你的域名>/v1/health`，看到 `"ok": true` 就好了

表结构在第一次请求时自动建立，**不需要手动执行 SQL**。

不绑定 D1 也能跑：状态放在当前 isolate 的内存里，单机试用没问题，
但多地域的节点可能互相看不见（`/v1/health` 会显示 `"storage": "memory"` 并给出警告）。
真正用起来请绑定 D1。

## 两把钥匙，别混

| | 谁持有 | 干什么 | 泄漏后果 |
|---|---|---|---|
| `ADMIN_SECRET` | **只有管理员**（Worker 环境变量） | 建网络、换某个网络的加入密钥 | 别人能建网络、能重置任意网络的密钥 |
| 加入密钥 `<join_key>` | 该网络的每台节点 | 进入这一个网络 | 只丢这一个网络，换掉即可 |

**两者没有任何推导关系。** 加入密钥在创建网络时确定（你指定，或服务端随机生成），
服务端只存它的 `sha256`：
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

返回：

```json
{
  "ok": true,
  "network": { "id": "home", "name": "home", "cidr": "10.97.0.0/16" },
  "token": "qp2p1_home_我自己定的一串长密钥"
}
```

- `join_key` 可省略（16~128 字符）：省略时服务端随机生成 48 位十六进制，**只回显这一次**
- 带**同一个** `join_key` 重复建网是幂等的，返回同一把令牌，方便把命令存进脚本
- 网络已存在又不带 `join_key` 时返回 409，不会悄悄换掉大家的密钥
- 令牌形状是 `qp2p1_<网络id>_<join_key>`，节点只拿这个，永远不接触 `ADMIN_SECRET`

网段从 `10.64.0.0/16` 起顺序分配，最多 64 个网络，按网络 id 的哈希挑位并跳过已占用的。
需要指定就在请求里加 `"cidr": "10.99.0.0/16"`。

## 换掉某个网络的加入密钥

```bash
curl -X POST https://<你的域名>/v1/admin/networks/home/rotate \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "content-type: application/json" \
  -d '{"join_key":"换一把新的"}'      # 不填则随机生成
```

旧令牌立刻失效，其他网络不受影响。

> **升级提示**：2.0 版本的令牌是 `HMAC(ADMIN_SECRET, "token:<网络>")`，与 `ADMIN_SECRET`
> 绑死——拿到一把令牌就能离线爆破管理密钥。这类老网络仍能继续用（服务端有兼容分支），
> 但建议对每个网络调一次 `rotate`，之后就和 `ADMIN_SECRET` 解耦了。

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/v1/health` | 无 | 状态、存储后端、节点数 |
| POST | `/v1/admin/networks` | `X-Admin-Secret` | 创建网络，返回加入密钥 |
| POST | `/v1/admin/networks/:id/rotate` | `X-Admin-Secret` | 换掉该网络的加入密钥 |
| POST | `/v1/join` | 令牌 | 登记节点、领虚拟地址、拿对端列表 |
| POST | `/v1/register` | 令牌 | 上报候选地址（至少一个） |
| POST | `/v1/connect` | 令牌 | 撮合：返回对端候选，并给对端投一条事件 |
| GET | `/v1/events` | 令牌 | 拉取待处理事件（`?node_id=&since=`） |
| POST | `/v1/leave` | 令牌 | 主动下线 |

令牌走 `Authorization: Bearer <token>`；`/v1/events` 这种 GET 也接受 `?token=`。

### 加入密钥为什么只存哈希

`token = qp2p1_<网络id>_<join_key>`，服务端存的是 `sha256(join_key)`。

比对时把令牌里的那一段重新哈希，与库里的值做常数时间比较。
数据库里没有明文密钥，但也不需要 `ADMIN_SECRET` 参与——所以这两把钥匙互不影响。

### 身份与签名

`node_id` 必须等于 `sha256(pubkey)[..32]`，否则 403。

但只有这个还不够：持有令牌的成员在 `peers` 里能看到别人的 `node_id`，
如果不签名，他就能用 `from=<受害者>` 提交请求，把受害者的候选改成自己的地址
（在 TLS 还没有对端认证的当下，这就是中间人）。

所以 **join / register / connect / events / leave 全部要求节点私钥签名**，
而且签名覆盖**整个请求体**，不是手挑几个字段：

```
body      = 请求 JSON 去掉 sig
canonical = 键按 Unicode 码点升序、无空白、非 ASCII 转义成 \uXXXX 的 JSON
digest    = sha256_hex(canonical)
message   = qp2p1|<op>|<network>|<ts>|<nonce>|<digest>
sig       = hex(ed25519_sign(私钥, utf8(message)))
```

- `ts` 毫秒时间戳，服务端只接受 ±120 秒内
- `nonce` 16~64 位十六进制，同一网络内一次性使用；写操作会消费它，重复提交直接 403
- 轮询（`/v1/events`）不消费 nonce，因为它本身幂等，否则每次心跳都要多写一行
- **数字只允许 ±(2^53-1) 以内的整数**。`-0`、超出范围的整数会被拒绝
  （服务端返回 403，`detail` 里写"请求体无法规范化"）。
  注意 `1.0`、`1e2` 这类写法在 JS 里解析后就是 `1`、`100`，**无法区分**，会被当作整数；
  但 Rust 侧会原样看到 `1.0` 并拒绝签名。所以 Rust 客户端请用 `u64`/`i64` 写数字字段，
  不要用 `f64`——这是唯一会真的把两边摘要搞坏的情况。
- 键排序按码点而不是 UTF-16 码元；JS 默认 `sort()` 在遇到 BMP 之上的字符时顺序不同，
  所以实现里用了专门的比较函数

这样 `candidates`、`tls_fp`、`name` 任何一项被改，摘要就变，签名立刻失效。
Rust 侧 `crates/core/src/signal/canonical.rs` 有一份同规则实现，和 JS 共用一组
测试向量（含固定种子下的确定性签名），任何一边改了序列化都会在 CI 里失败。

`pubkey` 是 32 字节 Ed25519 公钥的十六进制。手算 node_id：

```bash
node -e 'crypto.subtle.digest("SHA-256", Buffer.from(process.argv[1],"hex")).then(d=>console.log(Buffer.from(d).toString("hex").slice(0,32)))' <pubkey hex>
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

限流：每 IP 每分钟 240 次请求（`/v1/health` 单独 60 次），超了直接 429。
`/v1/health` 里的节点数是 60 秒缓存，不会变成免费的 D1 读放大器。

僵尸节点：超过 **10 分钟**没有心跳的节点会被后台清理；网络满（256）时优先淘汰
最久没心跳的离线节点，而不是直接拒绝新节点。

首次拉事件（`since=0`）只返回最近 30 秒的 `punch_request`——更早的连接请求已经过期，
交给客户端判断不如在服务端就挡掉。

## 本地测试

```bash
node signal/smoke.mjs                              # 内存 + SQLite 冒充 D1，两条路径各 72 项
node signal/dev-server.mjs                         # 起在 127.0.0.1:8787，可直接 curl
ADMIN_SECRET=dev node signal/dev-server.mjs 9000   # 换端口
```

`dev-server.mjs` 把 `worker.js` 的 fetch handler 挂到真 HTTP 服务上，存储用 Node 内置
SQLite 冒充 D1（重启即清空）。改完 Worker 想用 curl 试一下，用它比部署到线上快得多。

## 验收线上部署

同一套断言可以直接打远端，确认部署的是新代码、D1 通、签名生效：

```bash
ADMIN_SECRET=你的密钥 node signal/smoke.mjs --remote https://你的域名
```

跑完会打印每一项的 ok/FAIL。它会建两个测试网络（`home-lab`、`lab`），
注册两个随机身份的节点并在结束时清理，不会留下垃圾数据。

## 还没做的

- **候选地址只挡了明显不可用的**（回环、0.0.0.0、链路本地、组播/保留段），
  没做"这个 IP 属于不属于该成员"的校验——内网地址依然可以登记。
- **服务端不下发时间对齐信息**：`server_ms` 有了，客户端还没用它做时钟估计。
- **网络删除 / 成员踢除**：没有管理接口，只能换 `ADMIN_SECRET` 全网重来。
- **审计**：没有连接日志。
- **D1 的 UNIQUE 约束**没加，`assignIp` 在极端并发下仍可能撞地址（概率极低，
  影响是两台机器同址）。
