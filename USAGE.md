# 使用手册

从零到两台机器互访的完整流程。**按顺序做，每一步都有验收判据**，不通过就停下，
别往下走——后面每一步都依赖前面。

> 先说清楚现状，免得你白折腾：
>
> | 能力 | 状态 |
> |---|---|
> | 打洞（UDP/QUIC）+ 双向身份认证 | ✅ 可用 |
> | 端口映射（`forward`，不需要 root） | ✅ 可用 |
> | 虚拟网卡（`tun`，Linux / Windows） | ✅ 可用（Windows 要 wintun.dll + 管理员） |
> | 信令服务（Worker） | ✅ 服务端可用 |
> | **客户端接信令（`qp2p join`）** | ❌ **还没实现** |
>
> 最后一条意味着：**你现在必须手工交换 IP 和 node_id**，加入码（token）暂时用不上。
> 手册里"第 2 步"仍然要做（把网络建出来），但它现在只是备用。

---

## 第 1 步：部署信令服务（一次性，只做一次）

已经有 Worker 且 `/v1/health` 返回 `has_admin_secret: true` 就跳到第 2 步。

1. Cloudflare Dashboard → **Workers & Pages → Create → Worker** → Deploy
2. 点 **Edit code** → 全选删掉 → 粘贴 `signal/worker.js` 全文 → **Deploy**
3. （强烈建议）**Storage → D1 → Create database**，名字随意（例 `qp2p`）
   → 回到 Worker → **Settings → Bindings → Add → D1** → 变量名必须是 **`DB`**
4. **Settings → Variables and Secrets → Add**：
   名字 **`ADMIN_SECRET`**，类型选 **Secret**，值用随机串：

   ```bash
   openssl rand -hex 32
   ```

**验收**

```bash
curl -s https://<你的域名>/v1/health
```

期望：

```json
{"ok":true,"storage":"d1","has_admin_secret":true,...}
```

- `storage` 必须是 `d1`；是 `memory` 说明 D1 没绑好（能跑，但多地域节点互相看不见）
- `has_admin_secret` 必须是 `true`，否则建网一律 503

---

## 第 2 步：建网络，拿加入密钥

```bash
curl -X POST https://<你的域名>/v1/admin/networks \
  -H "X-Admin-Secret: <你的 ADMIN_SECRET>" \
  -H "content-type: application/json" \
  -d '{"name":"home"}'
```

返回：

```json
{
  "ok": true,
  "network": { "id": "home", "cidr": "10.97.0.0/16" },
  "token": "qp2p1_home_3f8a1c9e..."
}
```

- **不填 `join_key` 时服务端随机生成，只回显这一次**，记下来
- 想自己定就加 `"join_key":"一串至少 16 位的随机字符"`；带同一把重复调用是幂等的
- 密钥丢了就用 `POST /v1/admin/networks/home/rotate` 换一把（旧令牌立刻失效）

**验收**：返回里有 `token`，格式为 `qp2p1_<网络id>_<密钥>`。

> ⚠️ 这枚 token 现在**没有客户端会用**。留着，等 `qp2p join` 做出来直接能用。
> 下面第 4 步的连接是手工完成的，不需要它。

---

## 第 3 步：拿到二进制

**方式一：下载 CI 产物**（推荐）

GitHub → Actions → 最近一次成功的 run → 页面底部 Artifacts：

| 产物 | 什么时候用 |
|---|---|
| `qp2p-linux-x86_64-static` | **优先用这个**，静态链接，任何发行版都能跑 |
| `qp2p-linux-x86_64` | 动态链接，要求 glibc ≥ 2.39（Ubuntu 24.04+） |
| `qp2p-windows-x86_64` | Windows |

```bash
chmod +x qp2p
```

**方式二：自己编**

```bash
cargo build --release          # 产物 target/release/qp2p
```

**Windows 额外一步**：把 [wintun.dll](https://www.wintun.net/)（选 amd64）放到
`qp2p.exe` 同目录。只有 `tun` 模式需要它，`forward` 不需要。

**验收**

```bash
./qp2p --version        # qp2p 0.1.0 (protocol 1)
```

---

## 第 4 步：两台机器建立连接

先决定用哪种方式，选一个就行：

| | `forward` 端口映射 | `tun` 虚拟网卡 |
|---|---|---|
| 需要权限 | **不需要** | Linux 要 root，Windows 要管理员 |
| 能访问什么 | 你配置的那一个地址 | 整个虚拟网段（`10.64.x.x`） |
| 适合 | 访问某个 Web / SSH / 数据库 | 想"像在同一局域网"一样用 |

**建议先跑通 `forward`**：不用权限，出错信息也清楚。

### 4.0 两边都先做这一步

在**两台机器**上分别执行：

```bash
./qp2p doctor --data-dir ~/.qp2p
```

输出类似：

```
node_id: 56bcc722ac8270ca25a72ec05a66e26
pubkey : 259c1ac8...
udp  local: 0.0.0.0:51820
candidate host 192.168.1.10:51820
```

要记下三样：

1. **`node_id`**（32 位十六进制）——填对方的 `--peer-id`
2. **候选地址**——填对方的 `--peer`
3. 如果跨网，加 `--stun stun.l.google.com:19302` 再跑一次，
   拿到 `candidate srflx` 那一行的公网地址，那个才是对方该填的 `--peer`

> `--data-dir` 一定要给，否则默认 `~/.qp2p`。**同一台机器跑两个实例时，两个目录必须不同**，
> 否则身份和端口会打架。

### 4.1 端口映射：把对端的某个地址变成本机端口

假设：

- A 机 `192.168.1.10`，想访问 B 机所在网络里的 `10.0.0.7:22`（SSH）
- B 机 `192.168.1.20`，想访问 A 机所在网络里的 `10.0.0.5:80`（网页）

```bash
# A 机（listener，不加 --dialer）
./qp2p forward \
  --bind 0.0.0.0:51820 --peer 192.168.1.20:51820 \
  --peer-id <B 的 node_id> \
  --listen 127.0.0.1:2222 --target 10.0.0.7:22 --serve 10.0.0.5:80 \
  --data-dir ~/.qp2p

# B 机（dialer，加 --dialer）
./qp2p forward \
  --bind 0.0.0.0:51820 --peer 192.168.1.10:51820 --dialer \
  --peer-id <A 的 node_id> \
  --listen 127.0.0.1:8080 --target 10.0.0.5:80 --serve 10.0.0.7:22 \
  --data-dir ~/.qp2p
```

**三个语义，最容易搞错，必须分清：**

| 参数 | 含义 | 谁填什么 |
|---|---|---|
| `--listen` | 本机开哪个端口给**自己**用 | 自己决定，随便 |
| `--target` | 对端要去连的地址（**写对端那边的地址**） | A 填 B 的、B 填 A 的 |
| `--serve` | 本机允许对端连的地址（**写自己这边的地址**） | A 填自己的、B 填自己的 |

`--target` 和 `--serve` 是**交叉对应**的：A 的 `--target` 必须等于 B 的 `--serve`，反之亦然。
`--serve` 不填就是**拒绝一切入站**，日志会有警告。

**验收**

日志出现这两行：

```
[punch] 对端认证通过 peer=<对端 node_id>
直连已建立 rtt=1.3ms
```

然后：

```bash
ssh -p 2222 root@127.0.0.1     # 在 A 上，连到了 B 侧的 10.0.0.7:22
curl http://127.0.0.1:8080     # 在 B 上，连到了 A 侧的 10.0.0.5:80
```

### 4.2 虚拟网卡：整网段互访

```bash
# A 机
sudo ./qp2p tun --bind 0.0.0.0:51820 --peer 192.168.1.20:51820 \
  --peer-id <B 的 node_id> --net 10.64.0.0/16 --data-dir /etc/qp2p

# B 机
sudo ./qp2p tun --bind 0.0.0.0:51820 --peer 192.168.1.10:51820 --dialer \
  --peer-id <A 的 node_id> --net 10.64.0.0/16 --data-dir /etc/qp2p
```

启动后会打印各自的虚拟地址（由 `node_id` 派生，重启不变）：

```
虚拟地址   : 10.64.37.181/16
隧道已启动：可以 ping 对端的虚拟地址
```

**验收**

```bash
ping 10.64.x.y      # 换成对端打印的地址
```

ping 通说明隧道是通的。**这一步不需要对端开转发**——echo 请求由对端直接应答。

**想访问对端背后的整个局域网**（比如 B 家里的 `192.168.1.0/24`）：

```bash
# A 机：把那个网段指到隧道
sudo ./qp2p tun ... --route 192.168.1.0/24

# B 机：需要转发 + SNAT，否则内网设备不知道怎么回到 10.64/16
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.64.0.0/16 -o eth0 -j MASQUERADE
```

---

## 第 5 步：退出

`Ctrl+C` 即可。程序会：

- 关掉 QUIC 连接
- **删掉路由器上的 UPnP 端口映射**（不做的话，端口会在路由器里挂一小时）

如果进程被强杀（`kill -9`），映射会残留到租约到期，重启一次即可重新建立。

---

## 故障对照表

| 症状 | 最可能的原因 | 怎么确认 |
|---|---|---|
| `错误：缺少 --peer-id` | 没写 `--peer-id` 也没写 `--any-peer` | 按提示补上；只在可信网络里试验才用 `--any-peer` |
| `对端身份不符：期望 … 实际 …` | 两边 `--peer-id` 填错了，或对端换了身份（换了 `--data-dir`） | 在对方跑 `qp2p doctor` 重新抄 node_id |
| `打洞失败: 超时` | 双方在不同 NAT 后面，但 `--peer` 填的是内网地址 | 加 `--stun` 拿到公网候选，用它当 `--peer` |
| 连上了但访问超时 | `--serve` 没填，或填的不是对方的 `--target` | 看日志有没有"拒绝未授权目标" |
| `创建虚拟网卡失败` | 没 root / 没管理员 / 缺 wintun.dll | Linux 用 sudo；Windows 放好 dll 并用管理员终端 |
| `udp 公网: 未知` | 没配 `--stun` 或 STUN 不可达 | 换一个 STUN 服务器，或确认能出 UDP |
| Worker 返回 503 `admin_secret_unset` | Worker 没配 `ADMIN_SECRET`，或名字写错 | `/v1/health` 里 `has_admin_secret` 应为 `true` |

排障先看日志：`RUST_LOG=qp2p=debug ./qp2p ...`

---

## 还没做到的（别在这上面浪费时间）

- **`qp2p join` 不存在**：加入码拿到了也用不上，连接仍要手工交换 IP 和 node_id
- **没有中继**：对称 NAT、严格企业防火墙 **100% 连不上**，没有任何兜底
- **只支持 TCP**：UDP 目标（DNS、游戏）不通
- **没有后台服务**：关掉终端连接就断；没有开机自启
- **Android 没有交付**
- **多跳路由**（A 经 B 访问 C）没做
