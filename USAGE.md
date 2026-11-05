# qp2p 使用手册

从零到多台机器互访。**建网、发密钥、加入、上线全部在客户端里完成**，
你不需要调用任何 HTTP 接口，也不需要手工交换 IP 和 node_id。

---

## 0. 最快路径

```bash
# ① 建网的那台机器（只做一次）
qp2p init https://p2p.example.com --admin <ADMIN_SECRET>
qp2p create home

# ② 其它每一台机器（把 ① 打印出来的那行原样发过去）
qp2p join qp2p1_home_xxxxxxxx

# ③ 所有人
sudo qp2p up                 # Linux
qp2p up                      # Windows：先用「以管理员身份运行」打开终端
```

`qp2p create` 会打印：

```
加入令牌（发给其它机器，一条命令就能加入）：

    qp2p join qp2p1_home_4b96...
```

那一行就是邀请。对方复制粘贴即可，不需要你解释任何东西。

---

## 1. 部署信令服务（一次性，做的人只有你）

信令服务器只做三件事：登记节点、撮合打洞、维持在线状态。**它不转发任何业务流量**，
所以带宽和额度压力都很小。

1. Cloudflare Dashboard → **Workers & Pages → Create → Worker** → Deploy
2. **Edit code** → 全选删除 → 粘贴仓库里的 `signal/worker.js` 全文 → **Deploy**
3. 建议绑定 D1（不绑也能跑，但状态只存在单个实例里，多地域部署会互相看不见）：
   **Storage → D1 → Create database**（名字随意，例 `qp2p`）
   → 回到 Worker → **Settings → Bindings → Add → D1**，变量名必须是 **`DB`**
4. **Settings → Variables and Secrets → Add**：名字 **`ADMIN_SECRET`**，类型 **Secret**，
   值用随机串（`openssl rand -hex 32`）

### 验收

```bash
qp2p init https://<你的域名> --admin <ADMIN_SECRET>
```

应当输出：

```
✓ Worker 可用
  版本    : 2.3.0
  存储    : D1（多地域一致）
  管理密钥: 已配置
```

- **版本低于 2.3**：请重新粘贴一次 `worker.js`（2.3 才有删网、列网络、自定义 IP）。2.2 起撮合事件里带了对端的虚拟地址，
  多机组网靠它决定「这个包该发给谁」（旧版客户端会用推导算法兜底，但网络里出现
  地址冲突时可能连错）。
- **存储显示"内存"**：没绑 D1，重启 Worker 就丢网络，确认上面第 3 步。
- **管理密钥: 未配置**：还能加入别人的网络，但建不了网络，确认上面第 4 步。

国内访问 `*.workers.dev` 可能不通，给 Worker 绑定一个自己的域名再填进来即可。

---

## 2. 安装客户端

从仓库 **Actions → 最新一次 ci → Artifacts** 下载：

| 平台 | 文件 | 说明 |
|---|---|---|
| Linux x86_64（主流发行版） | `qp2p-linux-x86_64` | 需要 glibc ≥ 2.39（Ubuntu 24.04 及以上） |
| Linux x86_64（老系统/容器） | `qp2p-linux-x86_64-static` | 静态链接，Debian 11/12、Alpine 都能跑 |
| Windows x86_64 | `qp2p-windows-x86_64` | 解压出 `qp2p.exe` |

```bash
chmod +x qp2p-linux-x86_64-static
sudo mv qp2p-linux-x86_64-static /usr/local/bin/qp2p
qp2p -V
```

**Windows 的虚拟网卡**还需要 `wintun.dll`：从 <https://www.wintun.net/> 下载 amd64 包，
把 `bin/amd64/wintun.dll` 放到 `qp2p.exe` 同目录。没有它也能打洞，只是不能 ping 通对端。

---

## 3. 建网络（第一台机器）

```bash
qp2p init https://p2p.example.com --admin <ADMIN_SECRET>   # 如果第 1 步已经做过可跳过
qp2p create home
```

网络名只能用小写字母、数字和连字符。想自己定加入密钥（比如给家人用的口令）可以：

```bash
qp2p create home --key "my-family-2026-passphrase"          # 16~128 字符
```

### 它做了什么

| 动作 | 结果 |
|---|---|
| 在服务端建网络 | 分配一个 `10.x.0.0/16` 网段，全网络共用 |
| 生成加入密钥 | 默认服务端随机生成；也可以 `--key` 自己定 |
| 保存到本机 | 写进 `~/.qp2p/config.toml`（权限 0600） |

之后 `qp2p token` 可以随时再显示令牌，`qp2p rotate` 可以换新的。

---

## 4. 加入（其它每一台机器）

```bash
qp2p join qp2p1_home_4b96...
```

也可以直接粘贴带令牌的链接（`https://.../?token=qp2p1_home_...`），客户端会自己拆。

它会立刻用这个令牌向服务端登记一次，成功说明令牌有效：

```
✓ 已加入 home（10.78.0.0/16）
  本机  : bob  10.78.129.223
  成员  : 1 个在线/历史节点
```

虚拟地址是服务端分配的，同一个网络里唯一，重启不变。

---

## 5. 上线

```bash
sudo qp2p up                    # Linux
qp2p up                         # Windows（管理员终端）
```

启动后会依次做：

1. 绑定 UDP（默认 `51820`）、向 STUN 探自己的公网映射、尽量用 UPnP 开端口
2. 把候选地址登记到信令服务
3. 拉取事件，和同网络里的每个节点逐个打洞
4. 打通的节点直接打印出来

```
qp2p 0.1.0 · 网络 home
信令 https://p2p.example.com
本机 laptop  node_id=e6659aba1e2a8fa837d9a1251ee1b584
公网映射 120.229.55.68:6923
虚拟地址 10.78.160.187/16（home）
成员 2 个（在线 2）
虚拟网卡 qp2p0 已就绪
已上线（Ctrl+C 退出）。直连建立时会打印对端名字和延迟。
✓ 直连已建立：bob (10.78.156.207) rtt=18.4ms
```

### 验收：ping 对方的虚拟地址

```bash
ping 10.78.156.207         # Windows: ping 10.78.156.207
```

能 ping 通就说明整条链路（信令 → 打洞 → 认证 → 虚拟网卡）都通了。
端口、SSH、文件共享都直接用这个虚拟地址，不需要再做端口映射。

### 常用参数

| 参数 | 用途 |
|---|---|
| `--name <名字>` | 成员列表里显示的名字，默认取主机名 |
| `--punch-only` | 只打洞、不建虚拟网卡；不需要 root，用来先验证能不能连通 |
| `--bind <addr>` | UDP 监听地址，端口冲突时换一个（默认 `0.0.0.0:51820`） |
| `--stun <host:port>` | 可重复，覆盖默认的 STUN 服务器 |
| `--dev <名字>` | 虚拟网卡名，默认 `qp2p0` |
| `--mtu <n>` | 默认 1400；链路质量差可以降到 1280 |
| `--route <网段>` | 额外让某个网段走隧道（访问对端背后的局域网） |

> 没有 root 时会**自动降级**成「只打洞」模式：能连上、能看日志，但 ping 不通。
> 看到提示就加 sudo（Linux）或用管理员终端（Windows）重跑。

---

## 6. 日常操作

| 命令 | 作用 |
|---|---|
| `qp2p status` | 本机地址 + 成员列表（在线状态、虚拟地址、候选数） |
| `qp2p token` | 再显示一次加入令牌，用来发给新机器 |
| `qp2p rotate` | 换新令牌，旧令牌立刻失效（有人退出群聊时用） |
| `qp2p leave` | 把本机从网络里注销（不影响本机保存的令牌） |
| `qp2p config` | 查看/修改本机配置（MTU、网卡名、路由、虚拟地址…） |
| `qp2p up -h` | 看组网的完整选项 |

管理员命令（需要 `ADMIN_SECRET`）：

| 命令 | 作用 |
|---|---|
| `qp2p nets` | 列出这台 Worker 上的所有网络（成员数、网段、准入密码是否设置） |
| `qp2p rotate --network <名字>` | 换某个网络的准入密码；不给 `--network` 就是本机所在的网络 |
| `qp2p rotate --network x --key <新密码>` | 自己指定新密码（16~128 字符） |
| `qp2p delete <名字> --yes` | 删除网络，成员和事件一并清除，**不可恢复** |

`qp2p status` 的样子：

```
网络     : home  10.78.0.0/16
本机名称 : laptop
虚拟地址 : 10.78.160.187（网段 10.78.0.0/16）

成员（1 个，不算本机）：
  名称               虚拟地址             状态      可直连地址
  bob              10.78.156.207    在线      3
```

**换密钥的注意事项**：`rotate` 之后，已经在运行的节点**直连不会立刻断**，
但它们 60 秒后刷新注册会被拒。它们会打印「加入令牌已失效」并停下，
需要拿新令牌重新 `qp2p join` 一次再 `qp2p up`。

---

## 6.5 自定义：虚拟地址 / MTU / 网卡名 / 路由

用户级的东西改一次就记住，不用每次 `up` 都带参数。

### 加入时固定自己的地址

```bash
qp2p join <令牌> --ip 10.78.0.20
qp2p join <令牌>                 # 不给就由服务端分配
```

服务端会校验：必须落在本网络网段内、不能是网段地址或广播地址、不能和别人重复。
冲突时直接报错并告诉你是谁占了：

```
10.78.0.20 已经被节点「nas」占用，换一个
```

想改已经在用的地址：

```bash
qp2p config set ip 10.78.0.30    # 下次 up 生效
```

### 其它本机配置

```bash
qp2p config                      # 看当前生效的全部配置
qp2p config set mtu 1280
qp2p config set dev qp2p1
qp2p config set stun stun.cloudflare.com:3478,stun.l.google.com:19302
qp2p config set routes 192.168.1.0/24,192.168.2.0/24
qp2p config unset mtu            # 回到默认
```

可用项：`worker` `admin_secret` `node_name` `listen` `mtu` `dev` `stun` `routes` `ip`。

**取值顺序**：命令行 > 配置文件 > 默认值。
想让这次的命令行选择长期生效，加 `--save`：

```bash
qp2p up --mtu 1280 --route 192.168.1.0/24 --save
```

也可以直接 `qp2p config set`，两者等价。

## 7. 组网是怎么连的

- **谁连谁**：每个节点都从服务端拿到成员列表；`node_id` 小的一方主动发起，
  另一方收到撮合事件后在本机守着，两边同时开孔。启动先后无所谓。
- **连不上会自动重试**：退避 10s → 20s → 40s → 60s，一直连到为止。
- **多对端**：一台机器同时和多个节点保持独立直连，数据面按**目标虚拟地址**选连接，
  所以 A↔B、A↔C 之间是同一条虚拟网卡上的不同连接，不需要两套配置。
- **NAT 变了**：候选地址每 60 秒重新登记一次；长时间一个都连不上时会重建端点重新 STUN。
- **身份**：每条连接建立后双方交换 Ed25519 签名并互相验签，签名绑定这条 TLS 会话。
  信令服务只是介绍人，拿不到你的密钥，也无法冒充任何一个节点。

---

## 8. 平台说明

| 平台 | 状态 | 说明 |
|---|---|---|
| Linux | ✅ | TUN 需要 root 或 `CAP_NET_ADMIN` |
| Windows | ✅ | 需要管理员 + `wintun.dll`；非管理员会自动降级为只打洞 |
| Android | ✅ | APK 走 VpnService，只接管虚拟网段 |

### Windows 怎么装

1. 下 CI 产物 `qp2p-windows-x86_64`（Actions 里最新一次成功构建的 Artifacts）
2. 解压，目录里应当有 `qp2p.exe`、`wintun.dll`、`USAGE.md` —— **dll 不要单独挪走**
3. 右键开始菜单 →「终端(管理员)」，`cd` 到解压目录
4. 命令和 Linux 完全一样：

```powershell
.\qp2p.exe init https://你的-worker.workers.dev
.\qp2p.exe join qp2p1_home_xxxxxxxx
.\qp2p.exe up
```

不加管理员也能 `up`，但会降级成「只打洞」：能看到谁连上了，ping 不通。
这也是判断"打洞成功但网卡没建起来"的办法。

### Android 怎么装

1. 下 `qp2p-android-apk`，安装（需允许「安装未知来源」）
2. 打开 App，填三项：信令地址、加入令牌、本机名称（留空则用 node_id 前 8 位）
3. 点「连接」，第一次会弹系统 VPN 授权，同意
4. 通知栏出现 qp2p 即在线；断开点 App 里的按钮，或在系统设置里关掉 VPN

几点说明：

- **只接管虚拟网段**（例如 `10.78.0.0/16`），手机上网照旧走运营商，不做全局代理
- 令牌就是电脑上 `qp2p create` / `qp2p token` 打出的那串，和 PC 用同一个
- 内层 MTU 默认 1280（移动网络更保守），要改就改 `android/app/.../Qp2pVpnService.kt` 里的传参
- App 自己的信令流量被排除在隧道外，避免绕回自己

`qp2p` 的身份、证书、配置都在 `~/.qp2p/`（Windows 是 `C:\Users\<你>\.qp2p\`）：

| 文件 | 内容 |
|---|---|
| `identity.key` | 节点私钥（0600）。删掉就等于换了一个新节点 |
| `tls.crt` / `tls.key.der` | 自签证书，指纹用于对端钉扎 |
| `config.toml` | 信令地址、网络、加入令牌（0600，**不要分享**） |

想彻底重来：`rm -rf ~/.qp2p`，然后重新 `qp2p join`。

---

## 9. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `还没设置信令地址` | 先 `qp2p init https://<域名>` |
| `建网需要管理密钥` | 用 `qp2p init <地址> --admin <密钥>` 保存一次，或 `--admin` 临时给 |
| `ADMIN_SECRET 不对` | Cloudflare 里的变量和本机保存的不一致；重新 `qp2p init` 一次 |
| `加入密钥不正确` | 令牌被 `rotate` 换过，或网络被删了；找管理员要新的 |
| `本机还没加入任何网络` | 先 `qp2p create` 或 `qp2p join` |
| `绑定 UDP 失败` | 端口被占用（常见于开了两个实例），用 `--bind 0.0.0.0:51821` |
| `虚拟网卡创建失败` | Linux 加 sudo；Windows 用管理员终端，并确认 `wintun.dll` 在 exe 旁边 |
| `暂时连不上 xxx` | 对端没在 `qp2p up`，或对端在线但 NAT 类型太严；双方都开 up 后会自动重试 |
| ping 不通但显示"直连已建立" | 处在降级模式（没建成虚拟网卡），按上一条处理 |
| 提示"加入令牌已失效" | 管理员换过密钥；`qp2p join <新令牌>` 后重新 `qp2p up` |
| 时间相关的签名错误 | 本机时钟偏差超过 2 分钟，校准时间后重试 |

### 排查顺序

```bash
qp2p doctor            # 本地：node_id、公网映射、候选地址、UPnP
qp2p status            # 服务端视角：成员在线状态、候选数量
qp2p up --punch-only   # 不建网卡，只验证能不能打通
```

`--punch-only` 能看到「✓ 直连已建立」就说明打洞没问题，剩下的都是本机网卡权限问题。

---

## 10. 安全模型（两把密钥不要混）

| 密钥 | 谁能拿到 | 作用 | 泄漏后果 |
|---|---|---|---|
| `ADMIN_SECRET` | 只有部署者 | 建网络、换加入密钥 | 别人可以建网/换你网络的密钥 |
| 加入令牌 `qp2p1_<网络>_<密钥>` | 网络成员 | 加入网络、登记节点 | 别人能进这个网络（下次 `rotate` 即可踢掉） |

- 服务端**只存加入密钥的 sha256**，不存明文；`ADMIN_SECRET` 推不出加入密钥。
- 换 `ADMIN_SECRET` 不会让成员掉线；换加入密钥才需要大家重新 join。
- 信令服务看得到：谁在线、候选地址、虚拟地址。看不到：你的私钥、业务流量内容。
- 直连之后流量是端到端加密的（QUIC + 自签证书钉扎 + 双向签名认证）。

---

## 11. 开发者：本地跑一遍

```bash
# 1. 本地信令服务（Node 22，内置 SQLite 冒充 D1，重启即清空）
ADMIN_SECRET=dev node signal/dev-server.mjs 8787

# 2. 客户端（debug 构建）
cargo build --bin qp2p
./target/debug/qp2p init http://127.0.0.1:8787 --admin dev --data-dir /tmp/qa
./target/debug/qp2p create home --data-dir /tmp/qa

# 3. 第二个节点（另一个 data-dir 就是另一台机器）
TOKEN=$(./target/debug/qp2p token --data-dir /tmp/qa)
./target/debug/qp2p join "$TOKEN" --worker http://127.0.0.1:8787 --name bob --data-dir /tmp/qb
./target/debug/qp2p up --punch-only --bind 0.0.0.0:51822 --data-dir /tmp/qb   # 另开一个终端
./target/debug/qp2p up --punch-only --bind 0.0.0.0:51821 --data-dir /tmp/qa
```

两端都打印 `✓ 直连已建立` 就说明整条链路是通的。

```bash
cargo test --all          # Rust：单测 + e2e 打洞
node signal/smoke.mjs     # 信令：内存 + D1 两条存储路径
```
