# qp2p 使用手册

从零到多台机器互访。建网、发密钥、加入、上线全部在客户端里完成，
不需要调用任何 HTTP 接口，也不用手工交换 IP 和 node_id。

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
qp2p up                      # Windows：管理员终端
```

`qp2p create` 会打印这样一行，这就是邀请，对方复制粘贴即可：

```
    qp2p join qp2p1_home_4b96...
```

Windows 更省事：双击 `qp2p.exe` 打开图形界面，把令牌粘进去点「连接」。

---

## 1. 部署信令服务（一次性，做的人只有你）

信令服务器只做三件事：登记节点、撮合打洞、维持在线状态。**它不转发业务流量**，
带宽和额度压力都很小。

1. Cloudflare Dashboard → **Workers & Pages → Create → Worker** → Deploy
2. **Edit code** → 全选删除 → 粘贴仓库里的 `signal/worker.js` 全文 → **Deploy**
3. 建议绑定 D1（不绑也能跑，但状态只存在单个实例里）：
   **Storage → D1 → Create database** → 回到 Worker →
   **Settings → Bindings → Add → D1**，变量名必须是 **`DB`**
4. **Settings → Variables and Secrets → Add**：名字 **`ADMIN_SECRET`**，类型 **Secret**，
   值用随机串（`openssl rand -hex 32`）

### 验收

```bash
qp2p init https://<你的域名> --admin <ADMIN_SECRET>
```

期望输出：

```
✓ Worker 可达
  版本    : 2.5.0
  存储    : D1（多地域一致）
  管理密钥: 已配置
```

这些详情只对带管理密钥的请求返回；不加 `--admin` 只会看到「✓ Worker 可达」和一行提示。
根路径 `/` 返回 404，不提供任何接口清单。

| 不符合 | 处理 |
|---|---|
| 版本低于 2.3 | 重新粘贴一次 `worker.js`（2.3 才有删网、列网络、自定义 IP） |
| 存储显示「内存」 | 没绑 D1，重启 Worker 会丢网络，检查第 3 步 |
| 管理密钥「未配置」 | 还能加入别人的网络，但建不了网络，检查第 4 步 |

国内访问 `*.workers.dev` 可能不通，给 Worker 绑定自己的域名再填进来。

---

## 2. 安装客户端

从 **Releases → 最新版** 下载（每个版本都附 `SHA256SUMS.txt`）：

| 平台 | 文件 | 说明 |
|---|---|---|
| Windows 10/11 x64 | `qp2p-0.1.2-windows-x86_64.exe` | 单文件，双击打开图形界面（会弹 UAC） |
| Linux x86_64（主流发行版） | `qp2p-0.1.2-linux-x86_64` | 需要 glibc ≥ 2.39（Ubuntu 24.04 及以上） |
| Linux x86_64（老系统/容器） | `qp2p-0.1.2-linux-x86_64-static` | 静态链接，Debian 11/12、Alpine 都能跑 |
| Linux aarch64（ARM64 路由器/开发板） | `qp2p-0.1.2-linux-aarch64-static` | 静态链接，OpenWrt（`aarch64_cortex-a53` 一类）直接用 |
| Android 8+ | `qp2p-0.1.2-android.apk` | VpnService，debug 签名 |

下载后先校验：

```bash
sha256sum -c SHA256SUMS.txt
```

Linux 安装：

```bash
chmod +x qp2p-0.1.2-linux-x86_64-static
sudo mv qp2p-0.1.2-linux-x86_64-static /usr/local/bin/qp2p
qp2p -V
```

Windows 直接双击 exe：图标和 `wintun.dll` 都已内嵌，**不需要另外下载 dll**。
程序会把内嵌的 dll 解到 `%LOCALAPPDATA%\qp2p\`，系统里装过旧版 wintun 也不影响。

---

## 3. Windows 图形界面

双击 `qp2p.exe` 即可，等价于 `qp2p gui`。打开的是原生窗口，不是网页。

1. **信令地址**：`https://qp2p.321288.xyz`
2. **加入令牌**：管理员给你的 `qp2p1_...`
3. **本机名称**：默认取主机名，可改
4. **虚拟 IP**：留空由服务端分配；填了会被预留
5. 点 **连接**

**双击就会弹 UAC**：exe 清单里声明了 `requireAdministrator`，同意后整个进程都是管理员，
创建虚拟网卡不再单独提权。

> 副作用：在非管理员的命令行里敲 `qp2p` / `qp2p --help` 也会先弹 UAC，
> 输出出现在**新开**的控制台窗口里。想在原终端看日志，就先开一个管理员终端。

| 操作 | 结果 |
|---|---|
| 点右上角 × | 收进托盘，不断开连接 |
| 托盘双击 / 单击 | 还原窗口 |
| 托盘右键 | 打开界面 / 连接 / 断开 / 退出 |
| 悬停托盘图标 | 显示当前状态和直连条数 |
| 再运行一次 exe | 不会开第二个窗口，直接把已有窗口提到前面 |

「空闲断开（秒）」填 0 表示从不断开（桌面默认），手机场景可用 600。

Linux 没有图形界面，`qp2p gui` 会提示改用命令行。

---

## 4. 建网络（第一台机器）

```bash
qp2p init https://p2p.example.com --admin <ADMIN_SECRET>   # 第 1 步做过可跳过
qp2p create home
```

网络名只能用小写字母、数字和连字符。也可以自己定加入密钥：

```bash
qp2p create home --key "my-family-2026-passphrase"          # 16~128 字符
```

| 动作 | 结果 |
|---|---|
| 在服务端建网络 | 分配一个 `10.x.0.0/16` 网段，全网络共用 |
| 生成加入密钥 | 默认服务端随机生成；也可以 `--key` 自己定 |
| 保存到本机 | 写进 `~/.qp2p/config.toml`（权限 0600） |

`qp2p token` 可随时再显示令牌，`qp2p rotate` 换新的。

---

## 5. 加入（其它每一台机器）

```bash
qp2p join qp2p1_home_4b96...
```

也可以直接粘贴带令牌的链接（`https://.../?token=qp2p1_home_...`），客户端会自己拆。
加入时会立刻向服务端登记一次，成功说明令牌有效：

```
✓ 已加入 home（10.78.0.0/16）
  本机  : bob  10.78.129.223
  成员  : 1 个在线/历史节点
```

虚拟地址由服务端分配，同一网络内唯一，重启不变。

---

## 6. 上线

```bash
sudo qp2p up                    # Linux
qp2p up                         # Windows（管理员终端）
```

启动后依次做：绑定 UDP（默认 `51820`）→ STUN 探公网映射 → 登记候选地址 →
拉取成员列表并逐个打洞 → 打通的节点打印出来。

```
qp2p 0.1.2 · 网络 home
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
ping 10.78.156.207         # Windows 同一条命令
```

能 ping 通说明整条链路（信令 → 打洞 → 认证 → 虚拟网卡）都通了。
端口、SSH、文件共享都直接用这个虚拟地址，不需要再做端口映射。

### 常用参数

| 参数 | 用途 |
|---|---|
| `--name <名字>` | 成员列表里显示的名字，默认取主机名 |
| `--punch-only` | 只打洞、不建虚拟网卡；不需要 root，用来先验证能不能连通 |
| `--bind <addr>` | UDP 监听地址，端口冲突时换一个（默认 `0.0.0.0:51820`） |
| `--stun <host:port>` | 可重复，覆盖默认 STUN 服务器 |
| `--dev <名字>` | 虚拟网卡名，默认 `qp2p0` |
| `--mtu <n>` | 默认 1400；链路质量差可以降到 1280 |
| `--route <网段>` | 额外让某个网段走隧道（访问对端背后的局域网） |

> 没有 root 时**自动降级**成「只打洞」：能连上、能看日志，但 ping 不通。

---

## 7. 日常操作

| 命令 | 作用 |
|---|---|
| `qp2p status` | 本机地址 + 成员列表（在线状态、虚拟地址、候选数） |
| `qp2p token` | 再显示一次加入令牌 |
| `qp2p rotate` | 换新令牌，旧令牌立刻失效 |
| `qp2p leave` | 把本机从网络里注销 |
| `qp2p config` | 查看/修改本机配置 |
| `qp2p up -h` | 看组网的完整选项 |

管理员命令（需要 `ADMIN_SECRET`）：

| 命令 | 作用 |
|---|---|
| `qp2p nets` | 列出这台 Worker 上的所有网络 |
| `qp2p rotate --network <名字>` | 换某个网络的准入密码 |
| `qp2p rotate --network x --key <新密码>` | 自己指定新密码（16~128 字符） |
| `qp2p delete <名字> --yes` | 删除网络，**不可恢复** |

`qp2p status` 的样子：

```
网络     : home  10.78.0.0/16
本机名称 : laptop
虚拟地址 : 10.78.160.187（网段 10.78.0.0/16）

成员（1 个，不算本机）：
  名称               虚拟地址             状态      可直连地址
  bob              10.78.156.207    在线      3
```

**换密钥之后**：已运行的节点直连不会立刻断，但下次刷新注册（5 分钟内）会被拒，
需要拿新令牌重新 `qp2p join` 再 `qp2p up`。管理页上也能一键换。

---

## 8. 自定义配置

用户级配置改一次就记住，不用每次 `up` 都带参数。

### 固定自己的虚拟地址

```bash
qp2p join <令牌> --ip 10.78.0.20
qp2p config set ip 10.78.0.30    # 改已在用的地址，下次 up 生效
```

服务端会校验：必须在网络网段内、不能是网段或广播地址、不能重复。
冲突时报错并告诉你是谁占了：

```
10.78.0.20 已经被节点「nas」占用，换一个
```

**手填的地址会被预留**：节点离线甚至被清理后，这个 IP 仍归它，别人填会收到
`virtual_ip_reserved`，它自己重连则拿回原地址。要收回就在管理页「IP 预留」里释放。

### 空闲断链（省电/省流量）

```bash
qp2p up --idle 600      # 直连空闲 600 秒断开，有流量时自动重连
```

桌面端默认不断，Android 固定 10 分钟。断链后第一次 ping 有 1~3 秒重连延迟。

### 信令传输方式（省请求）

默认是轮询：每个节点每分钟问一次服务端有没有新事件，一天约 1440 次请求。
服务端是绑定 Durable Object 的部署时，可以换成 WebSocket 长连接，事件由服务端推，
一天约 260 次请求，撮合延迟也从"最多等一个轮询周期"变成即时。

```bash
qp2p up --transport ws          # 强制长连接
qp2p config set transport poll  # 只用轮询
qp2p config unset transport     # 回默认（auto）
```

三种取值：

| 值 | 行为 |
|---|---|
| `auto`（默认） | 先试长连接；120 秒内连续失败 3 次就退回轮询，之后按 5 分钟→10→20→40→60 分钟的间隔重试，连上后间隔复位。服务端哪天升级了，最多 1 小时会自动切过去 |
| `ws` | 强制长连接，连不上按 1→60 秒一直重试，**不退回轮询**（确认服务端支持时用） |
| `poll` | 完全不试长连接 |

- 旧服务端（没有 Durable Object）握手会返回 501，`auto` 模式十几秒内就会退回轮询，
  日志打一条「长连接连续失败（…），改用轮询，N 分钟后再试」。默认配置下不会有任何不适。
- 想知道服务端支不支持：`qp2p init <地址> --admin <密钥>` 会打一行
  `引擎    : room（支持 WebSocket 长连接）` / `legacy（只能用轮询）`。
- 休眠联动：进入空闲休眠满 60 秒会断开长连接（手机省电），有流量唤醒后立刻接回来。
- 长连接只承载"谁上线了、谁要连我"这类撮合消息，隧道数据不经过它。

### 其它本机配置

```bash
qp2p config                      # 看当前生效的全部配置
qp2p config set mtu 1280
qp2p config set dev qp2p1
qp2p config set stun stun.cloudflare.com:3478,stun.miwifi.com:3478
qp2p config set routes 192.168.1.0/24,192.168.2.0/24
qp2p config unset mtu            # 回到默认
```

可用项：`worker` `admin_secret` `node_name` `listen` `mtu` `dev` `stun` `routes` `transport` `ip`。
取值顺序：命令行 > 配置文件 > 默认值。想让这次的命令行选择长期生效就加 `--save`：

```bash
qp2p up --mtu 1280 --route 192.168.1.0/24 --save
```

---

## 9. 管理页面

浏览器打开 `https://你的-worker地址/admin`。

**第一次**：页面要求创建管理员账号（用户名 + 至少 8 位密码），需要填 `ADMIN_SECRET`
作为初始化密钥；**之后只用账号密码登录**，`ADMIN_SECRET` 只用于命令行和重置密码。

- 密码用 PBKDF2-HMAC-SHA256（10 万轮）加盐存储，库里没有明文
- 登录成功签发 2 小时 HttpOnly + SameSite=Strict 会话 cookie
- 忘记密码：

```bash
curl -X POST -H "x-admin-secret: $ADMIN" -H 'content-type: application/json' \
  -d '{"username":"admin","new_password":"新的密码"}' \
  https://你的-worker/v1/admin/password/reset
```

登录失败按连续次数阶梯锁定（5 次 60 秒、8 次 5 分钟、12 次 15 分钟、20 次 60 分钟），
`user:<用户名>` 全局锁定 + `ip:<ip>|<用户名>` 单来源锁定，计数存 D1，锁定期间返回 `429`。
再想加固可以套一层 Cloudflare Access，或给 `/v1/admin/login` 加 WAF 限速。

页面上能做的事：

| 功能 | 说明 |
|---|---|
| 概览 | 网络数、设备总数、在线数、预留数、离线超 10 分钟的台数 |
| 建网络 / 改网段 | 网段可空（自动挑不冲突的）；改网段后落在外面的节点会自动重分配 |
| 换加入密钥 / 删网络 | 换密钥一次点击、新令牌只显示一次；删网络要输入网络 id 确认 |
| 成员与节点详情 | 在线优先排序，含虚拟地址、NAT 标签、在线时长；展开可看 node_id、公钥、候选地址、广告路由 |
| 批量操作 | 勾选多台踢下线；成员表和预留表都能导出 CSV |
| 固定 IP / 操作审计 | 任意节点可固定 IP；审计记录操作人、动作、对象，可按类别筛选 |

命令行同样可用：

```bash
curl -X PATCH -H "x-admin-secret: $ADMIN" -H 'content-type: application/json' \
     -d '{"cidr":"10.78.0.0/16"}' https://你的-worker/v1/admin/networks/home
curl -H "x-admin-secret: $ADMIN" https://你的-worker/v1/admin/networks/home/nodes
```

---

## 10. 组网原理

- **谁连谁**：每个节点从服务端拿成员列表，`node_id` 小的一方主动发起，另一方收到撮合事件后守着，两边同时开孔
- **重试**：连不上自动退避重试（10s → 20s → 40s → 60s），直到连上
- **多对端**：一台机器同时和多节点保持独立直连，数据面按目标虚拟地址选连接，不需要多套配置
- **换网自愈**：直连全断或连续 3 次打洞失败，立刻重绑端口、重探 STUN、用新地址重新注册
- **过期地址**：服务端拒绝拿心跳超过 120 秒的地址撮合（`target_stale`），避免空打
- **身份**：每条连接建立后双方交换 Ed25519 签名并互验，签名绑定这条 TLS 会话

---

## 11. 平台说明

| 平台 | 状态 | 说明 |
|---|---|---|
| Linux | ✅ | TUN 需要 root 或 `CAP_NET_ADMIN` |
| Windows | ✅ | 需要管理员；非管理员自动降级为只打洞 |
| Android | ✅ | APK 走 VpnService，只接管虚拟网段 |

### Windows

下载 exe 直接双击，或用管理员终端：

```powershell
.\qp2p.exe init https://你的-worker.workers.dev
.\qp2p.exe join qp2p1_home_xxxxxxxx
.\qp2p.exe up
```

### Android

1. 安装 APK（需允许「安装未知来源」）
2. 打开 App，填信令地址、加入令牌、本机名称（留空用 node_id 前 8 位）
3. 点「连接」，第一次会弹系统 VPN 授权，同意
4. 通知栏出现 qp2p 即在线

- **只接管虚拟网段**（如 `10.78.0.0/16`），手机上网照旧走运营商，不做全局代理
- 令牌就是电脑上 `qp2p create` / `qp2p token` 打出的那串
- 内层 MTU 默认 1280，App 自己的信令流量被排除在隧道外

### 数据目录

`~/.qp2p/`（Windows 是 `C:\Users\<你>\.qp2p\`）：

| 文件 | 内容 |
|---|---|
| `identity.key` | 节点私钥（0600）。删掉等于换了一个新节点 |
| `tls.crt` / `tls.key.der` | 自签证书，指纹用于对端钉扎 |
| `config.toml` | 信令地址、网络、加入令牌（0600，**不要分享**） |

彻底重来：`rm -rf ~/.qp2p`，再重新 `qp2p join`。

---

## 12. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `还没设置信令地址` | 先 `qp2p init https://<域名>` |
| `建网需要管理密钥` | 用 `qp2p init <地址> --admin <密钥>` 保存一次，或 `--admin` 临时给 |
| `ADMIN_SECRET 不对` | Cloudflare 里的变量和本机保存的不一致；重新 `qp2p init` 一次 |
| `加入密钥不正确` | 令牌被 `rotate` 换过，或网络被删了；找管理员要新的 |
| `本机还没加入任何网络` | 先 `qp2p create` 或 `qp2p join` |
| `绑定 UDP 失败` | 端口被占用（常见于开了两个实例），用 `--bind 0.0.0.0:51821` |
| `虚拟网卡创建失败` | Linux 加 sudo；Windows 用管理员终端 |
| `暂时连不上 xxx` | 对端没在 `qp2p up`，或对端 NAT 太严；双方都开 up 后自动重试 |
| ping 不通但显示「直连已建立」 | 处在降级模式（没建成虚拟网卡），按上一条处理 |
| 提示「加入令牌已失效」 | 管理员换过密钥；`qp2p join <新令牌>` 后重新 `qp2p up` |
| 时间相关的签名错误 | 本机时钟偏差超过 2 分钟，校准后重试 |

### 排查顺序

```bash
qp2p doctor            # 本地：node_id、公网映射、候选地址、UPnP
qp2p status            # 服务端视角：成员在线状态、候选数量
qp2p up --punch-only   # 不建网卡，只验证能不能打通
```

能看到 `✓ 直连已建立` 就说明打洞没问题，剩下的都是本机网卡权限问题。

---

## 13. 安全模型（两把密钥不要混）

| 密钥 | 谁能拿到 | 作用 | 泄漏后果 |
|---|---|---|---|
| `ADMIN_SECRET` | 只有部署者 | 建网络、换加入密钥 | 别人可以建网/换你网络的密钥 |
| 加入令牌 `qp2p1_<网络>_<密钥>` | 网络成员 | 加入网络、登记节点 | 别人能进这个网络（`rotate` 即可踢掉） |

- 服务端**只存加入密钥的 sha256**，不存明文；`ADMIN_SECRET` 推不出加入密钥
- 换 `ADMIN_SECRET` 不会让成员掉线；换加入密钥才需要大家重新 join
- 信令服务看得到：谁在线、候选地址、虚拟地址；看不到：你的私钥、业务流量内容
- 直连之后流量端到端加密（QUIC + 自签证书钉扎 + 双向签名认证）
