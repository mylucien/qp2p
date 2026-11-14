/**
 * qp2p 信令 Worker —— 单文件版，粘贴即可部署
 * ==========================================
 *
 * 只做三件事：登记节点、撮合打洞、维持在线状态。不转发任何业务数据。
 *
 * 部署（全程在 Cloudflare Dashboard，不需要 wrangler）：
 *   1. Workers & Pages → Create → Worker → Edit code → 粘贴本文件 → Deploy
 *   2. 可选：Storage → D1 → Create database `qp2p`，然后
 *      Worker → Settings → Bindings → 添加 D1，变量名填 DB
 *      （不绑定也能跑，但状态只存在单个 isolate 里，见 /v1/health 的 storage 字段）
 *   3. Settings → Variables → 添加 ADMIN_SECRET（用于创建网络）
 *   4. 表结构在首次请求时自动建立，不需要手动执行 SQL
 *
 * 不需要 Durable Object，不需要 WebSocket，不需要构建步骤。
 */

const VERSION = "2.8.4";
const TOKEN_PREFIX = "qp2p1_";

const OFFLINE_MS = 150_000; // 超过这个时间没心跳视为离线
// 轮询节点的 last_seen 超过这个时间就算"可能刚换网"：120 秒 > 两轮 60 秒轮询。
// 长连接节点不看它——socket 活着就是地点没变的证据，用它反而会把一直挂着的
// WS 节点在两分钟后判成"地址过期"（见 matchmake 里的注释）。
const STALE_MS = 120_000;
// last_seen 最快多久写一次（省 D1 写额度）。
// 取 55 秒而不是 60：客户端空闲时 60 秒一轮询，紧贴 60 秒的话请求间隔稍有抖动
// （比如 59.9 秒）就会跳过这次写入，last_seen 的实际年龄会被拖到 ~120 秒，贴着 STALE_MS。
const HEARTBEAT_MS = 55_000;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_NODES = 256; // 每个网络的上限
const MAX_CANDIDATES = 16;
const MAX_EVENTS = 50;
const EVENT_TTL_MS = 300_000;
const NODE_TTL_MS = 600_000; // 10 分钟没心跳就删，否则僵尸节点会占满 MAX_NODES
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 240; // 每 IP 每分钟请求数，防止误用把 D1 额度打满
// 清理是 4 条全表扫描的 DELETE，每个 isolate 各跑各的。TTL 本身是 5~10 分钟，
// 清理晚几分钟不影响正确性，却能把扫描量降到五分之一。
// （不要给这些表加 created_at / last_seen 索引：每次 INSERT 会多写一行，得不偿失。）
const SWEEP_INTERVAL_MS = 300_000;
// 发给全网所有节点的广播事件用这个 node_id（真实 node_id 是 32 位十六进制，不会冲突）
const BROADCAST = "*";

// 逐条执行：D1 的 exec() 对多行语句的行为不同版本不一致，不赌它
const DDL_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS networks (
    network_id TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    cidr       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    join_hash  TEXT NOT NULL DEFAULT ''
  )`,
  // 老库补列：重复执行会报 duplicate column，下面的循环会忽略
  `ALTER TABLE networks ADD COLUMN join_hash TEXT NOT NULL DEFAULT ''`,
  // 网络行版本号：create / rotate 前进，删除则留一个"墓碑 rev"。
  // 15 秒的行缓存会跨 isolate 各存一份，只靠缓存内容判断令牌是否还有效不够——
  // 换密钥后旧令牌在另一个 isolate 里能握手成功（§6.1 的已知滞后被放大成安全漏洞）。
  // 所以把 rev 一路带到 DO，DO 只认不小于自己见过的最大值（-15 秒缓存的安全阀）。
  `ALTER TABLE networks ADD COLUMN rev INTEGER NOT NULL DEFAULT 0`,
  // 配置版本号（名字 / 网段）：**只管"要不要应用"**，不参与鉴权。
  //
  // rev 解决的是安全问题（换密钥后拒绝更旧的上下文），所以它必须只在换密钥、新建时
  // 前进——改名也前进的话，别的 isolate 手里同 rev 的旧行会立刻被判过期，改个名字
  // 等于把全网踢 15 秒。但这也意味着"rev 没变"的上下文推不动 DO 里的名字/网段，
  // 于是派生第二个计数器：改名/改网段时前进它，DO 只在它更大时才覆盖名字与网段。
  `ALTER TABLE networks ADD COLUMN cfg_rev INTEGER NOT NULL DEFAULT 0`,
  // 全局单调计数器。用全局而不是"每个网络取 MAX+1"，是为了删网后重建同一个 id
  // 也能拿到比墓碑更大的 rev，否则新网络会被自己上一次删掉的墓碑永久拒绝。
  // k = 'seq' 是 rev，k = 'cfg' 是 cfg_rev，两条序列互不影响。
  `CREATE TABLE IF NOT EXISTS net_rev (
    k TEXT PRIMARY KEY,
    v INTEGER NOT NULL
  )`,
  // 数据面（nodes / events / nonces）在 Durable Object 里，D1 不再建这三张表。
  // 升级前遗留的旧表不读不写，留着不影响任何行为，想清就自己 DROP。
  // 预留备份：DO 是权威，这张表只是它的备份（B2）。DO 首次初始化时从这里恢复，
  // 免得重新部署后管理员手填的固定 IP 全丢。
  `CREATE TABLE IF NOT EXISTS reservations (
    network_id TEXT NOT NULL,
    ip         TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'auto',
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (network_id, ip)
  )`,
  `CREATE INDEX IF NOT EXISTS reservations_by_node ON reservations (network_id, node_id)`,
  // 管理面审计：谁在什么时候改了网段、换了密钥、踢了谁
  `CREATE TABLE IF NOT EXISTS admin_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT ''
  )`,
  // 管理员账号：口令用 PBKDF2-HMAC-SHA256 存，服务端拿不到明文
  `CREATE TABLE IF NOT EXISTS admin_users (
    username   TEXT PRIMARY KEY,
    salt       TEXT NOT NULL,
    hash       TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  // 登录失败计数：放在 D1 里，不随 isolate 回收清零
  `CREATE TABLE IF NOT EXISTS login_attempts (
    key        TEXT PRIMARY KEY,
    fails      INTEGER NOT NULL,
    first_at   INTEGER NOT NULL,
    last_at    INTEGER NOT NULL,
    locked_until INTEGER NOT NULL DEFAULT 0
  )`,
  // 老库补列必须放在建表之后：新库上 ALTER 会报 no such table
  `ALTER TABLE admin_actions ADD COLUMN actor TEXT NOT NULL DEFAULT ''`,
  // 会话代次：进 cookie 的 MAC 输入。改密码 / 重置密码 / 登出时 +1，
  // 于是所有已签发的 cookie 立刻失效——原来 MAC 只绑 username+过期时间，
  // 改密码和登出都踢不掉旧 cookie（哪怕它们写的是"旧 cookie 立刻失效"）。
  `ALTER TABLE admin_users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0`,
];

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env = {}, ctx = {}) {
    const url = new URL(request.url);
    const colo = request.cf?.colo ?? "local";
    const started = Date.now();

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname !== "/v1/health" && limited(request)) {
      return err(429, "rate_limited", `每 IP 每分钟最多 ${RATE_MAX} 次请求`);
    }
    if (url.pathname === "/v1/health" && limited(request, 60)) {
      return err(429, "rate_limited", "health 每分钟最多 60 次");
    }

    let res;
    try {
      res = await route(request, url, env, ctx);
    } catch (e) {
      res = err(500, "internal_error", e instanceof Error ? e.message : String(e));
    }

    if (typeof ctx.waitUntil === "function") {
      // room 模式下 D1 只剩控制面数据，别再对旧表跑全表 DELETE
      ctx.waitUntil(sweep(env).catch(() => {}));
    }

    if (!(res instanceof Response)) {
      // 本地冒烟的 101 是替身对象（node 的 Response 不接受 101），只有它会走到这里
      if (res && res.status === 101 && res.webSocket) return res;
      // 走到这里说明某个分支忘了 return Response，直接 500 会只剩一张空白错误页
      return err(500, "bad_internal_response", `route 返回了 ${typeof res} ${String(res).slice(0, 120)}`);
    }
    // WebSocket 升级响应（101）的头是只读的，set 会抛异常，整条连接就变成空白 500
    if (res.status !== 101) {
      try {
        res.headers.set("x-qp2p-colo", colo);
        res.headers.set("x-qp2p-ms", String(Date.now() - started));
      } catch {
        // 只读头来自 DO 转发，附加信息不是必需的
      }
    }
    return res;
  },
};

async function route(request, url, env, ctx) {
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  // 诊断端点：只有显式设置 LAB_DEBUG=1 的部署才会启用，用来把 DO 的异常原样带出来
  if (path === "/__diag" && env.LAB_DEBUG === "1") {
    const netId = url.searchParams.get("net") ?? "home";
    // 用真实的网络行：拼出来的假上下文没有 rev，换过密钥后会被 DO 当成过期上下文拒绝
    const net =
      (await getNetworkFresh(env, netId)) ?? { network_id: netId, name: netId, cidr: "10.78.0.0/16" };
    const stub = roomStub(env, net);
    if (!stub) return json({ ok: false, error: "no_room" });
    try {
      const r = await stub.fetch(
        new Request("https://room/i/debug", { headers: { "x-qp2p-net": netContext(net) } }),
      );
      const text = await r.text();
      return json({ status: r.status, body: text.slice(0, 800) });
    } catch (e) {
      return json({
        threw: true,
        name: e?.name ?? null,
        message: String(e?.message ?? e).slice(0, 400),
        stack: String(e?.stack ?? "").slice(0, 600),
      });
    }
  }

  // 根路径不提供任何入口信息：外部扫描应该看不出这里跑的是什么服务。
  if (path === "/admin") return adminPage();
  if (path === "/v1/health") return health(request, env);
  if (path === "/v1/admin/status" && method === "GET") return adminStatus(request, env);
  if (path === "/v1/admin/bootstrap" && method === "POST") return adminBootstrap(request, env);
  if (path === "/v1/admin/login" && method === "POST") return adminLogin(request, env);
  if (path === "/v1/admin/logout" && method === "POST") return adminLogout(request, env);
  if (path === "/v1/admin/me" && method === "GET") return adminMe(request, env);
  if (path === "/v1/admin/password" && method === "POST") return adminPassword(request, env);
  if (path === "/v1/admin/password/reset" && method === "POST") return adminResetPassword(request, env);
  if (path === "/v1/admin/audit" && method === "GET") return auditLog(request, env, url);
  if (path === "/v1/admin/networks" && method === "GET") return listNetworks(request, env);
  if (path === "/v1/admin/networks" && method === "POST") return createNetwork(request, env);
  const rotate = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/rotate$/.exec(path);
  if (rotate && method === "POST") return rotateJoinKey(request, env, rotate[1]);
  const netPath = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})$/.exec(path);
  if (netPath && method === "DELETE") return deleteNetwork(request, env, netPath[1]);
  if (netPath && method === "PATCH") return updateNetwork(request, env, netPath[1]);
  const nodesPath = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/nodes$/.exec(path);
  if (nodesPath && method === "GET") return listNetworkNodes(request, env, nodesPath[1]);
  const kickBatch = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/nodes\/kick$/.exec(path);
  if (kickBatch && method === "POST") return kickNodes(request, env, kickBatch[1]);
  const kick = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/nodes\/([0-9a-f]{32})\/kick$/.exec(path);
  if (kick && method === "POST") return kickNode(request, env, kick[1], kick[2]);
  const resv = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/reservations$/.exec(path);
  if (resv && method === "GET") return listReservationsAdmin(request, env, resv[1]);
  if (resv && method === "POST") return reserveIp(request, env, resv[1]);
  const resvOne =
    /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/reservations\/((?:\d{1,3}\.){3}\d{1,3})$/.exec(path);
  if (resvOne && method === "DELETE") return releaseIp(request, env, resvOne[1], resvOne[2]);

  const isRead = method === "GET";
  if (path === "/v1/ws" && isRead) return wsEntry(request, env, url);
  if (path === "/v1/join" && method === "POST") return joinOrRegister(request, env, url, false);
  if (path === "/v1/register" && method === "POST") return joinOrRegister(request, env, url, true);
  if (path === "/v1/connect" && method === "POST") return connect(request, env, url);
  if (path === "/v1/leave" && method === "POST") return leave(request, env, url);
  if (path === "/v1/events" && isRead) return events(request, env, url);

  return err(404, "not_found", `${method} ${path}`);
}

// ---------------------------------------------------------------------------
// Durable Object 转发层
// ---------------------------------------------------------------------------
//
// 引擎由「Worker 有没有绑定 ROOM」决定，与具体网络无关：绑了就全部走 room，
// 没绑就走 legacy（D1 数据面）。两条路都保留，回退就是部署一份不带绑定的版本。

/** 是否走 room 引擎。退役 legacy 后这是唯一的引擎，缺少绑定就是部署错误。 */
function roomEnabled(env) {
  return Boolean(env?.ROOM);
}

/** 没绑 DO 时的统一响应：给运维看得懂的一句话，而不是内部错误码。 */
function roomUnavailable() {
  return err(
    503,
    "room_unavailable",
    "这个 Worker 没有绑定 Durable Object（ROOM）。用 qp2p-deploy up 重新部署",
  );
}

/** 取某个网络的 DO 句柄。 */
function roomStub(env, network) {
  if (!env?.ROOM || !network?.network_id) return null;
  return env.ROOM.get(env.ROOM.idFromName(network.network_id));
}

/**
 * 传给 DO 的网络上下文。**不含 join_hash**，DO 不需要也不应该拿到它。
 *
 * `rev` 是安全版本号：DO 记住见过的最大值，比它小的上下文一律拒绝。这样"另一个
 * isolate 的 15 秒旧缓存"最多让它拿到一个旧的 rev，卡在 DO 这一关，而不是靠缓存
 * 新鲜度去赌。
 *
 * `cfg_rev` 是配置版本号：改名 / 改网段时前进，DO 只在它更大时才覆盖名字与网段。
 * 它与 rev 分开是必需的——见 DDL_STATEMENTS 里的说明。
 */
function netContext(network) {
  const ctx = {
    v: 1,
    id: network.network_id,
    name: network.name,
    cidr: network.cidr,
    rev: Number(network.rev ?? 0),
    cfg_rev: Number(network.cfg_rev ?? 0),
  };
  // HTTP 头只能是 ByteString（Latin-1）。网络名允许中文（只有 id 强制 ASCII），
  // 原样塞进 JSON 会让 headers.set 抛 "Cannot convert argument to a ByteString"，
  // 表现为这个网络的所有业务请求都 500。非 ASCII 一律转成 \uXXXX，JSON 解析后
  // 仍是原文；纯 ASCII 的内容逐字节不变。
  return JSON.stringify(ctx).replace(
    /[\u007f-\uffff]/g,
    (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/**
 * 把业务请求转给 DO。
 *
 * 先做令牌鉴权（D1 是控制面权威），再剥掉客户端带来的所有 x-qp2p-* 头，
 * 附上我们自己的网络上下文——不能让客户端伪造 x-qp2p-net 去指别的网络。
 */
async function forwardToRoom(request, env, url, path) {
  const auth = await authenticate(request, env, url);
  if (!auth.ok) return auth.response;

  const stub = roomStub(env, auth.network);
  if (!stub) {
    return err(
      503,
      "room_unavailable",
      "这个 Worker 没有绑定 Durable Object（ROOM）。用 qp2p-deploy up 重新部署",
    );
  }

  const headers = new Headers(request.headers);
  for (const key of [...headers.keys()]) {
    if (key.toLowerCase().startsWith("x-qp2p-")) headers.delete(key);
  }
  headers.set("x-qp2p-net", netContext(auth.network));

  const target = new URL(request.url);
  target.pathname = path;

  const isBodyless = request.method === "GET" || request.method === "HEAD";

  let payload;
  if (!isBodyless) {
    try {
      payload = await request.arrayBuffer();
    } catch (e) {
      return err(400, "body_read_failed", `${e?.name}: ${e?.message}`.slice(0, 300));
    }
    // 手动设的 content-length 会和实际字节数对不上，交给运行时自己算
    headers.delete("content-length");
  }

  let res;
  try {
    res = await stub.fetch(
      new Request(target.toString(), { method: request.method, headers, body: payload }),
    );
  } catch (e) {
    // 503 room_unavailable 是设计约定的"DO 不可用/额度耗尽"信号：客户端按 1→60 秒
    // 退避重试，Android 也靠它区分提示。502 会被当成网关错误，语义不对。
    return err(503, "room_unavailable", `${e?.name}: ${e?.message}`.slice(0, 300));
  }

  // DO 崩了的时候平台会给一个 HTML 错误页，直接透出去调用方只会看到 500。
  // 这里把原文截一段带出来，否则线上排查等于摸黑。
  if (res.status >= 500) {
    const text = await res.text().catch(() => "");
    return err(
      503,
      "room_unavailable",
      `DO 返回 ${res.status}：${text.replace(/\s+/g, " ").slice(0, 200)}`,
    );
  }

  // 关键：stub.fetch() 拿到的 Response headers 是只读的，而入口还要加 x-qp2p-colo
  // 和 x-qp2p-ms。直接改会抛「immutable headers」，未捕获后变成平台空白 500。
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: new Headers(res.headers),
  });
}

/**
 * 构造 101 升级响应。
 *
 * 线上必须返回带 `webSocket` 的 101 Response。本地冒烟用的是 node 的 Response，
 * 它的构造器只接受 200–599，101 会抛 RangeError，于是退化成同形状的普通对象。
 * 这个分支只在本地测试里走到，真机永远走第一条。
 */
/**
 * 组装一条 WS 事件消息。
 *
 * 消息类型字段占用 `t`，而 punch_request 载荷里的 `t` 是打洞时间戳——两个语义
 * 撞名。WS 侧把**载荷**的 `t` 改名 `punch_at`，消息类型仍是 `t`；HTTP 接口里
 * 这个字段继续叫 `t`，两边只有这一处差异（设计文档 §5.3）。
 */
function wsEvent(seq, type, payload) {
  const { t: punchAt, ...rest } = payload ?? {};
  const msg = { t: "event", seq, type, ...rest };
  if (punchAt !== undefined) msg.punch_at = punchAt;
  return msg;
}

function upgradeResponse(client) {
  try {
    return new Response(null, { status: 101, webSocket: client });
  } catch {
    return { status: 101, webSocket: client, headers: new Headers() };
  }
}

/**
 * `GET /v1/ws`：WebSocket 升级入口。
 *
 * Worker 只做三件事——限流、令牌鉴权（定位到哪个网络的 DO）、把升级请求原样转给 DO。
 * 验签、去重、hello、事件补发全在 DO 里，因为只有 DO 知道节点表。
 *
 * 101 响应必须**原样返回**：它是带 `webSocket` 属性的特殊 Response，
 * 复制 headers 会把这个属性丢掉，连接就建不起来。
 */
async function wsEntry(request, env, url) {
  const upgrade = (request.headers.get("upgrade") ?? "").toLowerCase();
  if (upgrade !== "websocket") {
    return err(426, "upgrade_required", "这个端点只接受 WebSocket 升级请求");
  }
  if (!roomEnabled(env)) {
    // 501 是给客户端的降级信号：退回轮询，不要反复重试握手
    return err(
      503,
      "room_unavailable",
      "这个 Worker 没有绑定 Durable Object（ROOM）。用 qp2p-deploy up 重新部署",
    );
  }
  if (limited(request, WS_HANDSHAKE_MAX, "ws|")) {
    return err(429, "rate_limited", `握手每 IP 每分钟最多 ${WS_HANDSHAKE_MAX} 次`);
  }

  const auth = await authenticate(request, env, url);
  if (!auth.ok) return auth.response;

  const stub = roomStub(env, auth.network);
  if (!stub) {
    return err(
      503,
      "room_unavailable",
      "这个 Worker 没有绑定 Durable Object（ROOM）。用 qp2p-deploy up 重新部署",
    );
  }

  const target = new URL(request.url);
  target.pathname = "/i/ws";

  const headers = new Headers(request.headers);
  // 客户端自带的 x-qp2p-* 一律不可信；网络上下文由我们按令牌填写
  for (const key of [...headers.keys()]) {
    if (key.toLowerCase().startsWith("x-qp2p-")) headers.delete(key);
  }
  headers.set("x-qp2p-net", netContext(auth.network));

  let res;
  try {
    res = await stub.fetch(new Request(target.toString(), { method: "GET", headers }));
  } catch (e) {
    return err(503, "room_unavailable", `${e?.name}: ${e?.message}`.slice(0, 300));
  }
  return res;
}

/** 把管理面请求转给 DO 的数据面。调用方已经做过 checkAdmin。 */
async function roomAdminApi(env, net, path, { method = "GET", body } = {}) {
  const stub = roomStub(env, net);
  if (!stub) return null;
  const res = await stub.fetch(
    new Request(`https://room${path}`, {
      method,
      headers: { "x-qp2p-net": netContext(net), "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
  // DO 的 Response headers 只读，入口还要加 x-qp2p-*，复制成可写的
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: new Headers(res.headers),
  });
}

/**
 * 并发取每个网络的 /i/stats（上限 8 路）。
 *
 * 单个网络失败只是不进结果，不拖垮整个列表——管理页的计数本来就是参考值。
 */
async function roomStatsAll(env, networks) {
  const out = new Map();
  const queue = [...networks];
  const lanes = Array.from({ length: Math.min(8, queue.length) || 1 }, async () => {
    while (queue.length) {
      const net = queue.shift();
      try {
        const res = await roomAdminApi(env, net, "/i/stats");
        if (res?.ok) out.set(net.network_id, await res.json());
      } catch {
        // 忽略：这个网络的计数按 0 处理
      }
    }
  });
  await Promise.all(lanes);
  return out;
}

// ---------------------------------------------------------------------------
// 基础接口
// ---------------------------------------------------------------------------

/// 健康检查。端点本身公开（监控探活要用），但**匿名只回一个 ok**：
/// 版本、存储后端、节点数、限额都属于部署细节，只给带对管理密钥的请求。
async function health(request, env) {
  const isAdmin =
    Boolean(env.ADMIN_SECRET) &&
    timingSafeEqual(request.headers.get("x-admin-secret") ?? "", env.ADMIN_SECRET);
  if (!isAdmin) return json({ ok: true });

  const storage = await ready(env);
  const out = {
    ok: true,
    version: VERSION,
    storage,
    has_admin_secret: Boolean(env.ADMIN_SECRET),
    engine: "room",
    room_bound: roomEnabled(env),
    // 没绑 DO 等于部署不完整，能力和数据面都不可用
    features: roomEnabled(env) ? ["ws"] : [],
    colo: request.cf?.colo ?? "local",
    server_ms: Date.now(),
    limits: LIMITS,
  };

  // 节点数只在控制面里统计：节点本身在 DO 里，这里数的是网络数量级的指标，
  // 不值得为 health 逐个网络去问 DO（那是 N 次唤醒）。
  const now = Date.now();
  if (!healthCache.at || now - healthCache.at > 60_000) {
    try {
      const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM networks").first();
      healthCache = { at: now, nodes: Number(row?.n ?? 0) };
    } catch {
      healthCache = { at: now, nodes: null };
    }
  }
  out.networks = healthCache.nodes;
  if (healthCache.nodes === null) {
    out.ok = false;
    out.error = "schema_not_ready";
  }
  if (!roomEnabled(env)) {
    out.warning = "没有绑定 Durable Object（ROOM），数据面不可用";
  }

  return json(out);
}

async function createNetwork(request, env) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const name = String(body.name ?? "").trim().slice(0, 48);
  const id = slug(name) || randomId();
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(id)) {
    return err(400, "invalid_name", "网络名只能包含字母、数字、连字符");
  }

  // 加入密钥（预设密钥）：管理员自己定；不填就生成一把随机的。
  // 它跟 ADMIN_SECRET 没有任何推导关系——ADMIN_SECRET 只管管理面，
  // 泄漏一把加入密钥不会连累管理面，换 ADMIN_SECRET 也不会把成员踢下线。
  const preset = body.join_key === undefined ? null : String(body.join_key);
  if (preset !== null) {
    const bad = validateJoinKey(preset);
    if (bad) return bad;
  }

  const existing = await getNetwork(env, id);
  if (existing) {
    // 带同一把预设密钥重复建网是幂等的（方便把命令存进脚本）
    if (preset !== null && existing.join_hash && timingSafeEqual(await sha256Hex(preset), existing.join_hash)) {
      return json({
        ok: true,
        network: { id: existing.network_id, name: existing.name, cidr: existing.cidr },
        token: tokenOf(id, preset),
        note: "网络已存在，预设密钥与现有的一致",
      });
    }
    return err(
      409,
      "network_exists",
      "网络已存在。要换加入密钥请 POST /v1/admin/networks/<id>/rotate（会自动生成新密钥）",
    );
  }

  const cidr = body.cidr ? normalizeCidr(String(body.cidr)) : await pickCidr(env, id);
  if (!cidr) return err(400, "invalid_cidr", "只接受 10.x.0.0/16 形式");

  const joinKey = preset ?? randomSecret();
  const net = {
    network_id: id,
    name: name || id,
    cidr,
    created_at: Date.now(),
    join_hash: await sha256Hex(joinKey),
  };
  await putNetwork(env, net);

  return json({
    ok: true,
    network: { id, name: net.name, cidr },
    token: tokenOf(id, joinKey),
    note: preset
      ? "这是你预设的加入密钥，请分发给要加入的节点"
      : "这是随机生成的加入密钥，只回显这一次；丢了用 rotate 换一把",
    ...(preset && joinKeyLooksWeak(joinKey)
      ? { warning: "这把预设密钥看起来容易被猜：服务端只存它的哈希，一旦数据库泄漏就能离线爆破。建议省略 join_key，让服务端生成随机的" }
      : {}),
  });
}

/** 换掉某个网络的加入密钥，返回新令牌。旧令牌立刻失效。 */
async function rotateJoinKey(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const body = (await readJson(request)) ?? {};
  const preset = body.join_key === undefined ? null : String(body.join_key);
  if (preset !== null) {
    const bad = validateJoinKey(preset);
    if (bad) return bad;
  }

  const joinKey = preset ?? randomSecret();
  net.join_hash = await sha256Hex(joinKey);
  // D1 先落库：新令牌是这次操作的唯一交付物，写失败必须整体失败，不能出现
  // "DO 已经踢人、D1 还是旧密钥"的中间态。
  await putNetwork(env, net);

  // room 引擎：把新上下文推进 DO，并让它在同一事务里关掉所有旧连接（4401）。
  // 旧令牌已失效，那些 socket 已经没有继续撮合的资格。
  //
  // 这一步失败**不能**把整个请求变成 500：此时 D1 里的密钥已经换了，新令牌只在这个
  // 响应里出现，返回 500 等于"旧令牌全废、新令牌没人知道"。所以降级成 200 + kicked:false，
  // 把新令牌交出去，并说明数据面没收到通知。
  //
  // 之后也不会有窗口期：下一个带新 rev 的请求到达 DO 时，loadNet 会把 maxRev 抬上去，
  // 拿着 15 秒旧缓存的 isolate 送来的旧 rev 就会被拒（stale_net_rev）。
  let kicked = false;
  let notifyError = "";
  const hasRoom = roomEnabled(env);
  if (hasRoom) {
    const payload = { net: JSON.parse(netContext(net)), close: true };
    for (let attempt = 0; attempt < 2 && !kicked; attempt += 1) {
      try {
        const res = await roomAdminApi(env, net, "/i/net-updated", { method: "POST", body: payload });
        const data = res?.ok ? await res.json().catch(() => null) : null;
        kicked = Boolean(data?.ok);
        if (!kicked) notifyError = `DO 返回 ${res?.status ?? "无响应"}`;
      } catch (e) {
        notifyError = `${e?.name ?? "Error"}: ${e?.message ?? e}`.slice(0, 120);
      }
    }
  }

  // 两条提醒可能同时成立（DO 没确认 + 预设密钥太弱），拼在一起，别互相覆盖
  const warnings = [];
  if (!hasRoom) {
    warnings.push("这个 Worker 没有绑定数据面（ROOM），部署不完整，节点连不上");
  } else if (!kicked) {
    warnings.push(`数据面未确认：${notifyError || "未知原因"}`);
  }
  if (preset && joinKeyLooksWeak(joinKey)) {
    warnings.push("这把预设密钥看起来容易被猜，建议省略 join_key 让服务端生成随机密钥");
  }

  return json({
    ok: true,
    network: { id: net.network_id, name: net.name, cidr: net.cidr },
    token: tokenOf(net.network_id, joinKey),
    kicked,
    note:
      hasRoom && !kicked
        ? "新令牌已生效（旧令牌在服务端已作废），但没能通知数据面断开现有连接：旧连接会在下次重连时被拒绝，必要时再执行一次 rotate"
        : "该网络原有令牌已失效，节点需要重新 join",
    ...(warnings.length ? { warning: warnings.join("；") } : {}),
  });
}

/** 列出所有网络（管理面）：用于管理员决定要不要删、要不要换密钥。 */
async function listNetworks(request, env) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const networks = await allNetworks(env);
  const counts = await nodeCounts(env);
  const online = await onlineCounts(env);
  const reserved = await reservationCounts(env);
  return json({
    ok: true,
    networks: networks.map((n) => ({
      id: n.network_id,
      name: n.name,
      cidr: n.cidr,
      created_at: n.created_at,
      nodes: counts[n.network_id] ?? 0,
      online: online[n.network_id] ?? 0,
      reservations: reserved[n.network_id] ?? 0,
      has_join_key: Boolean(n.join_hash),
    })),
  });
}

/**
 * 删除网络。
 *
 * 必须带 `confirm` 且与网络 id 完全一致：这是不可撤销操作，
 * 加一道"你得说出名字"的门槛，避免脚本里一个手滑把整个网络清掉。
 */
async function deleteNetwork(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const body = (await readJson(request)) ?? {};
  if (String(body.confirm ?? "") !== networkId) {
    return err(
      400,
      "confirm_required",
      `删除网络不可撤销。请在请求体里带 {"confirm": "${networkId}"} 确认`,
    );
  }

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  // 先让 DO 把节点/事件/预留清掉，再删控制面那一行：反过来的话，
  // 中途失败会留下一个"没有登记记录但 DO 还在跑"的孤儿网络。
  const res = await roomAdminApi(env, net, "/i/purge", { method: "POST", body: {} });
  if (!res) return roomUnavailable();
  const data = await res.json().catch(() => null);
  if (!data?.ok) return err(502, "room_bad_response", "DO 清理失败，网络没有删除");
  const removed = data.removed ?? 0;

  // 第二步失败会留下"中间态"：DO 已经写下墓碑并清空，D1 里还留着这一行（rev 与墓碑
  // 相同），此后所有请求都会被 403 network_deleted。再删一次能收尾，所以这里重试一次，
  // 仍然失败就把话说明白——不要让管理员看到一句笼统的 500 去猜。
  let deleted = false;
  let deleteError = "";
  for (let attempt = 0; attempt < 2 && !deleted; attempt += 1) {
    try {
      await deleteNetworkRow(env, networkId);
      deleted = true;
    } catch (e) {
      deleteError = `${e?.name ?? "Error"}: ${e?.message ?? e}`.slice(0, 160);
    }
  }
  if (!deleted) {
    return err(
      500,
      "delete_record_failed",
      `数据面已清理，但删除网络记录失败（${deleteError}）。这个网络现在对所有节点不可用，请再执行一次删除收尾`,
    );
  }

  await audit(env, "network.delete", networkId, `清理 ${removed} 个节点`, await adminActor(request, env));
  console.warn(`[signal] 删除网络 ${networkId}，清理 ${removed} 个节点`);

  return json({ ok: true, network: { id: networkId, name: net.name }, removed_nodes: removed });
}

/**
 * 改网络：名字 / 网段。改网段会把落在新网段外的节点重新分配地址。
 *
 * 两件容易做错的事，都在这里处理：
 *
 * 1. **D1 与 DO 的一致性**：D1 先落库，再用 `/i/net-updated` 通知 DO。通知失败时
 *    D1 已经是新值，管理员重试时 `changes.length === 0`——所以下面即使没有字段变更
 *    也照样推一次上下文（幂等重推），否则 DO 会永久停在旧网段，新节点被分到旧网段
 *    的地址。真正的"只在新时才应用"由 DO 用 cfg_rev 判定，见 NetworkRoom.loadNet。
 * 2. **失败不能变成 500**：D1 已改，返回 500 会让管理员以为没生效，而管理页读的正是
 *    D1（显示新值）。所以降级成 200 + synced:false + warning，重试即可自愈。
 */
async function updateNetwork(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const changes = [];
  let cfgChanged = false;
  if (body.name !== undefined) {
    const name = String(body.name).trim().slice(0, 48);
    if (!name) return err(400, "invalid_name", "网络名不能为空");
    if (name !== net.name) {
      changes.push(`名字 ${net.name} → ${name}`);
      cfgChanged = true;
    }
    net.name = name;
  }
  if (body.cidr !== undefined) {
    const cidr = normalizeCidr(String(body.cidr));
    if (!cidr) return err(400, "invalid_cidr", "只接受 10.x.0.0/16 形式");
    if (cidr !== net.cidr) {
      // 两个网络用同一网段，同一台机器接入时会路由打架，直接拒绝
      const clash = (await allNetworks(env)).find(
        (n) => n.network_id !== networkId && n.cidr === cidr,
      );
      if (clash) return err(409, "cidr_in_use", `${cidr} 已被网络「${clash.name}」使用`);
      changes.push(`网段 ${net.cidr} → ${cidr}`);
      cfgChanged = true;
    }
    net.cidr = cidr;
  }

  // 改名 / 改网段前进 cfg_rev，**不动 rev**：rev 一动，别的 isolate 手里同 rev 的旧行
  // 就会被判过期，改个名字等于把全网踢 15 秒。
  if (cfgChanged) await putNetwork(env, net, { bump: false, cfg: true });

  // 节点在 DO 里：改名/改网段要推过去，改网段时由 DO 负责重新分配地址。
  // 没有字段变更也推（幂等重推）：上一次通知失败时，管理员重试就是靠这一次收尾。
  const hasRoom = roomEnabled(env);
  let synced = false;
  let notifyError = "";
  let reassigned = 0;
  if (hasRoom) {
    const payload = { net: JSON.parse(netContext(net)), reassign: body.cidr !== undefined };
    for (let attempt = 0; attempt < 2 && !synced; attempt += 1) {
      try {
        const res = await roomAdminApi(env, net, "/i/net-updated", { method: "POST", body: payload });
        const data = res?.ok ? await res.json().catch(() => null) : null;
        synced = Boolean(data?.ok);
        if (synced) reassigned = Number(data?.reassigned ?? 0);
        else notifyError = `DO 返回 ${res?.status ?? "无响应"}`;
      } catch (e) {
        notifyError = `${e?.name ?? "Error"}: ${e?.message ?? e}`.slice(0, 120);
      }
    }
  } else {
    notifyError = "这个 Worker 没有绑定数据面（ROOM）";
  }

  if (changes.length) {
    await audit(
      env,
      "network.update",
      networkId,
      `${changes.join("；")}${reassigned ? `；重分配 ${reassigned} 个节点` : ""}${
        synced ? "" : `；数据面未确认：${notifyError}`
      }`,
      await adminActor(request, env),
    );
  }

  const warnings = [];
  if (!synced) {
    warnings.push(
      `数据面未确认（${notifyError || "未知原因"}）：控制面已是新配置${
        changes.length ? "" : "（这次没有字段变更，此次为重新下发）"
      }，节点可能仍按旧配置分配地址；再执行一次同样的修改即可重推`,
    );
  }

  return json({
    ok: true,
    changed: changes.length > 0,
    synced,
    network: { id: net.network_id, name: net.name, cidr: net.cidr },
    reassigned,
    ...(warnings.length ? { warning: warnings.join("；") } : {}),
  });
}

async function listNetworkNodes(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const res = await roomAdminApi(env, net, "/i/admin/nodes");
  if (!res) return roomUnavailable();
  return res;
}

/** 踢一个节点下线：删记录 + 清它的事件，定向预留保留。 */
async function kickNode(request, env, networkId, nodeId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const res = await roomAdminApi(env, net, "/i/admin/kick", {
    method: "POST",
    body: { node_ids: [nodeId] },
  });
  if (!res) return roomUnavailable();
  const data = await res.json().catch(() => null);
  if (!data) return err(502, "room_bad_response", "DO 没有返回可用结果");
  if (!data.ok) return json(data, res.status);
  if (!data.removed) return err(404, "node_not_found", `没有节点 ${nodeId}`);

  const hit = data.kicked[0];
  await audit(env, "node.kick", `${networkId}/${nodeId}`, hit.name, await adminActor(request, env));
  console.warn(`[room] 管理员踢下线 ${hit.name} (${nodeId})`);
  return json({ ok: true, node: { node_id: hit.node_id, name: hit.name } });
}

/** 批量踢下线：一次请求清掉多个节点，排查时比一个个点省事。 */
async function kickNodes(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const body = (await readJson(request)) ?? {};
  const res = await roomAdminApi(env, net, "/i/admin/kick", {
    method: "POST",
    body: { node_ids: body.node_ids },
  });
  if (!res) return roomUnavailable();
  const data = await res.json().catch(() => null);
  if (!data) return err(502, "room_bad_response", "DO 没有返回可用结果");
  if (!data.ok) return json(data, res.status);

  await audit(
    env,
    "node.kick_batch",
    networkId,
    `清理 ${data.removed} 个节点`,
    await adminActor(request, env),
  );
  console.warn(`[room] 管理员批量踢下线 ${data.removed} 个节点（${networkId}）`);
  return json({ ok: true, removed: data.removed });
}

/** 管理员手动预留一个 IP（可以给还没上线的节点预占）。 */
async function reserveIp(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);
  if (!roomStub(env, net)) return roomUnavailable();

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const res = await roomAdminApi(env, net, "/i/admin/reserve", { method: "POST", body });
  if (!res) return roomUnavailable();
  const data = await res.json().catch(() => null);
  if (!data) return err(502, "room_bad_response", "DO 没有返回可用结果");
  if (!data.ok) return json(data, res.status);

  await audit(
    env,
    "reservation.put",
    `${networkId}/${data.reservation.ip}`,
    data.reservation.node_id || "(未绑定节点)",
    await adminActor(request, env),
  );
  return json(data);
}

async function releaseIp(request, env, networkId, ip) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const res = await roomAdminApi(env, net, "/i/admin/release", { method: "POST", body: { ip } });
  if (!res) return roomUnavailable();
  const data = await res.json().catch(() => null);
  if (!data) return err(502, "room_bad_response", "DO 没有返回可用结果");
  if (!data.ok) return json(data, res.status);

  await audit(env, "reservation.delete", `${networkId}/${ip}`, "", await adminActor(request, env));
  return json({ ok: true, released: ip });
}

async function listReservationsAdmin(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetworkFresh(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const res = await roomAdminApi(env, net, "/i/admin/reservations");
  if (!res) return roomUnavailable();
  return res;
}

/** 管理台只认这几种动作前缀，避免把任意 LIKE 通配符带进 SQL。 */
const AUDIT_KINDS = ["network.", "node.", "reservation.", "login.", "admin."];

function auditInt(value, fallback, min, max) {
  const n = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

async function auditLog(request, env, url) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;
  const p = url.searchParams;
  // 旧调用（?limit=50）保持原样：只回最近 N 条，不带分页字段
  const paging = p.has("page") || p.has("page_size") || p.has("kind") || p.has("q");
  if (!paging) {
    const limit = Number(p.get("limit") ?? 100) || 100;
    return json({ ok: true, actions: await listAudit(env, limit) });
  }
  const pageSize = auditInt(p.get("page_size") ?? p.get("limit"), 20, 1, 100);
  const page = auditInt(p.get("page"), 1, 1, 100_000);
  const kind = AUDIT_KINDS.includes(p.get("kind")) ? p.get("kind") : "";
  const q = (p.get("q") ?? "").trim().slice(0, 100);
  return json(await listAuditPage(env, { page, pageSize, kind, q }));
}

async function allNetworks(env) {
  const { results } = await env.DB.prepare("SELECT * FROM networks").all();
  return results ?? [];
}

/** 每网络节点数 / 在线数 / 预留数：一次问全部 DO，管理页列表用。 */
async function statsByNetwork(env) {
  return roomStatsAll(env, await allNetworks(env));
}

async function nodeCounts(env) {
  const out = {};
  for (const [id, s] of await statsByNetwork(env)) out[id] = s.nodes ?? 0;
  return out;
}

async function onlineCounts(env) {
  const out = {};
  for (const [id, s] of await statsByNetwork(env)) out[id] = s.online ?? 0;
  return out;
}

async function reservationCounts(env) {
  const out = {};
  for (const [id, s] of await statsByNetwork(env)) out[id] = s.reservations ?? 0;
  return out;
}

/**
 * 删掉网络的控制面记录。
 *
 * 数据面（节点、事件、预留）在 DO 里，由 `/i/purge` 清；D1 这边只剩这一行。
 * 升级前遗留的旧表（nodes/events/nonces）不再读写，留着不影响任何行为。
 */
async function deleteNetworkRow(env, networkId) {
  // 先失效：删除前后各清一次，避免并发请求把即将/刚被删掉的行读回缓存
  invalidateNetwork(env, networkId);
  await env.DB.prepare("DELETE FROM networks WHERE network_id = ?").bind(networkId).run();
  // 预留备份也要一起删：否则同名网络重建时（例如测试里反复用 "home"）会把上一条
  // 网络的手填 IP 当成"历史预留"恢复出来，表现为"这个地址已被另一个节点预留"。
  await env.DB.prepare("DELETE FROM reservations WHERE network_id = ?").bind(networkId).run();
  invalidateNetwork(env, networkId);
}

async function checkAdmin(request, env) {
  if (!env.ADMIN_SECRET) {
    return err(
      503,
      "admin_secret_unset",
      "请在 Settings → Variables 添加 ADMIN_SECRET，然后重新部署",
    );
  }
  const provided = request.headers.get("x-admin-secret") ?? "";
  if (timingSafeEqual(provided, env.ADMIN_SECRET)) return null;

  // 管理页面用账号会话：口令只在登录时提交一次，之后靠 HttpOnly cookie。
  if (await adminSession(request, env)) return null;
  return err(401, "unauthorized", "需要 X-Admin-Secret（命令行），或先在 /admin 登录");
}

const ADMIN_COOKIE = "qp2p_admin";
const ADMIN_SESSION_MS = 2 * 60 * 60 * 1000; // 2 小时
// Cloudflare 的 WebCrypto 对 PBKDF2 有硬上限：iterations ≤ 100000，
// 超了会直接抛 "iteration counts above 100000 are not supported"。
// 迭代轮数按用户存库，将来调整只影响新账号。
const PBKDF2_ITERATIONS = 100_000;

/**
 * 允许用环境变量调低轮数。
 *
 * 免费档 CPU 上限只有 10ms/请求，如果登录时报 1102（超出 CPU），
 * 在 Settings → Variables 里加 PBKDF2_ITERATIONS=2000 即可；付费档可以不管。
 */
function pbkdf2Iterations(env) {
  const raw = Number(env?.PBKDF2_ITERATIONS ?? PBKDF2_ITERATIONS);
  if (!Number.isFinite(raw) || raw <= 0) return PBKDF2_ITERATIONS;
  return Math.max(1_000, Math.min(100_000, Math.floor(raw)));
}
const USERNAME_RE = /^[a-z0-9][a-z0-9_-]{2,31}$/;
const PASSWORD_MIN = 8;

/** PBKDF2-HMAC-SHA256。口令永远不以明文或可逆形式落库。 */
async function pbkdf2Hex(password, saltHex, iterations) {
  try {
    return await pbkdf2HexInner(password, saltHex, iterations);
  } catch (e) {
    const text = String(e?.message ?? e);
    throw new Error(
      /iteration/i.test(text)
        ? `口令哈希失败：迭代次数 ${iterations} 超出运行时限制（Workers 上限 100000）`
        : `口令哈希失败：${text}`,
    );
  }
}

async function pbkdf2HexInner(password, saltHex, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBytes(saltHex), iterations, hash: "SHA-256" },
    key,
    256,
  );
  return hex(new Uint8Array(bits));
}

async function getAdminUser(env, username) {
  await ready(env);
  return env.DB.prepare("SELECT * FROM admin_users WHERE username = ?").bind(username).first();
}

async function listAdminUsers(env) {
  await ready(env);
  const { results } = await env.DB.prepare("SELECT username FROM admin_users").all();
  return results ?? [];
}

async function putAdminUser(env, user) {
  await ready(env);
  await env.DB.prepare(
    `INSERT INTO admin_users (username, salt, hash, iterations, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(username) DO UPDATE SET
       salt = excluded.salt,
       hash = excluded.hash,
       iterations = excluded.iterations,
       updated_at = excluded.updated_at`,
  )
    .bind(user.username, user.salt, user.hash, user.iterations, user.created_at, user.updated_at)
    .run();
}

function validateAccount(username, password) {
  if (!USERNAME_RE.test(username)) {
    return err(400, "invalid_username", "用户名 3~32 位，只能用小写字母、数字、下划线、连字符");
  }
  if (String(password).length < PASSWORD_MIN) {
    return err(400, "weak_password", `密码至少 ${PASSWORD_MIN} 位`);
  }
  return null;
}

/**
 * 签发会话 cookie。
 *
 * 签名输入含 `epoch`（账号行里的 `session_epoch`）：改密码、重置密码、登出都会让它
 * +1，于是**所有**已签发的 cookie 立刻失效。原先只绑 `username` + 过期时间，
 * 那两类动作都踢不掉旧 cookie，而注释写的是"账号被删/改过，旧 cookie 立刻失效"——
 * 实际只有"删"生效。
 */
async function adminCookieFor(env, username, expiresAt, epoch) {
  const mac = await hmacHex(env.ADMIN_SECRET, `admin:${username}:${epoch}:${expiresAt}`);
  return `${expiresAt}.${username}.${epoch}.${mac.slice(0, 32)}`;
}

/**
 * 解析 cookie 里的会话：签名对、没过期、账号还在、代次没变，四者都满足才算数。
 *
 * 顺序上**先查库再验签**（原来相反）：MAC 里要拼库中当前的 `session_epoch`。
 * 这次查询本来就在（原来用于判断"账号是否还在"），没有多出一次 D1 读。
 */
async function adminSession(request, env) {
  if (!env.ADMIN_SECRET) return null;
  const raw = cookieValue(request, ADMIN_COOKIE);
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 4) return null;
  const [expText, username, epochText, mac] = parts;
  const expiresAt = Number(expText);
  const epoch = Number(epochText);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return null;
  if (!Number.isInteger(epoch) || epoch < 0) return null;
  if (!USERNAME_RE.test(username)) return null;

  const user = await getAdminUser(env, username);
  if (!user) return null;
  const current = Number(user.session_epoch ?? 0);
  const expect = await hmacHex(env.ADMIN_SECRET, `admin:${username}:${current}:${expiresAt}`);
  if (!timingSafeEqual(mac, expect.slice(0, 32))) return null;
  // 代次落后 = 改过密码或登出过。MAC 已经覆盖了 current，这里显式比一次，
  // 让"为什么失效"不必依赖读者记住签名输入里有什么。
  if (epoch !== current) return null;
  return { username, epoch: current };
}

/**
 * 会话代次 +1：让该账号所有已签发的 cookie 立刻失效。
 *
 * 按账号而不是按设备——单管理员场景下这是想要的（"一键踢掉我在所有浏览器上的登录"），
 * 多设备同时用同一账号时 A 设备登出会把 B 也踢下线，需要重登。
 */
async function bumpSessionEpoch(env, username) {
  await ready(env);
  await env.DB.prepare(
    "UPDATE admin_users SET session_epoch = session_epoch + 1 WHERE username = ?",
  )
    .bind(username)
    .run();
  const row = await env.DB.prepare("SELECT session_epoch FROM admin_users WHERE username = ?")
    .bind(username)
    .first();
  return Number(row?.session_epoch ?? 0);
}

function cookieValue(request, name) {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

function sessionCookie(request, value, maxAgeSeconds) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${ADMIN_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${secure}`;
}

function loginResponse(request, env, username, epoch) {
  return adminCookieFor(env, username, Date.now() + ADMIN_SESSION_MS, epoch).then(
    (value) =>
      new Response(JSON.stringify({ ok: true, username }), {
        status: 200,
        headers: {
          ...JSON_HEADERS,
          "set-cookie": sessionCookie(request, value, ADMIN_SESSION_MS / 1000),
        },
      }),
  );
}

/** 谁在操作：命令行带 X-Admin-Secret 记为 cli，页面里记用户名。 */
async function adminActor(request, env) {
  if (timingSafeEqual(request.headers.get("x-admin-secret") ?? "", env.ADMIN_SECRET ?? "")) {
    return "cli";
  }
  const session = await adminSession(request, env);
  return session ? session.username : "unknown";
}

/** 首次初始化状态：页面据此决定显示"创建管理员"还是"登录"。 */
async function adminStatus(request, env) {
  const users = await listAdminUsers(env);
  return json({
    ok: true,
    needs_bootstrap: users.length === 0,
    has_admin_secret: Boolean(env.ADMIN_SECRET),
  });
}

/** 第一次设账号：唯一需要 ADMIN_SECRET 的一步，之后只用账号密码。 */
async function adminBootstrap(request, env) {
  if (!env.ADMIN_SECRET) {
    return err(503, "admin_secret_unset", "先在 Cloudflare 里设置 ADMIN_SECRET，再来初始化账号");
  }
  if ((await listAdminUsers(env)).length > 0) {
    return err(409, "already_initialized", "管理员账号已存在，直接登录即可");
  }
  const body = (await readJson(request)) ?? {};
  if (!timingSafeEqual(String(body.secret ?? ""), env.ADMIN_SECRET)) {
    return err(401, "invalid_admin_secret", "初始化密钥不对");
  }
  const username = String(body.username ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const bad = validateAccount(username, password);
  if (bad) return bad;

  const salt = randomSecret();
  const now = Date.now();
  const iterations = pbkdf2Iterations(env);
  await putAdminUser(env, {
    username,
    salt,
    hash: await pbkdf2Hex(password, salt, iterations),
    iterations,
    created_at: now,
    updated_at: now,
  });
  await audit(env, "admin.bootstrap", username, "首次初始化", username);
  // 新账号代次是 0（建表默认值），不需要额外读一次
  return loginResponse(request, env, username, 0);
}

// 登录爆破防护：内存挡一层（isolate 内），D1 挡一层（跨 isolate、跨实例）。
//
// 策略按"连续失败次数"阶梯锁定，键有两个维度：
//   - user:<用户名>   全局锁定，防换 IP 继续爆破同一个账号
//   - ip:<ip>|<用户名>  单来源锁定，防同一台机器换账号扫
const LOGIN_WINDOW_MS = 60 * 60_000; // 1 小时没再失败就重新计数
const loginFails = new Map();

function lockSecondsFor(fails) {
  if (fails >= 20) return 3600;
  if (fails >= 12) return 900;
  if (fails >= 8) return 300;
  if (fails >= 5) return 60;
  return 0;
}

async function getAttempt(env, key) {
  await ready(env);
  return env.DB.prepare("SELECT * FROM login_attempts WHERE key = ?").bind(key).first();
}

async function putAttempt(env, row) {
  await ready(env);
  await env.DB.prepare(
    `INSERT INTO login_attempts (key, fails, first_at, last_at, locked_until)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET
       fails = excluded.fails,
       first_at = excluded.first_at,
       last_at = excluded.last_at,
       locked_until = excluded.locked_until`,
  )
    .bind(row.key, row.fails, row.first_at, row.last_at, row.locked_until)
    .run();
}

async function clearAttempt(env, key) {
  await ready(env);
  await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind(key).run();
}

/** 距离解锁还有多少秒；0 表示没锁。 */
async function lockedFor(env, username, ip) {
  const now = Date.now();
  for (const key of [`user:${username}`, `ip:${ip}|${username}`]) {
    const row = await getAttempt(env, key);
    if (!row) continue;
    if (Number(row.locked_until) > now) {
      return Math.ceil((Number(row.locked_until) - now) / 1000);
    }
  }
  return 0;
}

async function noteFailure(env, username, ip) {
  const now = Date.now();
  let longest = 0;
  for (const key of [`user:${username}`, `ip:${ip}|${username}`]) {
    const row = await getAttempt(env, key);
    const fresh =
      !row || now - Number(row.last_at) > LOGIN_WINDOW_MS
        ? { key, fails: 0, first_at: now, last_at: now, locked_until: 0 }
        : { ...row };
    fresh.fails = Number(fresh.fails) + 1;
    fresh.last_at = now;
    const lock = lockSecondsFor(fresh.fails);
    fresh.locked_until = lock > 0 ? now + lock * 1000 : 0;
    if (lock > longest) longest = lock;
    await putAttempt(env, fresh);
  }
  // 内存里再记一份，下一轮同 isolate 的请求不用查 D1 就能挡住
  const slot = loginFails.get(`${ip}|${username}`);
  if (!slot || now - slot.start > LOGIN_WINDOW_MS) {
    if (loginFails.size > 2048) loginFails.clear();
    loginFails.set(`${ip}|${username}`, { start: now, count: 1 });
  } else {
    slot.count += 1;
  }
  return longest;
}

async function clearFailures(env, username, ip) {
  loginFails.delete(`${ip}|${username}`);
  await clearAttempt(env, `user:${username}`);
  await clearAttempt(env, `ip:${ip}|${username}`);
}

async function adminLogin(request, env) {
  const body = (await readJson(request)) ?? {};
  const username = String(body.username ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const ip = request.headers.get("cf-connecting-ip") ?? "local";

  if (!username || !password) return err(400, "missing_credentials", "填用户名和密码");

  const wait = await lockedFor(env, username, ip);
  if (wait > 0) {
    const res = err(429, "too_many_attempts", `尝试过于频繁，请 ${wait} 秒后再试`);
    res.headers.set("retry-after", String(wait));
    return res;
  }

  const user = await getAdminUser(env, username);
  // 账号不存在时也算一次哈希，避免从响应时间上看出账号是否存在
  const salt = user?.salt ?? "00".repeat(24);
  const iterations = Number(user?.iterations ?? PBKDF2_ITERATIONS);
  const hash = await pbkdf2Hex(password, salt, iterations);
  const ok = Boolean(user) && timingSafeEqual(hash, user.hash);
  if (!ok) {
    const lock = await noteFailure(env, username, ip);
    await audit(env, "login.failed", username, ip, lock > 0 ? `已锁定 ${lock} 秒` : "");
    if (lock > 0) {
      const res = err(429, "too_many_attempts", `失败次数过多，锁定 ${lock} 秒`);
      res.headers.set("retry-after", String(lock));
      return res;
    }
    return err(401, "bad_credentials", "用户名或密码不对");
  }

  await clearFailures(env, username, ip);
  await audit(env, "login.ok", username, "", username);
  return loginResponse(request, env, username, Number(user.session_epoch ?? 0));
}

/** 改自己的密码：必须验证旧密码。 */
async function adminPassword(request, env) {
  const session = await adminSession(request, env);
  if (!session) return err(401, "not_logged_in", "先登录");
  const body = (await readJson(request)) ?? {};
  const user = await getAdminUser(env, session.username);
  if (!user) return err(401, "not_logged_in", "账号不存在");

  const oldHash = await pbkdf2Hex(
    String(body.old_password ?? ""),
    user.salt,
    Number(user.iterations),
  );
  if (!timingSafeEqual(oldHash, user.hash)) {
    await audit(env, "admin.password_failed", session.username, "");
    return err(403, "wrong_password", "旧密码不对");
  }
  const next = String(body.new_password ?? "");
  if (next.length < PASSWORD_MIN) return err(400, "weak_password", `密码至少 ${PASSWORD_MIN} 位`);

  const salt = randomSecret();
  const iterations = pbkdf2Iterations(env);
  await putAdminUser(env, {
    username: session.username,
    salt,
    hash: await pbkdf2Hex(next, salt, iterations),
    iterations,
    created_at: Number(user.created_at),
    updated_at: Date.now(),
  });
  await audit(env, "admin.password", session.username, "", session.username);
  // 代次 +1：所有已签发的 cookie（包括可能已经被偷走的那份）立刻作废；
  // 同时给当前浏览器发一张新代次的，避免改完密码把自己弹回登录页。
  const epoch = await bumpSessionEpoch(env, session.username);
  return loginResponse(request, env, session.username, epoch);
}

/** 忘记密码时的兜底：需要 ADMIN_SECRET（等同于服务器控制权）。 */
async function adminResetPassword(request, env) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;
  if (!timingSafeEqual(request.headers.get("x-admin-secret") ?? "", env.ADMIN_SECRET ?? "")) {
    return err(403, "secret_required", "重置密码必须在请求头里带 X-Admin-Secret");
  }
  const body = (await readJson(request)) ?? {};
  const username = String(body.username ?? "").trim().toLowerCase();
  const user = await getAdminUser(env, username);
  if (!user) return err(404, "user_not_found", `没有账号 ${username}`);
  const next = String(body.new_password ?? "");
  if (next.length < PASSWORD_MIN) return err(400, "weak_password", `密码至少 ${PASSWORD_MIN} 位`);

  const salt = randomSecret();
  const iterations = pbkdf2Iterations(env);
  await putAdminUser(env, {
    username,
    salt,
    hash: await pbkdf2Hex(next, salt, iterations),
    iterations,
    created_at: Number(user.created_at),
    updated_at: Date.now(),
  });
  // 重置密码（忘记密码的兜底）同样要作废所有已登录会话：
  // 重置的典型场景就是"怀疑账号被别人用过"。
  await bumpSessionEpoch(env, username);
  await audit(env, "admin.password_reset", username, "管理员重置", "cli");
  return json({ ok: true, username });
}

async function adminMe(request, env) {
  const session = await adminSession(request, env);
  if (!session) return err(401, "not_logged_in");
  return json({ ok: true, username: session.username });
}

/**
 * 登出：清掉浏览器里的 cookie，并把会话代次 +1。
 *
 * 只清 cookie 是不够的——cookie 一旦泄漏，攻击者手里那份副本会一直有效到过期
 * （最长 2 小时），管理员"登出"这个动作等于没做。代次 +1 才会让所有副本立刻作废。
 *
 * 只在**带了有效会话**时才 +1：否则任何人凭一个用户名调这个接口就能把管理员
 * 踢下线，等于白送一个拒绝服务入口。
 */
async function adminLogout(request, env) {
  const session = env?.ADMIN_SECRET ? await adminSession(request, env) : null;
  if (session) {
    await bumpSessionEpoch(env, session.username);
    await audit(env, "admin.logout", session.username, "", session.username);
  }
  return new Response(JSON.stringify({ ok: true, revoked: Boolean(session) }), {
    status: 200,
    headers: { ...JSON_HEADERS, "set-cookie": sessionCookie(request, "", 0) },
  });
}

function validateJoinKey(key) {
  if (key.length < 16 || key.length > 128) {
    return err(400, "invalid_join_key", "join_key 长度需在 16~128 字符之间");
  }
  return null;
}

/**
 * 手写密钥是不是明显可猜。
 *
 * 服务端只存 sha256，所以弱密钥本身不致命——但一旦 D1 备份泄漏，
 * 哈希就可以离线爆破。这里不拒绝（会误伤密码短语），只提醒。
 */
function joinKeyLooksWeak(key) {
  const unique = new Set(key).size;
  if (unique < 8) return true;
  if (/^[a-z]+$/.test(key) || /^[0-9]+$/.test(key)) return true;
  return false;
}

function tokenOf(networkId, joinKey) {
  return `${TOKEN_PREFIX}${networkId}_${joinKey}`;
}

function randomSecret() {
  const buf = new Uint8Array(24);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// 节点
// ---------------------------------------------------------------------------

async function joinOrRegister(request, env, url, needCandidates) {
  return forwardToRoom(request, env, url, needCandidates ? "/i/register" : "/i/join");
}

async function connect(request, env, url) {
  return forwardToRoom(request, env, url, "/i/connect");
}

async function events(request, env, url) {
  return forwardToRoom(request, env, url, "/i/events");
}

async function leave(request, env, url) {
  return forwardToRoom(request, env, url, "/i/leave");
}

async function authenticate(request, env, url) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.toLowerCase().startsWith("bearer ")
    ? header.slice(7).trim()
    : url.searchParams.get("token") ?? "";

  if (!token.startsWith(TOKEN_PREFIX)) {
    return { ok: false, response: err(401, "invalid_token", `令牌格式应为 ${TOKEN_PREFIX}<网络>_<密钥>`) };
  }

  const parsed = parseToken(token);
  if (!parsed) return { ok: false, response: err(401, "invalid_token") };

  let network = await getNetwork(env, parsed.networkId);

  // 正常路径：加入密钥是每个网络自己的，服务端只存哈希，
  // 与 ADMIN_SECRET 无关——换管理密钥不会让成员掉线，泄漏一把加入密钥
  // 也推不出管理密钥。
  if (network && network.join_hash) {
    const digest = await sha256Hex(parsed.secret);
    if (!timingSafeEqual(digest, network.join_hash)) {
      // 缓存里对不上，不代表这把令牌是错的：换密钥后的 15 秒内，本 isolate 手里可能
      // 还是旧 join_hash，拿到的恰恰是新令牌。鉴权失败是低频事件，直接读一次主库；
      // 读到了就用最新行（顺手刷新缓存），读不到才判 wrong_secret。
      // 反方向（旧令牌 + 旧缓存）不在这里兜，交给 DO 的 rev 判定，见 loadNet。
      const fresh = await getNetworkFresh(env, parsed.networkId);
      if (!fresh?.join_hash || !timingSafeEqual(digest, fresh.join_hash)) {
        return { ok: false, response: err(403, "wrong_secret", "加入密钥不正确") };
      }
      return { ok: true, network: fresh };
    }
    return { ok: true, network };
  }

  // 兼容：2.0 及更早建的网，密钥由 ADMIN_SECRET 派生，没有独立预设密钥。
  // 建议管理员对这些网络调一次 rotate，之后就与 ADMIN_SECRET 解耦了。
  if (!env.ADMIN_SECRET) {
    return { ok: false, response: err(503, "admin_secret_unset", "服务端未设置 ADMIN_SECRET") };
  }
  const expected = await legacyTokenFor(parsed.networkId, env.ADMIN_SECRET);
  if (!timingSafeEqual(expected, token)) {
    return { ok: false, response: err(403, "wrong_secret", "网络密钥不匹配") };
  }

  if (!network) {
    // 旧版令牌有效但注册表丢了：按同一算法补回，网段保持一致
    network = {
      network_id: parsed.networkId,
      name: parsed.networkId,
      cidr: await pickCidr(env, parsed.networkId),
      created_at: Date.now(),
      join_hash: "",
    };
    await putNetwork(env, network);
  }

  return { ok: true, network };
}

function parseToken(token) {
  const rest = token.slice(TOKEN_PREFIX.length);
  const index = rest.indexOf("_");
  if (index <= 0 || index === rest.length - 1) return null;
  return { networkId: rest.slice(0, index), secret: rest.slice(index + 1) };
}

/**
 * 旧版令牌：`HMAC(ADMIN_SECRET, "token:<网络>")`。
 *
 * 只用于 2.0 及更早创建的网络（networks.join_hash 为空）。
 * 这条路径的副作用是"拿到一把令牌就能离线爆破 ADMIN_SECRET"，
 * 所以新网络一律走独立密钥；旧网络调一次 rotate 即可切过来。
 */
async function legacyTokenFor(networkId, adminSecret) {
  const mac = await hmacHex(adminSecret, `token:${networkId}`);
  return `${TOKEN_PREFIX}${networkId}_${mac.slice(0, 40)}`;
}

// ---------------------------------------------------------------------------
// 存储：D1 优先，未绑定时退回 isolate 内存
// ---------------------------------------------------------------------------

/**
 * 建表（幂等）。只针对控制面：networks / 审计 / 管理员 / 登录失败 / 预留备份。
 * 数据面（节点、事件、nonce）在 Durable Object 自己的 SQLite 里。
 */
/** 建过表的 DB 对象（每个 isolate 各记一份，避免每次请求都跑 DDL）。 */
const migrated = new WeakSet();

async function ready(env) {
  if (!env.DB) throw new Error("Worker 没有绑定 D1（DB）。控制面必须要有 D1");
  if (!migrated.has(env.DB)) {
    for (const sql of DDL_STATEMENTS) {
      try {
        await env.DB.prepare(sql).run();
      } catch (e) {
        // 只放过"列已存在"，其它错误照旧抛
        if (!/duplicate column|already exists/i.test(String(e?.message ?? e))) throw e;
      }
    }
    migrated.add(env.DB);
  }
  return "d1";
}

/**
 * 网络行缓存。
 *
 * 每个请求（包括每一次 WS 握手）都要拿一次 network 行做令牌校验，room 模式下
 * 一次 events 请求就多一次 D1 读。这里按 isolate 缓存 15 秒，写路径显式失效。
 *
 * 代价：跨 isolate 的改名/换密钥最多滞后 15 秒可见（设计 §6.1）。**这个滞后不能
 * 被当成"只是显示旧名字"**——握手校验用的正是这张表，所以换密钥后，另一个
 * isolate 的旧缓存会认旧令牌（实测能拿到 101）。安全阀不在缓存新鲜度上，而是
 * 网络行自带的 `rev`：DO 拒绝比自己见过的最大值更旧的上下文（见 NetworkRoom.loadNet）。
 */
const NET_CACHE_TTL_MS = 15_000;
const netCache = new WeakMap(); // env.DB（对象身份）→ Map<id, { at, net }>

function invalidateNetwork(env, id) {
  if (!env.DB || !id) return;
  netCache.get(env.DB)?.delete(id);
}

async function getNetwork(env, id) {
  await ready(env);
  let box = netCache.get(env.DB);
  if (!box) {
    box = new Map();
    netCache.set(env.DB, box);
  }
  const hit = box.get(id);
  if (hit && Date.now() - hit.at < NET_CACHE_TTL_MS) return { ...hit.net };

  const net = await env.DB.prepare("SELECT * FROM networks WHERE network_id = ?").bind(id).first();
  if (net) box.set(id, { at: Date.now(), net: { ...net } });
  else box.delete(id);
  return net;
}

/**
 * 管理面专用：绕过缓存直接读 D1。
 *
 * 缓存是为了压热路径（每个请求、每次握手都要校验令牌）的读次数，代价是最多滞后
 * 15 秒，而且**跨 isolate 各存各的**。管理动作（删网、改名、换密钥）之后要立刻看到
 * 结果，所以这些地方必须读主库；读到之后顺手把缓存更新成最新值。
 */
async function getNetworkFresh(env, id) {
  await ready(env);
  const net = await env.DB.prepare("SELECT * FROM networks WHERE network_id = ?").bind(id).first();
  let box = netCache.get(env.DB);
  if (!box) {
    box = new Map();
    netCache.set(env.DB, box);
  }
  if (net) box.set(id, { at: Date.now(), net: { ...net } });
  else box.delete(id);
  return net;
}

/**
 * 取下一个全局单调的版本号。
 *
 * 先自增再读回，而不是 `RETURNING`：两条语句在 D1 与本地 SQLite 替身上行为一致。
 * 两个 isolate 并发时可能读到同一个值（各自的 +1 已经落库，读回的是更后面的值），
 * 这对正确性无影响——版本号只在同一个网络的 DO 内部比较，"不重复"不是必要条件，
 * "单调"才是。同一网络的写操作只有管理员触发，不存在并发抢同一个网络的场景。
 *
 * `k`：`'seq'` = 安全版本 rev，`'cfg'` = 配置版本 cfg_rev。两条序列独立编号。
 */
async function nextCounter(env, k) {
  await env.DB.prepare(
    "INSERT INTO net_rev (k, v) VALUES (?, 1) ON CONFLICT(k) DO UPDATE SET v = v + 1",
  )
    .bind(k)
    .run();
  const row = await env.DB.prepare("SELECT v FROM net_rev WHERE k = ?").bind(k).first();
  return Number(row?.v ?? 1);
}

function nextRev(env) {
  return nextCounter(env, "seq");
}

function nextCfgRev(env) {
  return nextCounter(env, "cfg");
}

/**
 * 写网络行。
 *
 * - `bump: true`（默认）前进 rev：仅用于新建与换密钥。它会让别的 isolate 手里的
 *   上下文立刻作废（那些请求会收到 403 stale_net_rev），改名绝不能用。
 * - `cfg: true` 前进 cfg_rev：用于改名 / 改网段。它不拒绝任何请求，只让 DO 知道
 *   "名字或网段变了，请覆盖你手里那份"。
 * - 删网则由 DO 记墓碑。
 */
async function putNetwork(env, net, { bump = true, cfg = false } = {}) {
  await ready(env);
  invalidateNetwork(env, net.network_id);
  if (bump) net.rev = await nextRev(env);
  else net.rev = Number(net.rev ?? 0);
  if (cfg) net.cfg_rev = await nextCfgRev(env);
  else net.cfg_rev = Number(net.cfg_rev ?? 0);
  await env.DB.prepare(
    "INSERT OR REPLACE INTO networks (network_id, name, cidr, created_at, join_hash, rev, cfg_rev) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      net.network_id,
      net.name,
      net.cidr,
      net.created_at,
      net.join_hash ?? "",
      net.rev,
      net.cfg_rev,
    )
    .run();
  // 再失效一次：分配版本号与写库之间有两个 await，同 isolate 的并发请求可能在这段
  // 窗口里把旧行重新读进缓存。只清一次会留下一个 15 秒的旧 join_hash。
  invalidateNetwork(env, net.network_id);
}


async function audit(env, action, target, detail = "", actor = "") {
  const row = {
    at: Date.now(),
    action,
    target,
    detail: String(detail).slice(0, 400),
    actor: String(actor).slice(0, 40),
  };
  await env.DB.prepare(
    "INSERT INTO admin_actions (at, action, target, detail, actor) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(row.at, row.action, row.target, row.detail, row.actor)
    .run();
}

async function listAudit(env, limit = 100) {
  await ready(env);
  const { results } = await env.DB.prepare(
    "SELECT at, action, target, detail, actor FROM admin_actions ORDER BY id DESC LIMIT ?",
  )
    .bind(Math.min(500, Math.max(1, limit)))
    .all();
  return results ?? [];
}

/**
 * 审计分页：筛选和搜索都下推到 D1，管理台不用把全部历史拉到浏览器。
 * 用 instr(lower(...)) 而不是 LIKE 做搜索，用户输入里的 % / _ 不会被当成通配符。
 */
async function listAuditPage(env, { page, pageSize, kind, q }) {
  await ready(env);
  const where = [];
  const args = [];
  if (kind) {
    where.push("action LIKE ?");
    args.push(`${kind}%`);
  }
  if (q) {
    where.push(
      "(instr(lower(action), lower(?)) > 0 OR instr(lower(target), lower(?)) > 0" +
        " OR instr(lower(detail), lower(?)) > 0 OR instr(lower(actor), lower(?)) > 0)",
    );
    args.push(q, q, q, q);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM admin_actions ${clause}`)
    .bind(...args)
    .first();
  const total = Number(row?.n ?? 0);
  const pages = Math.max(1, Math.ceil(total / pageSize));
  // 筛选后页数可能变小，把越界的页码钳回最后一页
  const safePage = Math.min(page, pages);
  const { results } = await env.DB.prepare(
    `SELECT at, action, target, detail, actor FROM admin_actions ${clause}` +
      " ORDER BY id DESC LIMIT ? OFFSET ?",
  )
    .bind(...args, pageSize, (safePage - 1) * pageSize)
    .all();
  return {
    ok: true,
    actions: results ?? [],
    total,
    page: safePage,
    page_size: pageSize,
    pages,
  };
}


function validateVirtualIp(network, text, nodeId, others, reservations = []) {
  if (!/^(\d{1,3})(\.\d{1,3}){3}$/.test(text)) {
    return err(400, "invalid_virtual_ip", `虚拟地址必须是 a.b.c.d 形式：${text}`);
  }
  if (text.split(".").some((part) => Number(part) > 255)) {
    return err(400, "invalid_virtual_ip", `虚拟地址每段必须在 0~255：${text}`);
  }

  const [base, prefixRaw] = String(network.cidr).split("/");
  const prefix = Math.min(30, Math.max(8, Number(prefixRaw) || 16));
  const hostBits = 32 - prefix;
  const mask = (0xffffffff << hostBits) >>> 0;
  const value = ipv4ToInt(text);

  if ((value & mask) >>> 0 !== (ipv4ToInt(base) & mask) >>> 0) {
    return err(400, "virtual_ip_not_in_network", `${text} 不在网段 ${network.cidr} 里`);
  }

  const hostMask = (~mask) >>> 0;
  const host = (value & hostMask) >>> 0;
  if (host === 0) return err(400, "invalid_virtual_ip", `${text} 是网段地址，不能给节点用`);
  if (host === hostMask) return err(400, "invalid_virtual_ip", `${text} 是广播地址，不能给节点用`);

  const taken = others.find((n) => n.node_id !== nodeId && n.virtual_ip === text);
  if (taken) {
    return err(409, "virtual_ip_taken", `${text} 已经被节点「${taken.name}」占用，换一个`);
  }

  // 被别人预留过的地址也不能抢：预留的意义就是"人不在也算他的"
  const reserved = reservations.find((r) => r.ip === text && r.node_id !== nodeId);
  if (reserved) {
    return err(409, "virtual_ip_reserved", `${text} 已被另一个节点预留，请让管理员先释放`);
  }
  return null;
}

async function assignIp(network, nodeId, others, reservations = []) {
  const used = new Set(others.map((n) => n.virtual_ip).filter(Boolean));
  for (const r of reservations) {
    if (r.node_id !== nodeId) used.add(r.ip);
  }
  for (let salt = 0; salt < 32; salt += 1) {
    const ip = await deriveVirtualIp(nodeId, network.cidr, salt);
    if (!used.has(ip)) return ip;
  }
  // 32 次都撞了：退化为线性探测，保证一定能分配
  const base = network.cidr.split("/")[0].split(".").slice(0, 3).join(".");
  for (let host = 2; host < 255; host += 1) {
    const ip = `${base}.${host}`;
    if (!used.has(ip)) return ip;
  }
  return `${base}.2`;
}

/** 与 crates/core/src/identity.rs 的 derive_virtual_ip 同算法。导出供交叉验证。 */
export async function deriveVirtualIp(nodeId, cidr, salt) {
  const [base, prefixRaw] = cidr.split("/");
  const prefix = Math.min(30, Math.max(8, Number(prefixRaw) || 16));
  const hostBits = 32 - prefix;
  const mask = hostBits >= 32 ? 0xffffffff : ((1 << hostBits) - 1) >>> 0;

  const idBytes = new TextEncoder().encode(nodeId);
  const buf = new Uint8Array(idBytes.length + 4);
  buf.set(idBytes);
  new DataView(buf.buffer).setUint32(idBytes.length, salt, false);

  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  const raw = new DataView(digest.buffer).getUint32(0, false);

  let host = ((raw & mask) | 2) >>> 0;
  if (host === mask) host ^= 1;

  const baseInt = ipv4ToInt(base) & (~mask >>> 0);
  return intToIpv4((baseInt | host) >>> 0);
}

async function pickCidr(env, networkId) {
  const digest = await sha256Hex(networkId);
  const preferred = parseInt(digest.slice(0, 2), 16) % 64;
  const taken = await usedCidrs(env);
  for (let i = 0; i < 64; i += 1) {
    const cidr = `10.${64 + ((preferred + i) % 64)}.0.0/16`;
    if (!taken.has(cidr)) return cidr;
  }
  return `10.${64 + preferred}.0.0/16`;
}

async function usedCidrs(env) {
  await ready(env);
  const { results } = await env.DB.prepare("SELECT cidr FROM networks").all();
  return new Set((results ?? []).map((r) => r.cidr));
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

function publicNode(node, now) {
  return {
    node_id: node.node_id,
    name: node.name,
    pubkey: node.pubkey,
    virtual_ip: node.virtual_ip,
    nat_type: node.nat_type,
    tls_fp: node.tls_fp,
    first_seen: Number(node.first_seen ?? 0) || node.last_seen,
    candidates: safeParseArray(node.candidates),
    last_seen: node.last_seen,
    online: now - node.last_seen <= OFFLINE_MS,
  };
}

function parseCandidates(raw) {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw) || raw.length > MAX_CANDIDATES) return null;
  const out = [];
  for (const item of raw) {
    // 兼容两种写法："ip:port" 或 {"type":"srflx","addr":"ip:port"}
    const text = (typeof item === "string" ? item : String(item?.addr ?? "")).trim();
    if (!/^(\d{1,3}(\.\d{1,3}){3}):(\d{1,5})$/.test(text)) return null;
    const [ip, portText] = text.split(":");
    const port = Number(portText);
    if (port < 1 || port > 65535) return null;
    if (ip.split(".").some((part) => Number(part) > 255 || part === "")) return null;
    if (!isDialable(ip)) return null;
    if (!out.includes(text)) out.push(text);
  }
  return out;
}

/// 只接受能当"对端地址"的 IP：回环、0.0.0.0、链路本地、组播/保留段一律拒绝。
/// 否则任意成员都能登记第三方地址，让其他节点往那里持续发 QUIC 包。
function isDialable(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 0 || a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a >= 224) return false;
  return true;
}

function normalizeCidr(text) {
  const match = /^10\.(\d{1,3})\.0\.0\/16$/.exec(text.trim());
  if (!match) return null;
  const second = Number(match[1]);
  if (second < 0 || second > 255) return null;
  return `10.${second}.0.0/16`;
}

function slug(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function randomId() {
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readJson(request) {
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > MAX_BODY_BYTES) return null;
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return null;
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

async function sha256Hex(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return hex(new Uint8Array(digest));
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return hex(new Uint8Array(sig));
}

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// 请求签名：签名覆盖整个请求体（去掉 sig），再加时间戳与 nonce 防重放
// ---------------------------------------------------------------------------

const SIGN_PREFIX = "qp2p1";
const TS_WINDOW_MS = 120_000;

/**
 * 规范 JSON：键按 Unicode 码点升序、无空白、非 ASCII 转义成 \\uXXXX。
 *
 * 客户端必须逐字节复现这段序列化，然后把 sha256 放进签名串：
 *   qp2p1|<op>|<network>|<ts>|<nonce>|<body digest>
 *
 * 之所以不手工挑字段：tls_fp、candidates、name 任何一个漏签，攻击者就能
 * 拿一份合法报文改掉它重放（tls_fp 将来要用于证书钉扎，尤其不能漏）。
 *
 * 数字规则（与 crates/core/src/signal/canonical.rs 一致）：
 * 只允许 ±(2^53-1) 以内的整数，其余一律拒绝而不是各自格式化。
 * JS 把 1.0 写成 1、会静默丢失 2^53 以上整数的精度，而 Rust 会原样输出，
 * 两边摘要不同只会表现为难以排查的 bad_signature。-0 也拒绝：
 * serde_json 把它解析成浮点，两端必须对"能不能签"得出同一个结论。
 */
export function canonicalJson(value) {
  if (value === null) return "null";
  const type = typeof value;
  if (type === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`不支持的数字 ${value}：只允许 ±(2^53-1) 以内的整数`);
    }
    return String(value);
  }
  if (type === "boolean") return value ? "true" : "false";
  if (type === "string") return quoteJson(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (type === "object") {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort(compareCodePoints);
    return `{${keys.map((k) => `${quoteJson(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  throw new Error(`不支持的类型：${type}`);
}

/** 按码点比较。默认 sort() 按 UTF-16 码元比较，遇到 BMP 之上的字符会和 Rust 的字节序不同。 */
function compareCodePoints(a, b) {
  const x = Array.from(a);
  const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i += 1) {
    const diff = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (diff !== 0) return diff;
  }
  return x.length - y.length;
}

function quoteJson(text) {
  let out = '"';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code > 0x7e) {
      if (code > 0xffff) {
        const rest = code - 0x10000;
        const hi = 0xd800 + (rest >> 10);
        const lo = 0xdc00 + (rest & 0x3ff);
        out += `\\u${hi.toString(16).padStart(4, "0")}\\u${lo.toString(16).padStart(4, "0")}`;
      } else {
        out += `\\u${code.toString(16).padStart(4, "0")}`;
      }
    } else out += ch;
  }
  return `${out}"`;
}

/** 去掉 sig 之后的请求体摘要。 */
async function bodyDigest(body) {
  const { sig: _sig, ...rest } = body ?? {};
  return sha256Hex(canonicalJson(rest));
}

function signingMessage(op, networkId, ts, nonce, digest) {
  return [SIGN_PREFIX, op, networkId, ts, nonce, digest].join("|");
}



async function verifySignature(pubkey, message, sig) {
  const text = String(sig ?? "").toLowerCase();
  if (!/^[0-9a-f]{128}$/.test(text)) return "sig 必须是 64 字节 Ed25519 签名的十六进制";

  try {
    const key = await crypto.subtle.importKey("raw", hexToBytes(pubkey), { name: "Ed25519" }, false, [
      "verify",
    ]);
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      hexToBytes(text),
      new TextEncoder().encode(message),
    );
    return ok ? null : "签名不匹配";
  } catch (e) {
    return `无法校验签名：${e instanceof Error ? e.message : String(e)}`;
  }
}

function hexToBytes(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function ipv4ToInt(text) {
  return text.split(".").reduce((acc, part) => ((acc << 8) | Number(part)) >>> 0, 0) >>> 0;
}

function intToIpv4(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

/** ip 是否落在 cidr 里。改网段后判断哪些节点要重新分配时用。 */
function ipInCidr(cidr, ip) {
  if (!ip || !/^(\d{1,3})(\.\d{1,3}){3}$/.test(ip)) return false;
  const [base, prefixRaw] = String(cidr).split("/");
  const prefix = Math.min(30, Math.max(8, Number(prefixRaw) || 16));
  const hostBits = 32 - prefix;
  const mask = (0xffffffff << hostBits) >>> 0;
  return (ipv4ToInt(ip) & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0;
}

function safeParse(text) {
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function safeParseArray(text) {
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const rate = new Map(); // "ip|上限" -> { start, count }

function limited(request, max = RATE_MAX, scope = "") {
  const ip = request.headers.get("cf-connecting-ip") ?? "local";
  const bucket = `${scope}${ip}|${max}`;
  const now = Date.now();
  const slot = rate.get(bucket);
  if (!slot || now - slot.start > RATE_WINDOW_MS) {
    if (rate.size > 4096) rate.clear();
    rate.set(bucket, { start: now, count: 1 });
    return false;
  }
  slot.count += 1;
  return slot.count > max;
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, content-type, x-admin-secret",
  "access-control-allow-methods": "GET, POST, PATCH, DELETE, OPTIONS",
};

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  ...CORS,
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS } });
}

function err(status, code, detail) {
  return json({ ok: false, error: code, ...(detail ? { detail } : {}) }, status);
}

// 事件与僵尸节点的清理：按间隔触发，避免每个请求都写一次
const sweeper = { last: 0 };
let healthCache = { at: 0, nodes: null };

/**
 * D1 清理。
 *
 * `dataPlane=false` 时只清控制面（登录失败记录）：room 模式下 nodes/events/
 * reservations/nonces 都已经搬进 DO，再对 D1 那几张表跑 4 条全表 DELETE 纯属浪费
 * 额度（每个 isolate 每 5 分钟一次）。
 */
/**
 * 控制面清理：登录失败记录与过期审计。
 *
 * 数据面（节点、事件、nonce、自动预留）在 DO 里，由 DO 自己的惰性 sweep 管。
 * 升级前留下的旧表不再读写，也不再清理——它们的 TTL 早已过，留着不占写入额度。
 */
async function sweep(env) {
  const now = Date.now();
  if (now - sweeper.last < SWEEP_INTERVAL_MS) return 0;
  sweeper.last = now;

  await env.DB.prepare("DELETE FROM login_attempts WHERE last_at < ?")
    .bind(now - 24 * 60 * 60_000)
    .run();
  return 0;
}

// ---------------------------------------------------------------------------
// 管理页面：单文件，同域，登录后所有请求走 cookie
// ---------------------------------------------------------------------------

function adminPage() {
  return new Response(ADMIN_PAGE, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "content-security-policy":
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
    },
  });
}

const ADMIN_PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>qp2p 管理台</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#1a1c1f;--muted:#6b7280;--line:#e5e7eb;--accent:#2563eb;--danger:#dc2626;--ok:#16a34a;--warn:#b45309}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--muted:#9aa3ad;--line:#262b33;--accent:#5b8cff;--danger:#f87171;--ok:#4ade80;--warn:#fbbf24}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:5}
h1{font-size:16px;margin:0;font-weight:600}
main{max-width:1100px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
input,select{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
select{width:auto;min-width:180px}
button{padding:7px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--danger);border-color:var(--danger)}
button.sm{padding:3px 8px;font-size:12px}
button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle}
th{color:var(--muted);font-weight:500;font-size:12px;white-space:nowrap}
tr:last-child td{border-bottom:0}
.muted{color:var(--muted)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.on{background:var(--ok)}.off{background:var(--muted)}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid var(--line);color:var(--muted)}
.tag.warn{color:var(--warn);border-color:var(--warn)}
.tag.good{color:var(--ok);border-color:var(--ok)}
pre{white-space:pre-wrap;word-break:break-all;background:var(--bg);padding:10px;border-radius:8px;font-size:12px}
.hide{display:none}
.scroll{overflow-x:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px}
.stat b{display:block;font-size:22px;line-height:1.2}
.stat span{font-size:12px;color:var(--muted)}
.banner{border-left:3px solid var(--warn);background:color-mix(in srgb,var(--warn) 8%,var(--card));padding:10px 12px;border-radius:8px;margin-bottom:12px;font-size:13px}
.detail td{background:var(--bg);font-size:12px}
.kv{display:grid;grid-template-columns:120px 1fr;gap:4px 12px}
.kv div:nth-child(odd){color:var(--muted)}
</style>
</head>
<body>
<header>
  <h1>qp2p 管理台</h1>
  <span class="muted" id="who"></span>
  <span style="flex:1"></span>
  <button id="changePwd" class="hide">改密码</button>
  <button id="refresh" class="hide">刷新</button>
  <button id="logout" class="hide">退出</button>
</header>
<main>
  <section id="login" class="card hide" style="max-width:420px;margin:40px auto">
    <h2 style="margin-top:0;font-size:15px" id="authTitle">登录</h2>
    <label>用户名</label>
    <input id="username" autocomplete="username" placeholder="admin">
    <label>密码</label>
    <input id="password" type="password" autocomplete="current-password" placeholder="至少 8 位">
    <label id="secretLabel" class="hide">初始化密钥（ADMIN_SECRET，只在第一次用）</label>
    <input id="secret" type="password" autocomplete="off" class="hide" placeholder="部署时设置的 ADMIN_SECRET">
    <div class="row" style="margin-top:14px"><button class="primary" id="doAuth">登录</button><span class="muted" id="authMsg"></span></div>
    <p class="muted" style="font-size:12px;margin-bottom:0" id="authHint">登录后服务端签发 2 小时 HttpOnly cookie，密码不会存进浏览器。</p>
  </section>

  <div id="dash" class="hide">
    <div id="healthBanner" class="banner hide"></div>

    <section class="card">
      <h2 style="margin:0 0 12px;font-size:15px">概览</h2>
      <div class="grid">
        <div class="stat"><b id="statNets">0</b><span>网络</span></div>
        <div class="stat"><b id="statNodes">0</b><span>设备总数</span></div>
        <div class="stat"><b id="statOnline">0</b><span>在线设备</span></div>
        <div class="stat"><b id="statResv">0</b><span>IP 预留</span></div>
        <div class="stat"><b id="statOffline">0</b><span>离线超 10 分钟</span></div>
      </div>
    </section>

    <section class="card">
      <h2 style="margin:0 0 10px;font-size:15px">网络</h2>
      <div class="scroll"><table><thead><tr><th>名称</th><th>网段</th><th>节点</th><th>在线</th><th>预留</th><th>操作</th></tr></thead><tbody id="nets"></tbody></table></div>
      <div class="row" style="margin-top:12px">
        <input id="newName" placeholder="新网络名称" style="max-width:180px">
        <input id="newCidr" placeholder="网段（可空，如 10.90.0.0/16）" style="max-width:220px">
        <input id="newKey" placeholder="加入密钥（可空，自动生成）" style="max-width:220px">
        <button class="primary" id="createNet">新建</button>
      </div>
      <pre id="tokenOut" class="hide"></pre>
    </section>

    <section class="card hide" id="nodesCard">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2 style="margin:0;font-size:15px">成员 <span class="muted" id="nodesFor"></span></h2>
        <div class="row">
          <select id="netPick" title="选择要查看的网络"></select>
          <button id="refreshNodes" class="sm">刷新</button>
        </div>
      </div>
      <div class="row" style="margin-bottom:10px">
        <label class="row" style="margin:0;font-size:12px;color:var(--muted)"><input type="checkbox" id="checkAll" style="width:auto;margin-right:6px">全选</label>
        <button id="kickSelected" class="sm danger" disabled>踢下线所选</button>
        <button id="exportNodes" class="sm">导出成员 CSV</button>
        <button id="exportResv" class="sm">导出预留 CSV</button>
      </div>
      <div class="scroll"><table><thead><tr><th style="width:28px"></th><th>状态</th><th>名称</th><th>虚拟 IP</th><th>NAT</th><th>在线时长</th><th>最后心跳</th><th>操作</th></tr></thead><tbody id="nodes"></tbody></table></div>
      <h2 style="margin:18px 0 10px;font-size:15px">IP 预留</h2>
      <div class="scroll"><table><thead><tr><th>IP</th><th>节点</th><th>类型</th><th>备注</th><th>操作</th></tr></thead><tbody id="resv"></tbody></table></div>
      <div class="row" style="margin-top:12px">
        <input id="resvIp" placeholder="要预留的 IP" style="max-width:160px">
        <input id="resvNode" placeholder="node_id（可空）" style="max-width:280px">
        <input id="resvNote" placeholder="备注" style="max-width:180px">
        <button id="addResv">预留</button>
      </div>
    </section>

    <section class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h2 style="margin:0;font-size:15px">操作审计</h2>
        <div class="row">
          <select id="auditKind">
            <option value="">全部动作</option>
            <option value="network.">网络</option>
            <option value="node.">节点</option>
            <option value="reservation.">预留</option>
            <option value="login.">登录</option>
            <option value="admin.">账号</option>
          </select>
          <input id="auditSearch" placeholder="搜索对象/详情/操作人" style="max-width:200px">
        </div>
      </div>
      <div class="scroll"><table><thead><tr><th>时间</th><th>操作人</th><th>动作</th><th>对象</th><th>详情</th></tr></thead><tbody id="audit"></tbody></table></div>
      <div class="row" style="justify-content:space-between;align-items:center;margin-top:10px">
        <span class="muted" id="auditInfo">共 0 条</span>
        <div class="row" style="gap:10px">
          <button class="sm" id="auditPrev">上一页</button>
          <span class="muted" id="auditPage">第 1 / 1 页</span>
          <button class="sm" id="auditNext">下一页</button>
        </div>
      </div>
    </section>
  </div>
</main>
<script>
var current = null, nets = [], nodes = [], reservations = [], needBootstrap = false;

function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function api(path, method, body){
  var opt = {method: method||'GET', credentials:'same-origin', headers:{}};
  if (body !== undefined) { opt.headers['content-type']='application/json'; opt.body=JSON.stringify(body); }
  return fetch(path, opt).then(function(r){
    return r.json().catch(function(){return {ok:false,error:'bad_json'}}).then(function(j){
      if (!r.ok || j.ok === false) { var e = new Error((j.error||String(r.status)) + ' ' + (j.detail||'')); e.status = r.status; throw e; }
      return j;
    });
  });
}
function ago(ms){ if(!ms) return '—'; var d=Math.max(0,Math.round((Date.now()-ms)/1000));
  if(d<60)return d+' 秒前'; if(d<3600)return Math.round(d/60)+' 分钟前'; if(d<86400)return Math.round(d/3600)+' 小时前'; return Math.round(d/86400)+' 天前'; }
function span(ms){ if(!ms) return '—'; var d=Math.max(0,Math.round((Date.now()-ms)/1000));
  var day=Math.floor(d/86400), h=Math.floor(d%86400/3600), m=Math.floor(d%3600/60);
  if(day) return day+' 天 '+h+' 小时'; if(h) return h+' 小时 '+m+' 分'; return m+' 分'; }
function natLabel(n){
  var map={upnp:'UPnP 映射',srflx:'STUN 反射',host:'内网地址',cone:'锥形 NAT',symmetric:'对称 NAT',unknown:'未知'};
  return map[n] || n || '未知';
}
function natRisk(n){ return n==='symmetric'; }
function copyText(text){
  if (navigator.clipboard) { navigator.clipboard.writeText(text).then(function(){},function(){prompt('手动复制：', text)}); }
  else prompt('手动复制：', text);
}
function download(name, rows){
  var csv = rows.map(function(r){return r.map(function(c){return '"'+String(c==null?'':c).replace(/"/g,'""')+'"'}).join(',')}).join('\\n');
  var blob = new Blob(['\\ufeff'+csv], {type:'text/csv;charset=utf-8'});
  var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
}

function showLogin(){
  $('dash').classList.add('hide');
  $('login').classList.remove('hide');
  $('who').textContent='';
  $('changePwd').classList.add('hide'); $('refresh').classList.add('hide'); $('logout').classList.add('hide');
}
function showBoot(){
  needBootstrap = true;
  $('authTitle').textContent='第一次使用：创建管理员';
  $('secretLabel').classList.remove('hide'); $('secret').classList.remove('hide');
  $('doAuth').textContent='创建并登录';
  $('authHint').textContent='这一步需要部署时设置的 ADMIN_SECRET，账号建好后就不再需要它了。';
  showLogin();
}
function showDash(username){
  $('login').classList.add('hide'); $('dash').classList.remove('hide');
  $('who').textContent = username ? '· ' + username : '';
  $('changePwd').classList.remove('hide'); $('refresh').classList.remove('hide'); $('logout').classList.remove('hide');
  load();
}

function auth(){
  var body = {username:$('username').value.trim(), password:$('password').value};
  var path = '/v1/admin/login';
  if (needBootstrap) { body.secret = $('secret').value; path = '/v1/admin/bootstrap'; }
  $('authMsg').textContent='处理中…';
  api(path,'POST',body).then(function(j){
    $('password').value=''; $('secret').value=''; $('authMsg').textContent='';
    showDash(j.username || body.username);
  }).catch(function(e){
    $('authMsg').textContent = needBootstrap ? ('创建失败：'+e.message) : ('登录失败：'+e.message);
  });
}

function load(){
  api('/v1/admin/networks').then(function(j){ renderNets(j.networks||[]) }).catch(function(e){
    if (e.status === 401) { showLogin(); }
  });
  loadAudit();
}
var auditCur = 1, auditPages = 1, auditTotal = 0, auditTimer = 0;
function loadAudit(page){
  if (typeof page === 'number') auditCur = page;
  var kind = $('auditKind').value, q = $('auditSearch').value.trim();
  var path = '/v1/admin/audit?page='+auditCur+'&page_size=20'+
    '&kind='+encodeURIComponent(kind)+'&q='+encodeURIComponent(q);
  api(path).then(function(j){
    var rows = j.actions || [];
    auditTotal = j.total || 0;
    auditPages = Math.max(1, j.pages || 1);
    auditCur = j.page || auditCur;
    renderAudit(rows);
    $('auditInfo').textContent = '共 '+auditTotal+' 条' + (rows.length ? '，本页 '+rows.length+' 条' : '');
    $('auditPage').textContent = '第 '+auditCur+' / '+auditPages+' 页';
    $('auditPrev').disabled = auditCur <= 1;
    $('auditNext').disabled = auditCur >= auditPages;
  }).catch(function(){});
}
function resetAudit(){ auditCur = 1; loadAudit(); }

function renderNets(list){
  nets = list;
  var total = 0, online = 0, resv = 0, offlineLong = 0;
  list.forEach(function(n){ total += n.nodes; online += n.online; resv += n.reservations; });
  $('statNets').textContent = list.length;
  $('statNodes').textContent = total;
  $('statOnline').textContent = online;
  $('statResv').textContent = resv;

  var pick = $('netPick');
  var keep = current || pick.value || null;
  pick.innerHTML = '';
  list.forEach(function(n){
    var opt = document.createElement('option');
    opt.value = n.id;
    opt.textContent = n.name + ' · ' + n.cidr + '（在线 ' + n.online + '/' + n.nodes + '）';
    pick.appendChild(opt);
  });
  if (keep && list.some(function(n){return n.id===keep;})) pick.value = keep;
  else if (list.length) { pick.value = list[0].id; current = list[0].id; }

  var t = $('nets'); t.innerHTML='';
  if (!list.length) t.innerHTML = '<tr><td colspan="6" class="muted">还没有网络，先新建一个</td></tr>';
  list.forEach(function(n){
    var tr = document.createElement('tr');
    tr.innerHTML = '<td><b>'+esc(n.name)+'</b><div class="muted" style="font-size:12px">'+esc(n.id)+'</div></td>'+
      '<td>'+esc(n.cidr)+'</td><td>'+n.nodes+'</td><td>'+n.online+'</td><td>'+n.reservations+'</td>';
    var td = document.createElement('td'); td.className='row';
    td.appendChild(btn('查看','sm',function(){ current=n.id; pick.value=n.id; loadNodes(n.id); }));
    td.appendChild(btn('改网段','sm',function(){
      var v=prompt('新网段（10.x.0.0/16）。落在网段外的节点会被重新分配地址', n.cidr);
      if(v) api('/v1/admin/networks/'+n.id,'PATCH',{cidr:v}).then(function(j){
        // 控制面已生效、数据面没确认时必须说出来，否则"改了没反应"无从排查
        if(j.warning) alert('已保存，但：'+j.warning);
        load();
      }).catch(function(e){alert(e.message)});
    }));
    td.appendChild(btn('换密钥','sm',function(){
      if(!confirm('换掉「'+n.name+'」的加入密钥？旧令牌立刻失效')) return;
      api('/v1/admin/networks/'+n.id+'/rotate','POST',{}).then(function(j){
        $('tokenOut').classList.remove('hide');
        $('tokenOut').textContent = '新令牌（只显示这一次）：\\n' + j.token;
        if(j.warning) alert('新令牌已生效，但：'+j.warning);
      }).catch(function(e){alert(e.message)});
    }));
    td.appendChild(btn('删除','sm danger',function(){
      var v=prompt('不可撤销。输入网络 id 确认删除：'+n.id); if(v!==n.id) return;
      api('/v1/admin/networks/'+n.id,'DELETE',{confirm:v}).then(function(){
        if(current===n.id){current=null;$('nodesCard').classList.add('hide')} load();
      }).catch(function(e){alert(e.message)});
    }));
    tr.appendChild(td); t.appendChild(tr);
  });

  if (current) loadNodes(current);
}

function btn(text, cls, fn){ var b=document.createElement('button'); b.textContent=text; b.className=cls; b.onclick=fn; return b; }

function loadNodes(id){
  current = id;
  $('nodesCard').classList.remove('hide');
  $('nodesFor').textContent = '· ' + id;
  api('/v1/admin/networks/'+id+'/nodes').then(function(j){
    nodes = j.nodes || []; reservations = j.reservations || [];
    var online = nodes.filter(function(n){return n.online}).length;
    var longOff = nodes.filter(function(n){return !n.online && Date.now()-n.last_seen > 600000}).length;
    $('nodesFor').textContent = '· ' + j.network.name + ' ' + j.network.cidr + '　在线 ' + online + ' / 共 ' + nodes.length;
    renderHealth(longOff);
    renderNodes();
    renderResv();
  }).catch(function(e){ if (e.status === 401) showLogin(); });
}

function renderHealth(longOff){
  var sym = nodes.filter(function(n){return n.online && natRisk(n.nat_type)}).length;
  var msgs = [];
  if (longOff) msgs.push(longOff + ' 台设备离线超过 10 分钟');
  if (sym) msgs.push(sym + ' 台在线设备是对称 NAT，打洞可能失败');
  var banner = $('healthBanner');
  if (!msgs.length) { banner.classList.add('hide'); return; }
  banner.classList.remove('hide');
  banner.textContent = '⚠ ' + msgs.join('；');
}

function renderNodes(){
  var t = $('nodes'); t.innerHTML='';
  if (!nodes.length) t.innerHTML = '<tr><td colspan="8" class="muted">还没有节点</td></tr>';
  nodes.slice().sort(function(a,b){ if(a.online!==b.online) return a.online?-1:1; return 0; }).forEach(function(n){
    var tr = document.createElement('tr');
    tr.innerHTML = '<td><input type="checkbox" class="pick" data-id="'+esc(n.node_id)+'" style="width:auto"></td>'+
      '<td><span class="dot '+(n.online?'on':'off')+'"></span>'+(n.online?'在线':'离线')+'</td>'+
      '<td>'+esc(n.name)+(n.reserved?' <span class="tag good">已固定</span>':'')+'</td>'+
      '<td>'+esc(n.virtual_ip)+'</td>'+
      '<td>'+esc(natLabel(n.nat_type))+(natRisk(n.nat_type)?' <span class="tag warn">风险</span>':'')+'</td>'+
      '<td class="muted">'+span(n.first_seen)+'</td>'+
      '<td class="muted">'+ago(n.last_seen)+'</td>';
    var td = document.createElement('td'); td.className='row';
    td.appendChild(btn('详情','sm',function(){ toggleDetail(tr, n); }));
    td.appendChild(btn('踢下线','sm danger',function(){
      if(!confirm('把「'+n.name+'」踢下线？')) return;
      api('/v1/admin/networks/'+current+'/nodes/'+n.node_id+'/kick','POST',{}).then(function(){loadNodes(current)}).catch(function(e){alert(e.message)});
    }));
    td.appendChild(btn('固定此 IP','sm',function(){
      api('/v1/admin/networks/'+current+'/reservations','POST',{ip:n.virtual_ip,node_id:n.node_id,note:'页面固定'})
        .then(function(){loadNodes(current)}).catch(function(e){alert(e.message)});
    }));
    tr.appendChild(td);
    t.appendChild(tr);
  });
  $('checkAll').checked = false;
  $('kickSelected').disabled = true;
  bindPicks();
}

function toggleDetail(tr, n){
  var next = tr.nextSibling;
  if (next && next.classList && next.classList.contains('detail')) { next.remove(); return; }
  var cands = (n.candidates || []).map(function(c){ return typeof c === 'string' ? c : (c.addr || JSON.stringify(c)); });
  var adv = (n.advertised || []).join(', ') || '—';
  var d = document.createElement('tr');
  d.className = 'detail';
  d.innerHTML = '<td colspan="8"><div class="kv">'+
    '<div>node_id</div><div>'+esc(n.node_id)+'</div>'+
    '<div>公钥</div><div>'+esc(n.pubkey ? n.pubkey.slice(0,32)+'…' : '—')+'</div>'+
    '<div>TLS 指纹</div><div>'+esc(n.tls_fp ? n.tls_fp.slice(0,32)+'…' : '—')+'</div>'+
    '<div>候选地址</div><div>'+esc(cands.join('  ') || '—')+'</div>'+
    '<div>广告路由</div><div>'+esc(adv)+'</div>'+
    '<div>首次上线</div><div>'+esc(new Date(n.first_seen||n.last_seen).toLocaleString())+'</div>'+
    '<div>快捷命令</div><div class="row">'+
      '<button class="sm" data-copy="ping '+esc(n.virtual_ip)+'">复制 ping</button>'+
      '<button class="sm" data-copy="ssh '+esc(n.virtual_ip)+'">复制 ssh</button>'+
    '</div></div></td>';
  tr.parentNode.insertBefore(d, tr.nextSibling);
  d.querySelectorAll('[data-copy]').forEach(function(b){
    b.onclick = function(){ copyText(b.getAttribute('data-copy')); };
  });
}

function bindPicks(){
  var boxes = document.querySelectorAll('.pick');
  Array.prototype.forEach.call(boxes, function(b){ b.onchange = updateKickBtn; });
  updateKickBtn();
}
function picked(){
  return Array.prototype.filter.call(document.querySelectorAll('.pick'), function(b){return b.checked})
    .map(function(b){return b.getAttribute('data-id')});
}
function updateKickBtn(){ $('kickSelected').disabled = picked().length === 0; }

function renderResv(){
  var r = $('resv'); r.innerHTML='';
  if (!reservations.length) r.innerHTML = '<tr><td colspan="5" class="muted">没有预留</td></tr>';
  reservations.forEach(function(x){
    var tr = document.createElement('tr');
    tr.innerHTML = '<td>'+esc(x.ip)+'</td><td class="muted">'+esc(x.node_id||'—')+'</td>'+
      '<td>'+(x.kind==='user'?'手动':'自动')+'</td><td class="muted">'+esc(x.note||'')+'</td>';
    var td = document.createElement('td');
    td.appendChild(btn('释放','sm danger',function(){
      api('/v1/admin/networks/'+current+'/reservations/'+x.ip,'DELETE').then(function(){loadNodes(current)}).catch(function(e){alert(e.message)});
    }));
    tr.appendChild(td); r.appendChild(tr);
  });
}

function renderAudit(list){
  var t = $('audit'); t.innerHTML='';
  if (!list || !list.length) { t.innerHTML = '<tr><td colspan="5" class="muted">没有匹配的记录</td></tr>'; return; }
  list.forEach(function(a){
    var tr = document.createElement('tr');
    tr.innerHTML = '<td class="muted">'+new Date(a.at).toLocaleString()+'</td>'+
      '<td>'+esc(a.actor || '—')+'</td><td>'+esc(a.action)+'</td>'+
      '<td>'+esc(a.target)+'</td><td class="muted">'+esc(a.detail)+'</td>';
    t.appendChild(tr);
  });
}

$('doAuth').onclick = auth;
$('password').addEventListener('keydown', function(e){ if(e.key==='Enter') auth(); });
$('secret').addEventListener('keydown', function(e){ if(e.key==='Enter') auth(); });
$('netPick').onchange = function(){ if(this.value) loadNodes(this.value); };
$('refreshNodes').onclick = function(){ if(current) loadNodes(current); };
$('refresh').onclick = load;
$('logout').onclick = function(){ api('/v1/admin/logout','POST',{}).then(showLogin).catch(showLogin); };
$('changePwd').onclick = function(){
  var oldPwd = prompt('当前密码'); if(!oldPwd) return;
  var newPwd = prompt('新密码（至少 8 位）'); if(!newPwd) return;
  api('/v1/admin/password','POST',{old_password:oldPwd,new_password:newPwd})
    .then(function(){ alert('密码已更新'); }).catch(function(e){ alert(e.message); });
};
$('createNet').onclick = function(){
  var body = {name:$('newName').value.trim()};
  if($('newCidr').value.trim()) body.cidr = $('newCidr').value.trim();
  if($('newKey').value.trim()) body.join_key = $('newKey').value.trim();
  api('/v1/admin/networks','POST',body).then(function(j){
    $('tokenOut').classList.remove('hide');
    $('tokenOut').textContent = '加入令牌（只显示这一次，请立刻保存）：\\n' + j.token + '\\n\\n客户端命令：\\nqp2p join ' + j.token + ' --name 设备名';
    $('newName').value=''; $('newCidr').value=''; $('newKey').value='';
    load();
  }).catch(function(e){ alert(e.message); });
};
$('addResv').onclick = function(){
  if(!current) return;
  api('/v1/admin/networks/'+current+'/reservations','POST',{ip:$('resvIp').value.trim(),node_id:$('resvNode').value.trim(),note:$('resvNote').value.trim()})
    .then(function(){ $('resvIp').value=''; $('resvNode').value=''; $('resvNote').value=''; loadNodes(current); })
    .catch(function(e){ alert(e.message); });
};
$('checkAll').onchange = function(){
  var on = this.checked;
  Array.prototype.forEach.call(document.querySelectorAll('.pick'), function(b){ b.checked = on; });
  updateKickBtn();
};
$('kickSelected').onclick = function(){
  var ids = picked(); if(!ids.length) return;
  if(!confirm('把选中的 ' + ids.length + ' 台设备踢下线？')) return;
  api('/v1/admin/networks/'+current+'/nodes/kick','POST',{node_ids:ids})
    .then(function(){ loadNodes(current); }).catch(function(e){ alert(e.message); });
};
$('exportNodes').onclick = function(){
  var rows = [['名称','虚拟IP','node_id','状态','NAT','在线时长','最后心跳','固定IP']];
  nodes.forEach(function(n){
    rows.push([n.name,n.virtual_ip,n.node_id,n.online?'在线':'离线',natLabel(n.nat_type),span(n.first_seen),new Date(n.last_seen).toLocaleString(),n.reserved?'是':'否']);
  });
  download('qp2p-members.csv', rows);
};
$('exportResv').onclick = function(){
  var rows = [['IP','node_id','类型','备注','创建时间']];
  reservations.forEach(function(r){
    rows.push([r.ip,r.node_id,r.kind==='user'?'手动':'自动',r.note||'',new Date(r.created_at).toLocaleString()]);
  });
  download('qp2p-reservations.csv', rows);
};
$('auditKind').onchange = resetAudit;
$('auditSearch').oninput = function(){
  clearTimeout(auditTimer);
  auditTimer = setTimeout(resetAudit, 250);
};
$('auditPrev').onclick = function(){ if (auditCur > 1) loadAudit(auditCur - 1); };
$('auditNext').onclick = function(){ if (auditCur < auditPages) loadAudit(auditCur + 1); };

// 打开页面：先问服务端是否已初始化账号
api('/v1/admin/status').then(function(j){
  if (j.needs_bootstrap) { showBoot(); return; }
  api('/v1/admin/me').then(function(me){ showDash(me.username); }).catch(function(){ showLogin(); });
}).catch(function(){ showLogin(); });
</script>
</body>
</html>`;

// ---------------------------------------------------------------------------
// NetworkRoom（Durable Object，每个网络一个）
// ---------------------------------------------------------------------------
//
// 网络的全部数据面（节点、预留、事件、nonce）都在这个对象的 SQLite 里。
//
// 两条硬性约束，破坏任何一条都会让休眠失效、一天烧光 13,000 GB·秒的免费时长：
//   1. 不注册任何定时器（setTimeout / setInterval / storage.setAlarm）
//   2. 不发起任何出站连接（fetch / connect）
// 清理靠惰性 sweep()：HTTP 与 WebSocket 消息入口都顺带调用，距上次满 5 分钟才执行。
//
// 设计文档：docs/signal-v3-design.md

const ROOM_SCHEMA_VERSION = 1;

// ---- WebSocket（P3） ------------------------------------------------------

const ROOM_PROTO_V = 1;
const WS_GRACE_MS = 75_000; // socket 存活判定：约 3 个 ping 周期
const PING_EVERY_MS = 25_000; // 下发给客户端的保活间隔
const WS_HANDSHAKE_MAX = 30; // 握手限流：每 IP 每分钟
const WS_MSG_MAX_BYTES = 4096; // 单条消息上限
const WS_MSG_LIMIT = 20; // 每 socket 每窗口消息数
const WS_MSG_WINDOW_MS = 10_000;
const MAX_CAPS = 16; // 客户端能力项数上限（参与握手签名，两端必须一致）

const WS_CLOSE_NORMAL = 1000;
const WS_CLOSE_SUPERSEDED = 4000; // 被同 node 的新连接替换
const WS_CLOSE_UNAUTHORIZED = 4401; // 令牌失效、被踢、密钥轮换
const WS_CLOSE_ROOM_GONE = 4410; // 网络已删除
const WS_CLOSE_RATE = 4429; // 消息限流
const WS_CLOSE_INTERNAL = 4500;

/** 下发给客户端的阈值，避免两端各写一份不一致（附录 A）。 */
const LIMITS = {
  ping_every_ms: PING_EVERY_MS,
  pong_timeout_ms: 10_000,
  ws_grace_ms: WS_GRACE_MS,
  offline_ms: OFFLINE_MS,
  heartbeat_ms: HEARTBEAT_MS,
  max_nodes: MAX_NODES,
  max_events: MAX_EVENTS,
};

const ROOM_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS nodes (
    node_id      TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    pubkey       TEXT NOT NULL,
    tls_fp       TEXT NOT NULL,
    virtual_ip   TEXT NOT NULL UNIQUE,
    nat_type     TEXT NOT NULL DEFAULT '',
    advertise    TEXT NOT NULL DEFAULT '',
    candidates   TEXT NOT NULL DEFAULT '',
    candidates_at INTEGER NOT NULL DEFAULT 0,
    last_seen    INTEGER NOT NULL,
    first_seen   INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS reservations (
    ip         TEXT PRIMARY KEY,
    node_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    to_node    TEXT NOT NULL,
    type       TEXT NOT NULL,
    payload    TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS events_to_node ON events (to_node, id)`,
  `CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
  )`,
];

export class NetworkRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.bootAt = Date.now();
    // 仅内存：socket 对象本身休眠后由 state.getWebSockets() 恢复，
    // 所以这张表只服务诊断与限流计数，丢了不影响正确性。
    this.sockets = new Map();
    this.lastSweep = 0;
    // 由 loadNet 每次请求重设：请求带来的网络上下文是否已经过期 / 属于已删除的网络
    this.stale = false;
    this.gone = false;
    this.lastCtx = null;

    // ping 由运行时自动应答：不唤醒对象、不计入请求（设计文档 §11 的容量假设依赖它）
    if (
      typeof state.setWebSocketAutoResponse === "function" &&
      typeof WebSocketRequestResponsePair === "function"
    ) {
      state.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    }

    state.blockConcurrencyWhile?.(async () => this.initSchema());
  }

  /** 幂等建表并记录 schema_version。结构演进走内部迁移，DO 类名永久冻结。 */
  initSchema() {
    for (const stmt of ROOM_SCHEMA) this.sql.exec(stmt);
    const row = this.sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").toArray()[0];
    if (!row) {
      this.sql.exec(
        "INSERT INTO meta (k, v) VALUES (?, ?)",
        "schema_version",
        String(ROOM_SCHEMA_VERSION),
      );
    }
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    try {
      // 保持网络上下文最新：Worker 换了绑定或网络改名时会带新头过来。
      // 顺带在这里判定上下文是否过期（stale 由 loadNet 设置）。
      this.loadNet(request);
      // 清理必须放在 stale 判定**之前**：删网中途失败（DO 已打墓碑、D1 行还在）时，
      // 管理员重试删除带进来的正是那块墓碑的 rev，会被判 stale。这样第二次删除
      // 永远进不来，"再删一次收尾"就成了空话。这个端点只有 Worker 鉴权后才会调。
      if (path === "/i/purge" && method === "POST") return await this.handlePurge();
      // 已删除网络的请求（含删网前 15 秒内缓存的网络行）与过期上下文（换密钥后别的
      // isolate 还拿着旧缓存）一律在这里拦掉。403 不是"稍后重试"，是"你的令牌已经
      // 不算数了"——客户端收到后应停止重连，用新令牌重新 join（设计 §5.2）。
      if (this.stale) {
        return this.gone
          ? err(403, "network_deleted", "这个网络已被删除；请从管理员那里重新获取加入密钥")
          : err(403, "stale_net_rev", "网络授权已更新，这个上下文已过期；请用最新令牌重新连接");
      }
      // 重新部署后 DO 是空的，先把 D1 里的预留捞回来再处理任何请求
      // （内部有一次性标记，正常运行时只是一次布尔判断）
      await this.ensureReservations();
      if (path === "/i/init" && method === "POST") return await this.handleInit(request);
      if (path === "/i/net-updated" && method === "POST") return await this.handleNetUpdated(request);
      if (path === "/i/stats" && method === "GET") return json(this.stats());
      if (path === "/i/debug" && method === "GET") return json(this.debug());

      // 业务端点：同一套逻辑既服务 HTTP 轮询，也服务长连接（/i/ws 握手同样落到这里验签）
      if (path === "/i/join" && method === "POST") return await this.handleJoinRegister(request, false);
      if (path === "/i/register" && method === "POST") return await this.handleJoinRegister(request, true);
      if (path === "/i/connect" && method === "POST") return await this.handleConnect(request);
      if (path === "/i/events" && method === "GET") return await this.handleEvents(request);
      if (path === "/i/leave" && method === "POST") return await this.handleLeave(request);

      // 管理面：鉴权与审计留在 Worker（控制面），这里只做数据面
      if (path === "/i/admin/nodes" && method === "GET") return this.handleAdminNodes();
      if (path === "/i/admin/kick" && method === "POST") {
        return this.handleAdminKick(await readJson(request));
      }
      if (path === "/i/admin/reservations" && method === "GET") return this.handleAdminReservations();
      if (path === "/i/admin/reserve" && method === "POST") {
        return this.handleAdminReserve(await readJson(request));
      }
      if (path === "/i/admin/release" && method === "POST") {
        return this.handleAdminRelease((await readJson(request))?.ip);
      }

      if (path === "/i/ws") return await this.acceptWs(request);
      return err(404, "not_found", `${method} ${path}`);
    } catch (e) {
      return err(500, "internal_error", e instanceof Error ? e.message : String(e));
    }
  }

  /**
   * 读 x-qp2p-net，做两件与安全相关的事，再做一次上下文同步。
   *
   * 1. **墓碑**：删网时 `/i/purge` 记下 `{id, rev}`。同一 id、rev 不超过墓碑的请求，
   *    说明它拿着删网前缓存的网络行——拒绝，否则别的 isolate 还能往已删除的网络里
   *    写节点，留下一个 D1 里查不到、管理面清不掉的孤儿网络。
   * 2. **rev 单调**：记下见过的最大 rev，比它更旧的上下文一律拒绝。这是 15 秒行缓存
   *    的安全阀——换密钥后旧令牌在旧缓存里仍然"验得过"，但它带的 rev 比 DO 见过的旧。
   *
   * 同步规则（两件事分开）：
   * - **名字 / 网段**看 `cfg_rev`，只有它更大才覆盖。改名、改网段不前进 rev（否则
   *   等于把全网踢 15 秒），所以 rev 相同不代表配置相同；反过来，别的 isolate 缓存
   *   的旧名字/旧网段 cfg_rev 更小，覆盖不了新值。
   * - **不拒绝请求**：cfg_rev 再旧也只是"不应用"，绝不因此判 stale。
   */
  loadNet(request) {
    // 每次请求重来：stale 只看这一次带来的上下文
    this.stale = false;
    this.gone = false;
    this.lastCtx = null;
    const raw = request.headers.get("x-qp2p-net");
    const cur = this.net();
    if (!raw) return cur;
    let ctx;
    try {
      ctx = JSON.parse(raw);
    } catch {
      return cur;
    }
    if (ctx.v !== 1 || !ctx.id) return cur;

    const rev = Number(ctx.rev ?? 0);
    const cfgRev = Number(ctx.cfg_rev ?? 0);
    this.lastCtx = { id: ctx.id, rev };

    const tomb = this.tombstone();
    if (tomb && tomb.id === ctx.id && rev <= Number(tomb.rev ?? 0)) {
      // 网络已删除：与"上下文过期"区分开。删网中途失败（DO 清理成功、D1 行没删掉）
      // 时也会走到这里，报"上下文已过期"会让人以为重连能好，其实要管理员再删一次。
      this.stale = true;
      this.gone = true;
      return cur;
    }

    const maxRev = Number(this.getMeta("rev", "0"));
    if (rev < maxRev) {
      this.stale = true;
      return cur;
    }
    if (rev > maxRev) this.setMeta("rev", String(rev));

    // 比整个上下文，不只比 id：改名、改网段后 DO 里的话术也得跟着变。
    // 名字/网段只在 cfg_rev 前进（或首次拿到上下文、或换了网络 id）时覆盖，避免
    // 别的 isolate 缓存里的旧值把新值改回去；rev 前进说明是更新的行，一并采用。
    const curCfg = Number(cur?.cfg_rev ?? 0);
    if (!cur || cur.id !== ctx.id || cfgRev > curCfg || rev > maxRev) {
      const next = {
        v: 1,
        id: ctx.id,
        name: ctx.name,
        cidr: ctx.cidr,
        rev,
        cfg_rev: cfgRev,
      };
      this.setMeta("net", JSON.stringify(next));
      return next;
    }
    return cur;
  }

  /** 删网墓碑：`{ id, rev }`，只在 handlePurge 时写。 */
  tombstone() {
    const raw = this.getMeta("deleted");
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      return parsed && parsed.id ? parsed : null;
    } catch {
      return null;
    }
  }

  net() {
    const row = this.sql.exec("SELECT v FROM meta WHERE k = 'net'").toArray()[0];
    if (!row) return null;
    try {
      return JSON.parse(row.v);
    } catch {
      return null;
    }
  }

  setMeta(k, v) {
    this.sql.exec(
      "INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
      k,
      String(v),
    );
  }

  getMeta(k, fallback = null) {
    const row = this.sql.exec("SELECT v FROM meta WHERE k = ?", k).toArray()[0];
    return row ? row.v : fallback;
  }

  async handleInit(request) {
    const body = await request.json().catch(() => null);
    if (!body || !body.net || !body.net.id) return err(400, "invalid_json");
    const prev = this.net();
    this.setMeta("net", JSON.stringify(body.net));
    // 初始化同样要把 rev 记成"见过的最大值"，否则首次部署后旧缓存送来的
    // 低 rev 上下文反而不受约束
    const initRev = Number(body.net.rev ?? 0);
    if (initRev > Number(this.getMeta("rev", "0"))) this.setMeta("rev", String(initRev));
    // 同一个 DO 换了网络 id：旧连接的上下文已经不对，直接关掉让客户端重新握手，
    // 恢复标记也要重来（新网络对应 D1 里另一批预留）
    if (prev && prev.id !== body.net.id) {
      this.closeAll(WS_CLOSE_ROOM_GONE, "network reinit");
      this.sql.exec("DELETE FROM meta WHERE k = 'reservations_restored'");
      this._reservationsReady = false;
    }
    this.sweepNow();
    return json({ ok: true, schema_version: ROOM_SCHEMA_VERSION });
  }

  /** 网络改名 / 改网段。reassign=true 时把落到新网段外的节点重新分配。 */
  async handleNetUpdated(request) {
    const body = await request.json().catch(() => null);
    if (!body || !body.net || !body.net.id) return err(400, "invalid_json");

    // rev 必须一路带进来：换密钥时 Worker 先写了 D1（rev 前进），这里的 maxRev
    // 要立刻跟上，之后拿着 15 秒旧缓存送来的旧 rev 才会被 loadNet 拒掉。
    const rev = Number(body.net.rev ?? 0);
    const cfgRev = Number(body.net.cfg_rev ?? 0);
    const cur = this.net();
    // 同一个网络、cfg_rev 却比手里的小：这是一次滞后的推送（并发改两次、或重试比
    // 首次还慢），应用它会把名字/网段、节点地址一起改回去。忽略配置部分。
    // 换密钥（close=true）不受影响：那条路径 rev 一定前进、cfg_rev 不变。
    const lagging = Boolean(cur) && cur.id === body.net.id && cfgRev < Number(cur.cfg_rev ?? 0);
    const net = lagging
      ? cur
      : {
          v: 1,
          id: body.net.id,
          name: body.net.name,
          cidr: body.net.cidr,
          rev,
          cfg_rev: cfgRev,
        };
    if (!lagging) this.setMeta("net", JSON.stringify(net));
    if (rev > Number(this.getMeta("rev", "0"))) this.setMeta("rev", String(rev));

    let reassigned = 0;
    if (body.reassign === true && !lagging) {
      const nodes = this.listNodes();
      for (const node of nodes) {
        if (ipInCidr(net.cidr, node.virtual_ip)) continue;
        const oldIp = node.virtual_ip;
        const fresh = await assignIp(net, node.node_id, nodes, []);
        this.deleteReservation(oldIp);
        node.virtual_ip = fresh;
        this.putNode(node);
        this.putReservation({
          ip: fresh,
          node_id: node.node_id,
          kind: "auto",
          note: "网段变更后重新分配",
          created_at: Date.now(),
        });
        reassigned += 1;
      }
      // 落在新网段外的预留不可能再生效，一并清掉
      for (const r of this.listReservations()) {
        if (!ipInCidr(net.cidr, r.ip)) this.deleteReservation(r.ip);
      }
    }

    // 换密钥：旧令牌必须立刻作废。只改 D1 的话，已经握上手的 socket 不受影响，
    // 攻击者能一直用旧连接撮合（新握手才会被拒）。设计 §5.2/§6.3 要求 closeAll(4401)。
    if (body.close === true) {
      this.closeAll(WS_CLOSE_UNAUTHORIZED, "join key rotated");
    }

    return json({ ok: true, reassigned });
  }

  async handlePurge() {
    const removed = this.listNodes().length;
    // 先遣散连接：网络被删了还挂着的 socket 只会不停重连
    this.closeAll(WS_CLOSE_ROOM_GONE, "network purged");
    for (const table of ["nodes", "reservations", "events", "nonces"]) {
      this.sql.exec(`DELETE FROM ${table}`);
    }
    // epoch 一起清掉：重建后会换新的，客户端据此判断本地 cursor 已失效。
    // 恢复标记也要清，否则重建网络后不会再从 D1 捞预留。
    this.sql.exec(
      "DELETE FROM meta WHERE k IN ('net', 'epoch', 'reservations_restored')",
    );
    this._reservationsReady = false;

    // 墓碑：记下删网时的 rev。别的 isolate 还缓存着这张网络行（最多 15 秒），
    // 不带墓碑的话它们仍能 join，在 DO 里凭空造出一批"D1 里没有"的节点。
    // 重建同名网络会拿到更大的 rev，墓碑不会误伤。
    const ctx = this.lastCtx;
    if (ctx?.id) {
      this.setMeta("deleted", JSON.stringify({ id: ctx.id, rev: Number(ctx.rev ?? 0), at: Date.now() }));
    }
    return json({ ok: true, removed });
  }

  /** 统计：节点、在线、socket、预留、事件。 */
  stats() {
    const now = Date.now();
    const idx = this.socketIndex();
    const nodes = this.listNodes();
    const count = (table) => this.sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).toArray()[0]?.n ?? 0;
    let onlineWs = 0;
    let onlinePoll = 0;
    for (const n of nodes) {
      const ws = idx.get(n.node_id);
      if (ws) {
        const stamp = this.autoResponseAt(ws) ?? this.attachment(ws).joinedAt ?? now;
        if (now - stamp <= WS_GRACE_MS) onlineWs += 1;
      } else if (now - n.last_seen <= OFFLINE_MS) {
        onlinePoll += 1;
      }
    }
    return {
      ok: true,
      nodes: nodes.length,
      online: onlineWs + onlinePoll,
      online_ws: onlineWs,
      online_poll: onlinePoll,
      sockets: idx.size,
      reservations: count("reservations"),
      events: count("events"),
      schema_version: ROOM_SCHEMA_VERSION,
    };
  }

  debug() {
    const now = Date.now();
    return {
      ok: true,
      bootAt: this.bootAt,
      schema_version: ROOM_SCHEMA_VERSION,
      net: this.net(),
      epoch: this.epoch(),
      sockets: (this.state.getWebSockets?.() ?? []).map((ws) => {
        const a = this.attachment(ws);
        const pingAt = this.autoResponseAt(ws);
        return {
          node: a.node ?? null,
          joinedAt: a.joinedAt ?? null,
          caps: a.caps ?? [],
          lastPingAt: pingAt,
          alive: pingAt === null ? null : now - pingAt <= WS_GRACE_MS,
        };
      }),
      lastSweep: this.lastSweep,
    };
  }

  /** 惰性 GC 入口：HTTP 与 WebSocket 消息路径都要调，距上次满 5 分钟才真正执行。 */
  sweep() {
    // last_sweep 必须从 meta 读回：对象休眠后内存全丢，只留这个字段为 0 的话，
    // 每次唤醒都会白跑一轮 GC（多写一条 meta，也违背容量估算）。
    if (this.lastSweep === 0) this.lastSweep = Number(this.getMeta("last_sweep", 0)) || 0;
    if (Date.now() - this.lastSweep < SWEEP_INTERVAL_MS) return;
    this.sweepNow();
  }

  sweepNow(now = Date.now()) {
    this.lastSweep = now;
    this.setMeta("last_sweep", String(now));

    this.sql.exec("DELETE FROM events WHERE created_at < ?", now - EVENT_TTL_MS);
    this.sql.exec("DELETE FROM nonces WHERE created_at < ?", now - EVENT_TTL_MS);

    // 僵尸节点：10 分钟没心跳、且当前没有活跃 socket
    const alive = new Set(
      (this.state.getWebSockets?.() ?? [])
        .map((ws) => ws.deserializeAttachment?.()?.node)
        .filter(Boolean),
    );
    const stale = this.sql.exec("SELECT node_id FROM nodes WHERE last_seen < ?", now - NODE_TTL_MS).toArray();
    for (const row of stale) {
      if (alive.has(row.node_id)) continue;
      this.sql.exec("DELETE FROM nodes WHERE node_id = ?", row.node_id);
      this.sql.exec("DELETE FROM reservations WHERE node_id = ? AND kind = 'auto'", row.node_id);
    }
  }

  // ---- 存储访问（SQLite 版，对应 legacy 那组 D1 函数） ----------------------

  listNodes() {
    return this.sql.exec("SELECT * FROM nodes").toArray();
  }

  getNode(nodeId) {
    return this.sql.exec("SELECT * FROM nodes WHERE node_id = ?", nodeId).toArray()[0] ?? null;
  }

  putNode(n) {
    this.sql.exec(
      `INSERT INTO nodes (node_id, name, pubkey, tls_fp, virtual_ip, nat_type, advertise,
                          candidates, candidates_at, last_seen, first_seen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(node_id) DO UPDATE SET
         name = excluded.name,
         tls_fp = excluded.tls_fp,
         virtual_ip = excluded.virtual_ip,
         nat_type = excluded.nat_type,
         advertise = excluded.advertise,
         candidates = excluded.candidates,
         candidates_at = excluded.candidates_at,
         last_seen = excluded.last_seen`,
      n.node_id, n.name, n.pubkey, n.tls_fp, n.virtual_ip, n.nat_type,
      n.advertise, n.candidates, n.candidates_at, n.last_seen, n.first_seen,
    );
  }

  deleteNode(nodeId) {
    this.sql.exec("DELETE FROM nodes WHERE node_id = ?", nodeId);
  }

  touchNode(nodeId, now) {
    this.sql.exec("UPDATE nodes SET last_seen = ? WHERE node_id = ?", now, nodeId);
  }

  listReservations() {
    return this.sql.exec("SELECT * FROM reservations").toArray();
  }

  putReservation(r) {
    this.sql.exec(
      `INSERT INTO reservations (ip, node_id, kind, note, created_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(ip) DO UPDATE SET
         node_id = excluded.node_id, kind = excluded.kind, note = excluded.note`,
      r.ip, r.node_id, r.kind, r.note ?? "", r.created_at,
    );
    this.backupReservation(r);
  }

  deleteReservation(ip) {
    this.sql.exec("DELETE FROM reservations WHERE ip = ?", ip);
    this.backupRelease(ip);
  }

  dropAutoReservations(nodeId) {
    this.sql.exec("DELETE FROM reservations WHERE node_id = ? AND kind = 'auto'", nodeId);
    this.backupDropAuto(nodeId);
  }

  // ---- D1 备份：重新部署后 DO 是空的，靠这份数据把预留捞回来 ---------------
  //
  // 单向以 DO 为准（D1 只是副本）：DO 里改了什么就往 D1 写什么。
  // 用 waitUntil 而不是 await，避免把一次预留变更变成两次往返。

  backupSql(sql, ...args) {
    const db = this.env?.DB;
    const net = this.net();
    if (!db || !net) return;
    // 用 Promise.resolve().then 包一层：本地替身（fakeD1）的 run() 是同步返回的，
    // 直接 .catch 会报 "run(...).catch is not a function"
    const p = Promise.resolve()
      .then(() => db.prepare(sql).bind(...args).run())
      .catch((e) => console.warn(`[room] 预留备份失败：${e}`));
    // 构造期 / 本地替身上没有 waitUntil，退化成"发出去就不管"
    if (typeof this.state.waitUntil === "function") this.state.waitUntil(p);
    else p.catch(() => {});
  }

  backupReservation(r) {
    this.backupSql(
      `INSERT INTO reservations (network_id, ip, node_id, kind, note, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(network_id, ip) DO UPDATE SET
         node_id = excluded.node_id, kind = excluded.kind, note = excluded.note`,
      this.net()?.id ?? "", r.ip, r.node_id, r.kind, r.note ?? "", r.created_at,
    );
  }

  backupRelease(ip) {
    this.backupSql(
      "DELETE FROM reservations WHERE network_id = ? AND ip = ?",
      this.net()?.id ?? "",
      ip,
    );
  }

  backupDropAuto(nodeId) {
    this.backupSql(
      "DELETE FROM reservations WHERE network_id = ? AND node_id = ? AND kind = 'auto'",
      this.net()?.id ?? "",
      nodeId,
    );
  }

  /**
   * 从 D1 恢复预留。只在 DO 首次带网络上下文运行时做一次。
   *
   * 用 `blockConcurrencyWhile` 包住：恢复期间不能让别的请求看到"半套预留"，
   * 否则会把它正在用的地址当成空闲分给别人。
   */
  async ensureReservations() {
    if (this._reservationsReady) return;
    if (this.getMeta("reservations_restored") === "1") {
      this._reservationsReady = true;
      return;
    }
    const restore = async () => {
      const net = this.net();
      const db = this.env?.DB;
      if (!net || !db) return false;
      try {
        const { results } = await db
          .prepare(
            "SELECT ip, node_id, kind, note, created_at FROM reservations WHERE network_id = ?",
          )
          .bind(net.id)
          .all();
        const rows = results ?? [];
        for (const r of rows) {
          // DO 里已有的不覆盖：它比 D1 新
          this.sql.exec(
            `INSERT INTO reservations (ip, node_id, kind, note, created_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(ip) DO NOTHING`,
            r.ip, r.node_id, r.kind, r.note ?? "", Number(r.created_at) || Date.now(),
          );
        }
        this.setMeta("reservations_restored", "1");
        if (rows.length > 0) console.log(`[room] 从 D1 恢复了 ${rows.length} 条预留`);
        return true;
      } catch (e) {
        console.warn(`[room] 恢复预留失败，下次再试：${e}`);
        return false;
      }
    };

    const ok =
      typeof this.state.blockConcurrencyWhile === "function"
        ? await this.state.blockConcurrencyWhile(restore)
        : await restore();
    this._reservationsReady = ok === true;
  }

  /**
   * 写一条事件并返回 seq；同时直投给目标在线 socket。
   *
   * v3.0 一律落库（B1「有 socket 就不落库」留作后续优化）：落库才能让断线重连
   * 用 since 补齐。直投只是省掉一轮 wakeup 延迟，不是替代。
   */
  emit(to, type, payload) {
    const data = payload ?? {};
    this.sql.exec(
      "INSERT INTO events (to_node, type, payload, created_at) VALUES (?, ?, ?, ?)",
      to, type, JSON.stringify(data), Date.now(),
    );
    const seq = this.sql.exec("SELECT last_insert_rowid() AS id").toArray()[0].id;

    const msg = wsEvent(seq, type, data);
    if (to === BROADCAST) {
      for (const ws of this.state.getWebSockets?.() ?? []) this.deliver(ws, msg);
    } else {
      const ws = this.socketIndex().get(to);
      if (ws) this.deliver(ws, msg);
    }
    return seq;
  }

  /** 踢人时清掉这个节点待投递的事件。 */
  dropNodeEvents(nodeId) {
    this.sql.exec("DELETE FROM events WHERE to_node = ?", nodeId);
  }

  pullEvents(nodeId, since, limit, minCreatedAt = 0) {
    return this.sql.exec(
      `SELECT * FROM events
        WHERE (to_node = ? OR to_node = '*') AND id > ? AND created_at >= ?
        ORDER BY id LIMIT ?`,
      nodeId, since, minCreatedAt, limit,
    ).toArray();
  }

  consumeNonce(key, now) {
    const seen = this.sql.exec("SELECT 1 AS x FROM nonces WHERE nonce = ?", key).toArray().length > 0;
    if (seen) return false;
    this.sql.exec("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)", key, now);
    return true;
  }

  /**
   * 在线判定。
   *
   * 有 socket：看自动应答时间戳（没收到过 ping 就用 joinedAt），距现在不超过
   * WS_GRACE_MS 即存活。这条**完全依赖 V9** —— 时间戳不刷新的话所有 WS 节点
   * 会被同时判成离线，所以真机验证必做（见 ctl 的 room-probe）。
   * 无 socket：沿用 last_seen 与 OFFLINE_MS，与 legacy 一致。
   */
  liveness(node, now) {
    const ws = this.socketIndex().get(node.node_id);
    if (ws) {
      const stamp = this.autoResponseAt(ws) ?? this.attachment(ws).joinedAt ?? now;
      const idleMs = Math.max(0, now - stamp);
      return { online: idleMs <= WS_GRACE_MS, via: "ws", idleMs };
    }
    const idleMs = now - node.last_seen;
    return { online: idleMs <= OFFLINE_MS, via: "poll", idleMs };
  }

  /**
   * 撮合：校验对端可连并投递 punch_request。HTTP 与 WebSocket 两条路径共用，
   * 差别只在「身份怎么来」——HTTP 逐条验签，WS 取 socket attachment。
   */
  matchmake(from, target, { commit = true } = {}) {
    if (!/^[0-9a-f]{32}$/.test(from) || !/^[0-9a-f]{32}$/.test(target)) {
      return { ok: false, status: 400, error: "invalid_node_id", detail: "node_id 必须是 32 位十六进制" };
    }
    if (from === target) return { ok: false, status: 400, error: "self_connect", detail: "不能连自己" };

    const now = Date.now();
    const self = this.getNode(from);
    if (!self) return { ok: false, status: 404, error: "unknown_node", detail: "发起方尚未注册" };

    const peer = this.getNode(target);
    if (!peer) return { ok: false, status: 404, error: "target_not_found", detail: "对端不在这个网络里" };
    const live = this.liveness(peer, now);
    if (!live.online) {
      return { ok: false, status: 410, error: "target_offline", detail: "对端心跳已超时" };
    }

    // 地址新鲜度：两种传输的"存活证据"不同，不能共用 last_seen。
    // - 长连接节点：socket 活着就证明它还在原地，地址视为新鲜。客户端换网后会重新
    //   register（候选地址变化即强制上报），所以不需要按时间卡它。
    // - 轮询节点：events 每 55 秒写一次 last_seen，超过 STALE_MS 说明可能刚换网。
    // 曾经这里一律比 last_seen，而 WS 节点只在 register 时写（间隔 2 小时），
    // 于是长连接建好约两分钟后，任何人都撮合不到它（报 target_stale）。
    if (live.via === "poll") {
      const targetAge = now - peer.last_seen;
      if (targetAge > Number(this.env.STALE_MS ?? STALE_MS)) {
        return {
          ok: false,
          status: 409,
          error: "target_stale",
          detail: `对端 ${Math.round(targetAge / 1000)} 秒没有刷新地址，可能刚换网；稍后重试`,
        };
      }
    }

    const peerCandidates = safeParseArray(peer.candidates);
    if (peerCandidates.length === 0) {
      return { ok: false, status: 409, error: "target_no_candidates", detail: "对端还没有上报候选地址" };
    }

    const t = now + 500;
    // commit=false 只做预检：HTTP 路径要先把 nonce 占掉才允许产生副作用
    if (commit) this.emit(target, "punch_request", {
      from,
      from_name: self.name,
      virtual_ip: self.virtual_ip,
      candidates: safeParseArray(self.candidates),
      t,
      server_ms: now,
    });

    return {
      ok: true,
      reply: {
        t,
        target_last_seen: peer.last_seen,
        target_candidates: peerCandidates,
        target_virtual_ip: peer.virtual_ip,
        target_tls_fp: peer.tls_fp,
        server_ms: now,
      },
    };
  }

  // ---- 验签（与 legacy 的 verifySignedRequest 同规则，nonce 落 SQLite） ------

  async verifyReq({ op, body, pubkey, now, trackReplay }) {
    const network = this.net();
    if (!network) return "缺少网络上下文";

    const stamp = Number(body?.ts);
    if (!Number.isFinite(stamp)) return "缺少 ts（毫秒时间戳）";
    if (Math.abs(now - stamp) > TS_WINDOW_MS) return "ts 超出 ±120 秒窗口";

    const nonce = String(body?.nonce ?? "").toLowerCase();
    if (!/^[0-9a-f]{16,64}$/.test(nonce)) return "nonce 必须是 16~64 位十六进制";

    let digest;
    try {
      digest = await bodyDigest(body);
    } catch (e) {
      return `请求体无法规范化：${e instanceof Error ? e.message : String(e)}`;
    }
    const message = signingMessage(op, network.id, stamp, nonce, digest);
    const mismatch = await verifySignature(pubkey, message, body?.sig);
    if (mismatch) return mismatch;

    if (trackReplay && !this.consumeNonce(`${network.id}:${nonce}`, now)) {
      return "nonce 已用过（疑似重放）";
    }
    return null;
  }

  // ---- 业务（移植 legacy 的同名逻辑，D1 换 SQLite） -------------------------

  /** join（needCandidates=false）与 register（true）共用：语义与 legacy 逐字一致。 */
  async handleJoinRegister(request, needCandidates) {
    this.sweep();
    const network = this.net();
    if (!network) return err(503, "room_unavailable", "这个 DO 还没有网络上下文");

    const body = await readJson(request);
    if (body === null) return err(400, "invalid_json");

    const nodeId = String(body.node_id ?? "").toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(nodeId)) {
      return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
    }

    const pubkey = String(body.pubkey ?? "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pubkey)) {
      return err(400, "invalid_pubkey", "pubkey 必须是 64 位十六进制（32 字节 Ed25519 公钥）");
    }
    if ((await sha256Hex(hexToBytes(pubkey))).slice(0, 32) !== nodeId) {
      return err(403, "node_id_mismatch", "node_id 必须等于 sha256(pubkey)[..32]");
    }

    const candidates = parseCandidates(body.candidates);
    if (candidates === null) {
      return err(400, "invalid_candidates", `候选地址必须是合法 ip:port，最多 ${MAX_CANDIDATES} 个`);
    }
    if (needCandidates && candidates.length === 0) {
      return err(400, "missing_candidates", "register 至少需要一个候选地址");
    }

    const now = Date.now();
    // join / register 幂等：不占 nonce（省两次写入），与 legacy 一致
    const bad = await this.verifyReq({
      op: needCandidates ? "register" : "join",
      body,
      pubkey,
      now,
      trackReplay: false,
    });
    if (bad) return err(403, "bad_signature", bad);

    let others = this.listNodes();
    const existing = others.find((n) => n.node_id === nodeId) ?? null;
    if (!existing && others.length >= MAX_NODES) {
      const victim = others
        .filter((n) => now - n.last_seen > OFFLINE_MS)
        .sort((a, b) => a.last_seen - b.last_seen)[0];
      if (!victim) {
        return err(507, "network_full", `每个网络上限 ${MAX_NODES} 个节点，且都在线`);
      }
      this.deleteNode(victim.node_id);
      console.warn(`[room] 淘汰僵尸节点 ${victim.node_id}`);
      others = others.filter((n) => n.node_id !== victim.node_id);
    }

    const reservations = this.listReservations();

    const requested =
      body.virtual_ip === undefined || body.virtual_ip === null
        ? null
        : String(body.virtual_ip).trim();
    if (requested !== null) {
      const badIp = validateVirtualIp(network, requested, nodeId, others, reservations);
      if (badIp) return badIp;
    }

    // 优先级：这次指定 > 已有记录 > 自己的预留 > 自动分配
    let virtualIp = requested ?? existing?.virtual_ip ?? null;
    if (!virtualIp) {
      const mine = reservations.find((r) => r.node_id === nodeId);
      const stolen = mine && others.some((n) => n.node_id !== nodeId && n.virtual_ip === mine.ip);
      if (mine && !stolen) virtualIp = mine.ip;
    }
    if (!virtualIp || !ipInCidr(network.cidr, virtualIp)) {
      virtualIp = await assignIp(network, nodeId, others, reservations);
    }

    const oldRes = reservations.find((r) => r.node_id === nodeId && r.ip !== virtualIp);
    if (oldRes) this.deleteReservation(oldRes.ip);
    if (!reservations.some((r) => r.ip === virtualIp && r.node_id === nodeId)) {
      this.putReservation({
        ip: virtualIp,
        node_id: nodeId,
        kind: requested !== null ? "user" : "auto",
        note: reservations.find((r) => r.ip === virtualIp)?.note ?? "",
        created_at: now,
      });
    }

    const record = {
      node_id: nodeId,
      name: String(body.name ?? existing?.name ?? nodeId.slice(0, 8)).slice(0, 48),
      pubkey,
      tls_fp: String(body.tls_fp ?? existing?.tls_fp ?? "").slice(0, 128),
      virtual_ip: virtualIp,
      nat_type: String(body.nat_type ?? existing?.nat_type ?? "unknown").slice(0, 16),
      advertise: JSON.stringify(
        Array.isArray(body.advertise)
          ? body.advertise.slice(0, 8).map(String)
          : JSON.parse(existing?.advertise ?? "[]"),
      ),
      candidates: JSON.stringify(
        candidates.length > 0 ? candidates : JSON.parse(existing?.candidates ?? "[]"),
      ),
      // 地址最后上报时间与 last_seen 分开：换网判断看这个
      candidates_at: candidates.length > 0 ? now : Number(existing?.candidates_at ?? 0),
      last_seen: now,
      first_seen: Number(existing?.first_seen ?? 0) || now,
    };

    try {
      this.putNode(record);
    } catch (e) {
      // virtual_ip 有 UNIQUE 约束：并发下两个节点同时算到同一地址的概率极低，但一旦发生要让调用方重试
      return err(409, "virtual_ip_taken", `地址 ${virtualIp} 刚被占用，重试一次：${e instanceof Error ? e.message : String(e)}`);
    }

    const wasOnline = existing !== null && now - existing.last_seen <= OFFLINE_MS;
    const moved = existing !== null && existing.candidates !== record.candidates;
    if ((!wasOnline || moved) && safeParseArray(record.candidates).length > 0) {
      this.emit(BROADCAST, "peer_online", publicNode(record, now));
    }

    const peers = others.filter((n) => n.node_id !== nodeId).map((n) => publicNode(n, now));

    return json({
      ok: true,
      network: { id: network.id, name: network.name, cidr: network.cidr },
      node: { node_id: nodeId, virtual_ip: virtualIp, name: record.name },
      peers,
      durable: true,
      server_ms: now,
    });
  }

  async handleConnect(request) {
    this.sweep();
    const network = this.net();
    if (!network) return err(503, "room_unavailable", "这个 DO 还没有网络上下文");

    const body = await readJson(request);
    if (body === null) return err(400, "invalid_json");

    const from = String(body.from ?? "").toLowerCase();
    const target = String(body.target ?? "").toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(from) || !/^[0-9a-f]{32}$/.test(target)) {
      return err(400, "invalid_node_id", "from 与 target 都必须是 32 位十六进制 node_id");
    }
    if (from === target) return err(400, "self_connect", "不能连自己");

    const now = Date.now();
    const self = this.getNode(from);
    if (!self) return err(404, "unknown_node", "发起方尚未注册");

    const bad = await this.verifyReq({
      op: "connect",
      body,
      pubkey: self.pubkey,
      now,
      trackReplay: false,
    });
    if (bad) return err(403, "bad_signature", bad);

    // 先做无副作用的可连性预检，通过了才占 nonce（与 legacy 一致）
    const pre = this.matchmake(from, target, { commit: false });
    if (!pre.ok) return err(pre.status, pre.error, pre.detail);

    const nonce = String(body.nonce ?? "").toLowerCase();
    if (!this.consumeNonce(`${network.id}:${nonce}`, now)) {
      return err(403, "bad_signature", "nonce 已用过（疑似重放）");
    }

    const done = this.matchmake(from, target);
    if (!done.ok) return err(done.status, done.error, done.detail);
    return json({ ok: true, ...done.reply });
  }

  async handleEvents(request) {
    this.sweep();
    const network = this.net();
    if (!network) return err(503, "room_unavailable", "这个 DO 还没有网络上下文");

    const url = new URL(request.url);
    const nodeId = (url.searchParams.get("node_id") ?? "").toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(nodeId)) {
      return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
    }
    const since = Math.max(0, Number(url.searchParams.get("since") ?? 0) || 0);

    const now = Date.now();
    const node = this.getNode(nodeId);
    if (!node) return err(404, "unknown_node", "先 register 再拉事件");

    // GET 没有请求体：把参与签名的查询参数拼成同样结构再算摘要
    const signedBody = {
      node_id: nodeId,
      since,
      ts: Number(url.searchParams.get("ts")),
      nonce: url.searchParams.get("nonce"),
    };
    const bad = await this.verifyReq({
      op: "events",
      body: { ...signedBody, sig: url.searchParams.get("sig") },
      pubkey: node.pubkey,
      now,
      trackReplay: false,
    });
    if (bad) return err(403, "bad_signature", bad);

    // 签名用的是客户端发来的 since，校验通过后再钳制：换引擎后旧游标会大于
    // 当前最大 seq，不钳制的话客户端会一直拿到空列表（只能靠重启自愈）。
    const from = this.clampSince(since);

    const wasOffline = now - node.last_seen > OFFLINE_MS;
    if (now - node.last_seen >= HEARTBEAT_MS) this.touchNode(nodeId, now);

    const minCreatedAt = from === 0 ? now - 30_000 : 0;
    const rows = this.pullEvents(nodeId, from, MAX_EVENTS, minCreatedAt);
    const cursor = rows.length > 0 ? rows[rows.length - 1].id : from;

    if (wasOffline && safeParseArray(node.candidates).length > 0) {
      this.emit(BROADCAST, "peer_online", publicNode({ ...node, last_seen: now }, now));
    }

    return json({
      ok: true,
      cursor,
      events: rows.map((r) => ({ seq: r.id, type: r.type, ...safeParse(r.payload) })),
      server_ms: now,
    });
  }

  async handleLeave(request) {
    this.sweep();
    const network = this.net();
    if (!network) return err(503, "room_unavailable", "这个 DO 还没有网络上下文");

    const body = await readJson(request);
    if (body === null) return err(400, "invalid_json");

    const nodeId = String(body.node_id ?? "").toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(nodeId)) {
      return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
    }

    const pubkey = String(body.pubkey ?? "").toLowerCase();
    if (
      !/^[0-9a-f]{64}$/.test(pubkey) ||
      (await sha256Hex(hexToBytes(pubkey))).slice(0, 32) !== nodeId
    ) {
      return err(403, "node_id_mismatch", "leave 需要提供与 node_id 对应的 pubkey");
    }

    const bad = await this.verifyReq({
      op: "leave",
      body,
      pubkey,
      now: Date.now(),
      trackReplay: true,
    });
    if (bad) return err(403, "bad_signature", bad);

    // 预留不删：手填的地址在节点离线后仍然归它（与 legacy 一致）
    const node = this.getNode(nodeId);
    this.deleteNode(nodeId);

    // 主动下线要立刻让对端知道，否则它们只能等 liveness 超时（100 多秒）。
    // 同时把这条连接的 socket 关掉：HTTP leave 之后它已经没有任何资格继续撮合。
    this.announceOffline(nodeId, node?.name);
    const ws = this.socketIndex().get(nodeId);
    if (ws) {
      try {
        ws.close(WS_CLOSE_NORMAL, "bye");
      } catch {}
    }
    return json({ ok: true });
  }

  // ---- WebSocket（P3） -----------------------------------------------------

  /**
   * `GET /i/ws` 握手。
   *
   * 签名摘要固定为 `canonicalJson({node_id, since, ts, nonce, caps})`，
   * 其中 **caps 是排序后逗号拼接的字符串**：两边只需要对一个字符串，
   * 比数组的序列化形状好对齐（Rust 与 JS 的数组序列化差异是踩过的坑）。
   */
  async acceptWs(request) {
    this.sweep();
    const network = this.net();
    if (!network) return err(503, "room_unavailable", "这个 DO 还没有网络上下文");

    const url = new URL(request.url);
    const nodeId = (url.searchParams.get("node_id") ?? "").toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(nodeId)) {
      return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
    }
    const since = Math.max(0, Number(url.searchParams.get("since") ?? 0) || 0);
    const capsRaw = (url.searchParams.get("caps") ?? "").trim();
    const caps = capsRaw
      ? capsRaw
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean)
          .sort()
      : [];
    // 不能用 slice 截断：客户端签的是全量 caps，截断后摘要对不上，
    // 表现为「bad_signature」，排查时根本想不到是条数问题。
    if (caps.length > MAX_CAPS) {
      return err(400, "too_many_caps", `caps 最多 ${MAX_CAPS} 项，收到 ${caps.length} 项`);
    }

    const now = Date.now();
    const node = this.getNode(nodeId);
    // 节点必须先由 HTTP join/register 登记：公钥在那条记录里
    if (!node) return err(404, "unknown_node", "先 register 再连 WebSocket");

    const bad = await this.verifyReq({
      op: "ws",
      body: {
        node_id: nodeId,
        since,
        ts: Number(url.searchParams.get("ts")),
        nonce: url.searchParams.get("nonce"),
        caps: caps.join(","),
        sig: url.searchParams.get("sig"),
      },
      pubkey: node.pubkey,
      now,
      trackReplay: false,
    });
    if (bad) return err(403, "bad_signature", bad);

    if (!this.consumeNonce(`${network.id}:${url.searchParams.get("nonce")}`, now)) {
      return err(403, "bad_signature", "nonce 已用过（疑似重放）");
    }

    const wasOffline = !this.socketIndex().has(nodeId) && now - node.last_seen > OFFLINE_MS;

    // 同一 node 只留一条 socket：旧连接以 4000 关掉。
    // 客户端必须按「连接代次」处理这条码，否则自己的重连会被这条 4000 误停（§5.2）。
    const existing = this.socketIndex().get(nodeId);
    if (existing) {
      try {
        existing.close(WS_CLOSE_SUPERSEDED, "superseded");
      } catch {
        // 半开的 socket 关不掉是常态，不影响新连接
      }
    }

    if (typeof WebSocketPair !== "function") {
      return err(503, "room_unavailable", "运行时没有 WebSocketPair");
    }
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    const attachment = { node: nodeId, joinedAt: now, caps, v: ROOM_PROTO_V };
    server.serializeAttachment(attachment);
    if (typeof this.state.acceptWebSocket === "function") {
      this.state.acceptWebSocket(server, [nodeId]);
    } else {
      server.accept();
    }

    // 发数据要用服务端那一端（pair[1]）：pair[0] 是交给调用方的客户端对象
    this.send(server, {
      t: "hello",
      v: ROOM_PROTO_V,
      server_ms: now,
      cursor: this.maxSeq(),
      epoch: this.epoch(),
      limits: LIMITS,
    });

    // 断线重连：把离线期间攒的事件补齐，客户端不必再发一次 resume
    if (since > 0) this.replay(server, nodeId, since);

    if (wasOffline && safeParseArray(node.candidates).length > 0) {
      this.emit(BROADCAST, "peer_online", publicNode({ ...node, last_seen: now }, now));
    }

    return upgradeResponse(client);
  }

  /**
   * 补发 seq 大于 since 的事件（最多 MAX_EVENTS 条、只在事件 TTL 内）。
   *
   * since 一律先过 clampSince：换引擎（D1 自增 id → DO 的 seq）或数据被重建后，
   * 客户端手里的游标会大于当前最大 seq，那时它永远拿不到事件，只能靠重启自愈。
   */
  replay(ws, nodeId, since) {
    const from = this.clampSince(since);
    const rows = this.pullEvents(nodeId, from, MAX_EVENTS, Date.now() - EVENT_TTL_MS);
    for (const r of rows) {
      this.send(ws, wsEvent(r.id, r.type, safeParse(r.payload)));
    }
    return rows.length > 0 ? rows[rows.length - 1].id : from;
  }

  async webSocketMessage(ws, raw) {
    // sweep 也挂在这里：B4 取消定时 register 后，纯 WS 网络没有别的 HTTP 入口，
    // 漏掉这一处 events 与僵尸节点就永不回收。WS 消息本来就要唤醒 DO，不额外增加唤醒。
    this.sweep();

    if (typeof raw !== "string") return; // 二进制帧一律忽略
    // 上限是**字节**数：raw.length 是 UTF-16 码元，一个汉字只算 1，会低估三倍
    if (new TextEncoder().encode(raw).length > WS_MSG_MAX_BYTES) {
      try {
        ws.close(WS_CLOSE_RATE, "message too large");
      } catch {}
      return;
    }
    if (!this.allow(ws)) {
      try {
        ws.close(WS_CLOSE_RATE, "rate limited");
      } catch {}
      return;
    }

    let m;
    try {
      m = JSON.parse(raw);
    } catch {
      return; // 非法 JSON 静默忽略：不值得为一次坏帧断连
    }
    if (!m || typeof m.t !== "string") return;

    const a = this.attachment(ws);
    const nodeId = a.node;
    if (!nodeId) return;

    if (m.t === "connect") return this.onConnectMsg(ws, nodeId, m);
    if (m.t === "resume") return this.onResumeMsg(ws, nodeId, m);
    if (m.t === "leave") {
      // 主动下线：不留 last_seen 宽限，直接当离线，并立刻告诉声明的对端
      const node = this.getNode(nodeId);
      this.deleteNode(nodeId);
      this.announceOffline(nodeId, node?.name, ws);
      try {
        ws.close(WS_CLOSE_NORMAL, "bye");
      } catch {}
      return;
    }
  }

  /** socket 身份直接撮合，不再逐条验签（身份已在握手时确认）。 */
  onConnectMsg(ws, nodeId, m) {
    const req = m.req ?? null;
    const target = String(m.target ?? "").toLowerCase();
    const r = this.matchmake(nodeId, target);
    if (!r.ok) return this.send(ws, { t: "error", req, error: r.error, detail: r.detail });
    // 与 throw 一致：载荷里的 t（打洞时间）在 WS 侧叫 punch_at，不覆盖消息类型
    const { t: punchAt, ...rest } = r.reply;
    this.send(ws, { t: "connect_ok", req, ...rest, punch_at: punchAt });
  }

  onResumeMsg(ws, nodeId, m) {
    const since = Math.max(0, Number(m.since ?? 0) || 0);
    const cursor = this.replay(ws, nodeId, since);
    this.send(ws, { t: "resume_ok", cursor });
  }

  async webSocketClose(ws, code, reason) {
    this.sockets.delete(ws);
    const a = this.attachment(ws);
    const nodeId = a.node;

    // 1005/1006 是保留码，直接用它们回关会抛异常（原型已踩过）
    const safe = code === 1005 || code === 1006 ? WS_CLOSE_NORMAL : code;
    try {
      ws.close(safe, reason ?? "");
    } catch {}

    if (!nodeId) return;
    // leave 关闭时节点行已被删掉，这里拿到的就是 null，直接返回；
    // 其余情况写一次 last_seen，给轮询侧留一个离线宽限
    const node = this.getNode(nodeId);
    if (!node) return;

    // 同一节点已经有新 socket 接管（4000 抢占、或客户端刚重连）：这是"换了一条连接"，
    // 不是"人走了"。无条件广播 peer_offline 会让对端误判它离线，而且不会补发 peer_online。
    const stillHere = (this.state.getWebSockets?.() ?? []).some(
      (s) => s !== ws && this.attachment(s).node === nodeId,
    );
    this.touchNode(nodeId, Date.now());
    if (stillHere) return;

    this.announceOffline(nodeId, node.name, ws);
  }

  /**
   * 告诉声明了 `offline_evt` 能力的 socket：某个节点下线了。
   *
   * 不落库（不占 SQLite 写、也不会被迟到的事件补发出来）。旧客户端不声明这个能力，
   * 所以永远看不到这条消息，行为与升级前一致。
   */
  announceOffline(nodeId, name, exceptWs = null) {
    const msg = { t: "event", seq: 0, type: "peer_offline", node_id: nodeId, name: name ?? "" };
    for (const other of this.state.getWebSockets?.() ?? []) {
      if (other === exceptWs) continue;
      const ao = this.attachment(other);
      if (!ao.node || ao.node === nodeId) continue;
      if (!(ao.caps ?? []).includes("offline_evt")) continue;
      this.deliver(other, msg);
    }
  }

  webSocketError(ws, err) {
    this.sockets.delete(ws);
    console.warn(`[room] socket 异常: ${err instanceof Error ? err.message : String(err)}`);
  }

  /** 关闭全部 socket：换密钥、删网络、迁移使用。 */
  closeAll(code, reason) {
    for (const ws of this.state.getWebSockets?.() ?? []) {
      try {
        ws.close(code, reason);
      } catch {}
    }
    this.sockets.clear();
  }

  // ---- socket 辅助 ---------------------------------------------------------

  attachment(ws) {
    try {
      return ws.deserializeAttachment?.() ?? {};
    } catch {
      return {};
    }
  }

  /** node_id → socket。n ≤ 256，遍历足够，没必要再维护一份可能过期的索引。 */
  socketIndex() {
    const idx = new Map();
    for (const ws of this.state.getWebSockets?.() ?? []) {
      const a = this.attachment(ws);
      if (a?.node) idx.set(a.node, ws);
    }
    return idx;
  }

  /** 运行时记录的自动应答时间（毫秒）；没收到过 ping 时为 null。 */
  autoResponseAt(ws) {
    try {
      const t = this.state.getWebSocketAutoResponseTimestamp?.(ws);
      return t ? new Date(t).getTime() : null;
    } catch {
      return null;
    }
  }

  /** 每 socket 的消息令牌桶。休眠后丢失不影响正确性（只是重新计数）。 */
  allow(ws) {
    const now = Date.now();
    const slot = this.sockets.get(ws);
    if (!slot || now - slot.start > WS_MSG_WINDOW_MS) {
      if (this.sockets.size > 1024) this.sockets.clear();
      this.sockets.set(ws, { start: now, count: 1 });
      return true;
    }
    slot.count += 1;
    return slot.count <= WS_MSG_LIMIT;
  }

  send(ws, msg) {
    try {
      ws.send(JSON.stringify(msg));
      return true;
    } catch {
      return false;
    }
  }

  deliver(ws, msg) {
    return this.send(ws, msg);
  }

  maxSeq() {
    return this.sql.exec("SELECT COALESCE(MAX(id), 0) AS m FROM events").toArray()[0]?.m ?? 0;
  }

  /**
   * 把"超出当前最大 seq"的游标当成 0。
   *
   * 旧引擎的游标是 D1 自增 id（可能上万），DO 的 seq 每个网络从 1 开始；换引擎、
   * purge、重建数据之后，客户端手里的游标一定大于当前最大值。此时退回 0 让它重新
   * 从最近的事件开始读，比让它静默饿死强（事件只有 5 分钟 TTL，重放代价很小）。
   */
  clampSince(since) {
    const n = Math.max(0, Number(since) || 0);
    return n > this.maxSeq() ? 0 : n;
  }

  /** 数据代次：服务端数据被重建（purge / 换库）后客户端据此判断要不要重新 register。 */
  epoch() {
    const row = this.sql.exec("SELECT v FROM meta WHERE k = 'epoch'").toArray()[0];
    if (row) return row.v;
    const next = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
    this.sql.exec("INSERT INTO meta (k, v) VALUES ('epoch', ?)", next);
    return next;
  }

  // ---- 管理面数据操作（checkAdmin 与 audit 仍留在 Worker） ------------------

  handleAdminNodes() {
    const now = Date.now();
    const net = this.net() ?? {};
    const reservations = this.listReservations();
    // 索引只建一次：每个节点各调一次 liveness() 会退化成 O(n²) 的
    // attachment 反序列化，256 节点的网络打开管理页就能感到卡。
    const idx = this.socketIndex();
    const rows = this.listNodes()
      .map((n) => {
        const ws = idx.get(n.node_id);
        // 有 socket 就看自动应答时间戳；没有才退回 last_seen
        const idleMs = ws
          ? now - (this.autoResponseAt(ws) ?? this.attachment(ws).joinedAt ?? now)
          : now - n.last_seen;
        return {
          ...publicNode(n, now),
          node_id: n.node_id,
          advertised: safeParseArray(n.advertise),
          reserved: reservations.some((r) => r.ip === n.virtual_ip && r.node_id === n.node_id),
          // publicNode 的 online 只看 last_seen，对长连接节点是错的，这里覆盖掉
          online: idleMs <= (ws ? WS_GRACE_MS : OFFLINE_MS),
          via: ws ? "ws" : "poll",
        };
      })
      .sort((a, b) => ipv4ToInt(a.virtual_ip) - ipv4ToInt(b.virtual_ip));

    return json({
      ok: true,
      network: { id: net.id ?? "", name: net.name ?? "", cidr: net.cidr ?? "" },
      nodes: rows,
      reservations,
    });
  }

  /** 单个与批量踢人共用：node_id 或 node_ids 都接受。 */
  handleAdminKick(body) {
    const raw = Array.isArray(body?.node_ids)
      ? body.node_ids
      : body?.node_id !== undefined
        ? [body.node_id]
        : [];
    const ids = raw.map((x) => String(x).toLowerCase());
    if (ids.length === 0 || ids.length > MAX_NODES) {
      return err(400, "invalid_node_ids", `node_ids 必须是 1~${MAX_NODES} 个 node_id 的数组`);
    }
    if (ids.some((id) => !/^[0-9a-f]{32}$/.test(id))) {
      return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
    }

    const idx = this.socketIndex();
    const kicked = [];
    for (const id of ids) {
      const node = this.getNode(id);
      if (!node) continue;
      // 先告诉它为什么，再关：光断连的话客户端只会当成网络抖动去重连
      const ws = idx.get(id);
      if (ws) {
        this.send(ws, { t: "kick", reason: "被管理员移出网络" });
        try {
          ws.close(WS_CLOSE_UNAUTHORIZED, "kicked");
        } catch {}
      }
      this.deleteNode(id);
      this.dropNodeEvents(id);
      this.announceOffline(id, node.name);
      kicked.push({ node_id: id, name: node.name });
    }
    return json({ ok: true, removed: kicked.length, kicked });
  }

  handleAdminReservations() {
    return json({ ok: true, reservations: this.listReservations() });
  }

  handleAdminReserve(body) {
    const net = this.net();
    if (!net) return err(503, "room_unavailable", "这个 DO 还没有网络上下文");

    const ip = String(body?.ip ?? "").trim();
    const nodeId = String(body?.node_id ?? "").trim().toLowerCase();
    if (!/^(\d{1,3})(\.\d{1,3}){3}$/.test(ip) || ip.split(".").some((p) => Number(p) > 255)) {
      return err(400, "invalid_virtual_ip", `IP 格式不对：${ip}`);
    }
    if (nodeId && !/^[0-9a-f]{32}$/.test(nodeId)) {
      return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
    }
    if (!ipInCidr(net.cidr, ip)) {
      return err(400, "virtual_ip_not_in_network", `${ip} 不在网段 ${net.cidr} 里`);
    }

    const holder = this.listNodes().find((n) => n.virtual_ip === ip && n.node_id !== nodeId);
    if (holder) {
      return err(409, "virtual_ip_taken", `${ip} 当前被「${holder.name}」占用，先踢下线再预留`);
    }

    // 一个节点只保留一条预留：给新地址就把旧的删掉
    if (nodeId) {
      for (const old of this.listReservations()) {
        if (old.node_id === nodeId && old.ip !== ip) this.deleteReservation(old.ip);
      }
    }

    this.putReservation({
      ip,
      node_id: nodeId,
      kind: "user",
      note: String(body?.note ?? "").slice(0, 100),
      created_at: Date.now(),
    });
    return json({ ok: true, reservation: { ip, node_id: nodeId } });
  }

  handleAdminRelease(ip) {
    this.deleteReservation(String(ip ?? ""));
    return json({ ok: true, released: String(ip ?? "") });
  }
}
