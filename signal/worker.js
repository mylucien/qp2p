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

const VERSION = "2.4.0";
const TOKEN_PREFIX = "qp2p1_";

const OFFLINE_MS = 150_000; // 超过这个时间没心跳视为离线
const HEARTBEAT_MS = 60_000; // last_seen 最快多久写一次（省 D1 写额度）
const MAX_BODY_BYTES = 16 * 1024;
const MAX_NODES = 256; // 每个网络的上限
const MAX_CANDIDATES = 16;
const MAX_EVENTS = 50;
const EVENT_TTL_MS = 300_000;
const NODE_TTL_MS = 600_000; // 10 分钟没心跳就删，否则僵尸节点会占满 MAX_NODES
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 240; // 每 IP 每分钟请求数，防止误用把 D1 额度打满
const SWEEP_INTERVAL_MS = 60_000;

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
  `CREATE TABLE IF NOT EXISTS nodes (
    network_id TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    pubkey     TEXT NOT NULL,
    tls_fp     TEXT NOT NULL,
    virtual_ip TEXT NOT NULL,
    nat_type   TEXT NOT NULL,
    advertise  TEXT NOT NULL,
    candidates TEXT NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (network_id, node_id)
  )`,
  `CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT NOT NULL,
    node_id    TEXT NOT NULL,
    type       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS events_by_node ON events (network_id, node_id, id)`,
  `CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
  )`,
  // IP 预留：用户手填的地址要"固定"下来，节点离线清理后不能被别人抢走。
  // kind=user 永久保留（除非管理员释放）；kind=auto 跟随节点存在。
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
    detail     TEXT NOT NULL DEFAULT ''
  )`,
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
      ctx.waitUntil(sweep(env).catch(() => {}));
    }

    res.headers.set("x-qp2p-colo", colo);
    res.headers.set("x-qp2p-ms", String(Date.now() - started));
    return res;
  },
};

async function route(request, url, env, ctx) {
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (path === "/") return landing();
  if (path === "/admin") return adminPage();
  if (path === "/v1/health") return health(request, env);
  if (path === "/v1/admin/login" && method === "POST") return adminLogin(request, env);
  if (path === "/v1/admin/logout" && method === "POST") return adminLogout(request);
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
  const kick = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/nodes\/([0-9a-f]{32})\/kick$/.exec(path);
  if (kick && method === "POST") return kickNode(request, env, kick[1], kick[2]);
  const resv = /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/reservations$/.exec(path);
  if (resv && method === "GET") return listReservationsAdmin(request, env, resv[1]);
  if (resv && method === "POST") return reserveIp(request, env, resv[1]);
  const resvOne =
    /^\/v1\/admin\/networks\/([a-z0-9][a-z0-9-]{0,39})\/reservations\/((?:\d{1,3}\.){3}\d{1,3})$/.exec(path);
  if (resvOne && method === "DELETE") return releaseIp(request, env, resvOne[1], resvOne[2]);

  const isRead = method === "GET";
  if (path === "/v1/join" && method === "POST") return joinOrRegister(request, env, url, false);
  if (path === "/v1/register" && method === "POST") return joinOrRegister(request, env, url, true);
  if (path === "/v1/connect" && method === "POST") return connect(request, env, url);
  if (path === "/v1/leave" && method === "POST") return leave(request, env, url);
  if (path === "/v1/events" && isRead) return events(request, env, url);

  return err(404, "not_found", `${method} ${path}`);
}

// ---------------------------------------------------------------------------
// 基础接口
// ---------------------------------------------------------------------------

async function landing() {
  const body = [
    "qp2p signal worker",
    `version ${VERSION}`,
    "",
    "GET  /v1/health",
    "GET  /admin                       管理页面（登录后操作）",
    "POST /v1/admin/login              用 ADMIN_SECRET 换 2 小时 cookie",
    "POST /v1/admin/networks   需要 X-Admin-Secret，可带 join_key / cidr",
    "PATCH /v1/admin/networks/<id>     改名字 / 网段",
    "POST /v1/admin/networks/<id>/rotate   需要 X-Admin-Secret，换加入密钥",
    "GET  /v1/admin/networks/<id>/nodes    节点列表（在线状态）",
    "POST /v1/admin/networks/<id>/nodes/<node>/kick   踢下线",
    "GET/POST /v1/admin/networks/<id>/reservations     查/加 IP 预留",
    "DELETE /v1/admin/networks/<id>/reservations/<ip> 释放预留",
    "GET  /v1/admin/audit              管理操作审计",
    "POST /v1/join",
    "POST /v1/register",
    "POST /v1/connect",
    "GET  /v1/events?node_id=&since=",
    "POST /v1/leave",
  ].join("\n");
  return new Response(body + "\n", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

async function health(request, env) {
  const storage = await ready(env);
  const out = {
    ok: true,
    version: VERSION,
    storage,
    has_admin_secret: Boolean(env.ADMIN_SECRET),
    colo: request.cf?.colo ?? "local",
    server_ms: Date.now(),
    limits: { offline_ms: OFFLINE_MS, heartbeat_ms: HEARTBEAT_MS, max_nodes: MAX_NODES },
  };

  if (storage === "d1") {
    // 计数走 60 秒缓存：health 免鉴权，不能让它变成免费的 D1 读放大器
    const now = Date.now();
    if (!healthCache.at || now - healthCache.at > 60_000) {
      try {
        const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM nodes").first();
        healthCache = { at: now, nodes: Number(row?.n ?? 0) };
      } catch {
        healthCache = { at: now, nodes: null };
      }
    }
    out.nodes = healthCache.nodes;
    if (healthCache.nodes === null) {
      out.ok = false;
      out.error = "schema_not_ready";
    }
  } else {
    out.nodes = memoryNodes();
    out.warning = "未绑定 D1：状态只存在当前 isolate，多地域节点可能互相看不见";
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

  const net = await getNetwork(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const body = (await readJson(request)) ?? {};
  const preset = body.join_key === undefined ? null : String(body.join_key);
  if (preset !== null) {
    const bad = validateJoinKey(preset);
    if (bad) return bad;
  }

  const joinKey = preset ?? randomSecret();
  net.join_hash = await sha256Hex(joinKey);
  await putNetwork(env, net);

  return json({
    ok: true,
    network: { id: net.network_id, name: net.name, cidr: net.cidr },
    token: tokenOf(net.network_id, joinKey),
    note: "该网络原有令牌已失效，节点需要重新 join",
    ...(preset && joinKeyLooksWeak(joinKey)
      ? { warning: "这把预设密钥看起来容易被猜，建议省略 join_key 让服务端生成随机密钥" }
      : {}),
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

  const net = await getNetwork(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const removed = await purgeNetwork(env, networkId);
  await audit(env, "network.delete", networkId, `清理 ${removed} 个节点`);
  console.warn(`[signal] 删除网络 ${networkId}，清理 ${removed} 个节点`);

  return json({ ok: true, network: { id: networkId, name: net.name }, removed_nodes: removed });
}

/** 改网络：名字 / 网段。改网段会把落在新网段外的节点重新分配地址。 */
async function updateNetwork(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetwork(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const changes = [];
  if (body.name !== undefined) {
    const name = String(body.name).trim().slice(0, 48);
    if (!name) return err(400, "invalid_name", "网络名不能为空");
    if (name !== net.name) changes.push(`名字 ${net.name} → ${name}`);
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
      net.cidr = cidr;
    }
  }
  if (changes.length === 0) {
    return json({ ok: true, changed: false, network: { id: net.network_id, name: net.name, cidr: net.cidr } });
  }

  await putNetwork(env, net);

  // 网段变了：不在新网段里的节点重新分配，否则它们会顶着一个 ping 不通的地址
  let reassigned = 0;
  if (body.cidr !== undefined) {
    const nodes = await listNodes(env, networkId);
    for (const node of nodes) {
      if (ipInCidr(net.cidr, node.virtual_ip)) continue;
      const oldIp = node.virtual_ip;
      const fresh = await assignIp(net, node.node_id, nodes, []);
      await deleteReservation(env, networkId, oldIp);
      node.virtual_ip = fresh;
      await putNode(env, node);
      await putReservation(env, {
        network_id: networkId,
        ip: fresh,
        node_id: node.node_id,
        kind: "auto",
        note: "网段变更后重新分配",
        created_at: Date.now(),
      });
      reassigned += 1;
    }
    // 落在新网段外的预留已经不可能生效，一并清掉（管理员随时可以重新预留）
    for (const r of await listReservations(env, networkId)) {
      if (!ipInCidr(net.cidr, r.ip)) await deleteReservation(env, networkId, r.ip);
    }
  }

  await audit(env, "network.update", networkId, `${changes.join("；")}${reassigned ? `；重分配 ${reassigned} 个节点` : ""}`);
  return json({
    ok: true,
    changed: true,
    network: { id: net.network_id, name: net.name, cidr: net.cidr },
    reassigned,
  });
}

/** 管理面看节点：带在线状态、预留信息，按虚拟 IP 排序。 */
async function listNetworkNodes(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetwork(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const now = Date.now();
  const nodes = await listNodes(env, networkId);
  const reservations = await listReservations(env, networkId);
  const rows = nodes
    .map((n) => ({
      ...publicNode(n, now),
      node_id: n.node_id,
      advertised: safeParseArray(n.advertise),
      reserved: reservations.some((r) => r.ip === n.virtual_ip && r.node_id === n.node_id),
    }))
    .sort((a, b) => ipv4ToInt(a.virtual_ip) - ipv4ToInt(b.virtual_ip));

  return json({
    ok: true,
    network: { id: net.network_id, name: net.name, cidr: net.cidr },
    nodes: rows,
    reservations,
  });
}

/** 踢一个节点下线：删记录 + 清它的事件，定向预留保留。 */
async function kickNode(request, env, networkId, nodeId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const node = await getNode(env, networkId, nodeId);
  if (!node) return err(404, "node_not_found", `没有节点 ${nodeId}`);

  await deleteNode(env, networkId, nodeId);
  await dropNodeEvents(env, networkId, nodeId);
  await audit(env, "node.kick", `${networkId}/${nodeId}`, node.name);
  console.warn(`[signal] 管理员踢下线 ${node.name} (${nodeId})`);

  return json({ ok: true, node: { node_id: nodeId, name: node.name } });
}

/** 管理员手动预留一个 IP（可以给还没上线的节点预占）。 */
async function reserveIp(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  const net = await getNetwork(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const ip = String(body.ip ?? "").trim();
  const nodeId = String(body.node_id ?? "").trim().toLowerCase();
  if (!/^(\d{1,3})(\.\d{1,3}){3}$/.test(ip) || ip.split(".").some((p) => Number(p) > 255)) {
    return err(400, "invalid_virtual_ip", `IP 格式不对：${ip}`);
  }
  if (nodeId && !/^[0-9a-f]{32}$/.test(nodeId)) {
    return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
  }
  if (!ipInCidr(net.cidr, ip)) {
    return err(400, "virtual_ip_not_in_network", `${ip} 不在网段 ${net.cidr} 里`);
  }

  const others = await listNodes(env, networkId);
  const holder = others.find((n) => n.virtual_ip === ip && n.node_id !== nodeId);
  if (holder) {
    return err(409, "virtual_ip_taken", `${ip} 当前被「${holder.name}」占用，先踢下线再预留`);
  }

  // 一个节点只保留一条预留：给它新地址就把旧的删掉，免得 join 时二选一
  if (nodeId) {
    for (const old of await listReservations(env, networkId)) {
      if (old.node_id === nodeId && old.ip !== ip) {
        await deleteReservation(env, networkId, old.ip);
      }
    }
  }

  await putReservation(env, {
    network_id: networkId,
    ip,
    node_id: nodeId,
    kind: "user",
    note: String(body.note ?? "").slice(0, 100),
    created_at: Date.now(),
  });
  await audit(env, "reservation.put", `${networkId}/${ip}`, nodeId || "(未绑定节点)");
  return json({ ok: true, reservation: { ip, node_id: nodeId } });
}

async function releaseIp(request, env, networkId, ip) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;

  await deleteReservation(env, networkId, ip);
  await audit(env, "reservation.delete", `${networkId}/${ip}`, "");
  return json({ ok: true, released: ip });
}

async function listReservationsAdmin(request, env, networkId) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;
  const net = await getNetwork(env, networkId);
  if (!net) return err(404, "network_not_found", `没有网络 ${networkId}`);
  return json({ ok: true, reservations: await listReservations(env, networkId) });
}

async function auditLog(request, env, url) {
  const admin = await checkAdmin(request, env);
  if (admin) return admin;
  const limit = Number(url.searchParams.get("limit") ?? 100) || 100;
  return json({ ok: true, actions: await listAudit(env, limit) });
}

async function allNetworks(env) {
  if ((await ready(env)) === "memory") return [...memory.networks.values()];
  const { results } = await env.DB.prepare("SELECT * FROM networks").all();
  return results ?? [];
}

async function nodeCounts(env) {
  if ((await ready(env)) === "memory") {
    const out = {};
    for (const node of memory.nodes.values()) {
      out[node.network_id] = (out[node.network_id] ?? 0) + 1;
    }
    return out;
  }
  const { results } = await env.DB.prepare(
    "SELECT network_id, COUNT(*) AS n FROM nodes GROUP BY network_id",
  ).all();
  const out = {};
  for (const row of results ?? []) out[row.network_id] = Number(row.n ?? 0);
  return out;
}

/** 每网络在线节点数（管理页用，一次查询拿全）。 */
async function onlineCounts(env) {
  const now = Date.now();
  if ((await ready(env)) === "memory") {
    const out = {};
    for (const node of memory.nodes.values()) {
      if (now - node.last_seen <= OFFLINE_MS) {
        out[node.network_id] = (out[node.network_id] ?? 0) + 1;
      }
    }
    return out;
  }
  const { results } = await env.DB.prepare(
    "SELECT network_id, COUNT(*) AS n FROM nodes WHERE last_seen >= ? GROUP BY network_id",
  )
    .bind(now - OFFLINE_MS)
    .all();
  const out = {};
  for (const row of results ?? []) out[row.network_id] = Number(row.n ?? 0);
  return out;
}

async function reservationCounts(env) {
  if ((await ready(env)) === "memory") {
    const out = {};
    for (const r of memory.reservations.values()) {
      out[r.network_id] = (out[r.network_id] ?? 0) + 1;
    }
    return out;
  }
  const { results } = await env.DB.prepare(
    "SELECT network_id, COUNT(*) AS n FROM reservations GROUP BY network_id",
  ).all();
  const out = {};
  for (const row of results ?? []) out[row.network_id] = Number(row.n ?? 0);
  return out;
}

/** 删掉一个网络及其节点、事件、nonce，返回清理掉的节点数。 */
async function purgeNetwork(env, networkId) {
  if ((await ready(env)) === "memory") {
    const before = [...memory.nodes.values()].filter((n) => n.network_id === networkId).length;
    for (const [k, node] of [...memory.nodes.entries()]) {
      if (node.network_id === networkId) memory.nodes.delete(k);
    }
    memory.events = memory.events.filter((e) => e.network_id !== networkId);
    for (const [k, r] of [...memory.reservations.entries()]) {
      if (r.network_id === networkId) memory.reservations.delete(k);
    }
    memory.networks.delete(networkId);
    return before;
  }

  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM nodes WHERE network_id = ?")
    .bind(networkId)
    .first();
  await env.DB.prepare("DELETE FROM nodes WHERE network_id = ?").bind(networkId).run();
  await env.DB.prepare("DELETE FROM events WHERE network_id = ?").bind(networkId).run();
  await env.DB.prepare("DELETE FROM reservations WHERE network_id = ?").bind(networkId).run();
  await env.DB.prepare("DELETE FROM networks WHERE network_id = ?").bind(networkId).run();
  return Number(count?.n ?? 0);
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

  // 管理页面用 cookie：secret 只 POST 一次换成短期签名，之后不再出现在
  // URL 或 localStorage 里，被 XSS 抄走的机会小得多。
  if (await adminCookieValid(request, env)) return null;
  return err(401, "invalid_admin_secret", "需要 X-Admin-Secret，或先在 /admin 登录");
}

const ADMIN_COOKIE = "qp2p_admin";
const ADMIN_SESSION_MS = 2 * 60 * 60 * 1000; // 2 小时

async function adminCookieFor(env, expiresAt) {
  const mac = await hmacHex(env.ADMIN_SECRET, `admin:${expiresAt}`);
  return `${expiresAt}.${mac.slice(0, 32)}`;
}

async function adminCookieValid(request, env) {
  if (!env.ADMIN_SECRET) return false;
  const raw = cookieValue(request, ADMIN_COOKIE);
  if (!raw) return false;
  const [expText, mac] = raw.split(".");
  const expiresAt = Number(expText);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false;
  const expect = await hmacHex(env.ADMIN_SECRET, `admin:${expiresAt}`);
  return timingSafeEqual(mac ?? "", expect.slice(0, 32));
}

function cookieValue(request, name) {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

/** 用 secret 换一张短期 cookie；管理页面靠它免重复输入。 */
async function adminLogin(request, env) {
  if (!env.ADMIN_SECRET) return err(503, "admin_secret_unset", "请先部署 ADMIN_SECRET");
  const body = (await readJson(request)) ?? {};
  const secret = String(body.secret ?? "");
  if (!timingSafeEqual(secret, env.ADMIN_SECRET)) {
    await audit(env, "login.failed", "admin", request.headers.get("cf-connecting-ip") ?? "");
    return err(401, "invalid_admin_secret");
  }
  const expiresAt = Date.now() + ADMIN_SESSION_MS;
  const value = await adminCookieFor(env, expiresAt);
  await audit(env, "login.ok", "admin", "");
  // 线上是 https 才加 Secure；本地 dev-server 跑 http，加了会导致 cookie 存不下来
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return new Response(JSON.stringify({ ok: true, expires_at: expiresAt }), {
    status: 200,
    headers: {
      ...JSON_HEADERS,
      "set-cookie": `${ADMIN_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${ADMIN_SESSION_MS / 1000}${secure}`,
    },
  });
}

async function adminLogout(request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      ...JSON_HEADERS,
      "set-cookie": `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`,
    },
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
  const auth = await authenticate(request, env, url);
  if (!auth.ok) return auth.response;

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
  const derived = (await sha256Hex(hexToBytes(pubkey))).slice(0, 32);
  if (derived !== nodeId) {
    return err(403, "node_id_mismatch", "node_id 必须等于 sha256(pubkey)[..32]");
  }

  const candidates = parseCandidates(body.candidates);
  if (candidates === null) {
    return err(400, "invalid_candidates", `候选地址必须是合法 ip:port，最多 ${MAX_CANDIDATES} 个`);
  }
  if (needCandidates && candidates.length === 0) {
    return err(400, "missing_candidates", "register 至少需要一个候选地址");
  }

  const network = auth.network;
  const now = Date.now();

  // 签名覆盖整个请求体：改 candidates / tls_fp / name 任何一项都会让签名失效
  const bad = await verifySignedRequest({
    env,
    op: needCandidates ? "register" : "join",
    networkId: network.network_id,
    body,
    pubkey,
    now,
    trackReplay: true,
  });
  if (bad) return err(403, "bad_signature", bad);

  const existing = await getNode(env, network.network_id, nodeId);
  if (!existing) {
    const peersNow = await listNodes(env, network.network_id);
    if (peersNow.length >= MAX_NODES) {
      // 满了先淘汰最久没心跳的离线节点，否则僵尸节点会把网络永久占死
      const victim = peersNow
        .filter((n) => now - n.last_seen > OFFLINE_MS)
        .sort((a, b) => a.last_seen - b.last_seen)[0];
      if (!victim) {
        return err(507, "network_full", `每个网络上限 ${MAX_NODES} 个节点，且都在线`);
      }
      await deleteNode(env, network.network_id, victim.node_id);
      console.warn(`[signal] 淘汰僵尸节点 ${victim.node_id}`);
    }
  }

  const others = await listNodes(env, network.network_id);
  const reservations = await listReservations(env, network.network_id);

  // 用户可以在加入时自己指定虚拟地址（家庭里想固定 IP 的典型需求）。
  // 只校验、不自动改：撞车就报错，别让人以为生效了其实是别的地址。
  const requested = body.virtual_ip === undefined || body.virtual_ip === null
    ? null
    : String(body.virtual_ip).trim();
  if (requested !== null) {
    const bad = validateVirtualIp(network, requested, nodeId, others, reservations);
    if (bad) return bad;
  }

  // 地址优先级：这次指定 > 已有记录 > 自己的预留 > 自动分配。
  // 预留让"用户手填的地址"在节点离线清理之后依然归它——否则重连就换地址了。
  let virtualIp = requested ?? existing?.virtual_ip ?? null;
  if (!virtualIp) {
    const mine = reservations.find((r) => r.node_id === nodeId);
    const stolen = mine && others.some((n) => n.node_id !== nodeId && n.virtual_ip === mine.ip);
    if (mine && !stolen) virtualIp = mine.ip;
  }
  // 管理员改过网段的话，旧地址可能已经不在网段里：重新分配，别给个 ping 不通的地址
  if (!virtualIp || !ipInCidr(network.cidr, virtualIp)) {
    virtualIp = await assignIp(network, nodeId, others, reservations);
  }

  // 记录预留：用户手填的永久保留，自动分配的跟着节点走（节点清理时一起删）
  const oldRes = reservations.find((r) => r.node_id === nodeId && r.ip !== virtualIp);
  if (oldRes) await deleteReservation(env, network.network_id, oldRes.ip);
  await putReservation(env, {
    network_id: network.network_id,
    ip: virtualIp,
    node_id: nodeId,
    kind: reservations.find((r) => r.ip === virtualIp && r.node_id === nodeId)?.kind ??
      (requested !== null ? "user" : "auto"),
    note: reservations.find((r) => r.ip === virtualIp)?.note ?? "",
    created_at: Date.now(),
  });

  const record = {
    network_id: network.network_id,
    node_id: nodeId,
    name: String(body.name ?? existing?.name ?? nodeId.slice(0, 8)).slice(0, 48),
    pubkey,
    tls_fp: String(body.tls_fp ?? existing?.tls_fp ?? "").slice(0, 128),
    virtual_ip: virtualIp,
    nat_type: String(body.nat_type ?? existing?.nat_type ?? "unknown").slice(0, 16),
    advertise: JSON.stringify(
      Array.isArray(body.advertise) ? body.advertise.slice(0, 8).map(String) : JSON.parse(existing?.advertise ?? "[]"),
    ),
    candidates: JSON.stringify(candidates.length > 0 ? candidates : JSON.parse(existing?.candidates ?? "[]")),
    last_seen: now,
  };

  await putNode(env, record);

  const peers = (await listNodes(env, network.network_id))
    .filter((n) => n.node_id !== nodeId)
    .map((n) => publicNode(n, now));

  return json({
    ok: true,
    network: { id: network.network_id, name: network.name, cidr: network.cidr },
    node: { node_id: nodeId, virtual_ip: virtualIp, name: record.name },
    peers,
    durable: Boolean(env.DB),
    server_ms: now,
  });
}

async function connect(request, env, url) {
  const auth = await authenticate(request, env, url);
  if (!auth.ok) return auth.response;

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const from = String(body.from ?? "").toLowerCase();
  const target = String(body.target ?? "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(from) || !/^[0-9a-f]{32}$/.test(target)) {
    return err(400, "invalid_node_id", "from 与 target 都必须是 32 位十六进制 node_id");
  }
  if (from === target) return err(400, "self_connect", "不能连自己");

  const now = Date.now();
  const self = await getNode(env, auth.network.network_id, from);
  if (!self) return err(404, "unknown_node", "发起方尚未注册");

  const bad = await verifySignedRequest({
    env,
    op: "connect",
    networkId: auth.network.network_id,
    body,
    pubkey: self.pubkey,
    now,
    trackReplay: true,
  });
  if (bad) return err(403, "bad_signature", bad);

  const peer = await getNode(env, auth.network.network_id, target);
  if (!peer) return err(404, "target_not_found", "对端不在这个网络里");
  if (now - peer.last_seen > OFFLINE_MS) return err(410, "target_offline", "对端心跳已超时");

  const peerCandidates = JSON.parse(peer.candidates || "[]");
  if (peerCandidates.length === 0) {
    return err(409, "target_no_candidates", "对端还没有上报候选地址");
  }

  const t = now + 500;
  await pushEvent(env, auth.network.network_id, target, "punch_request", {
    from,
    // 组网时被叫方要靠这个地址决定"这个包该发给谁"，
    // 只给候选地址的话，被叫方拿到连接也不知道对端的虚拟 IP
    from_name: self.name,
    virtual_ip: self.virtual_ip,
    candidates: JSON.parse(self.candidates || "[]"),
    t,
    server_ms: now,
  });

  return json({
    ok: true,
    t,
    target_candidates: peerCandidates,
    target_virtual_ip: peer.virtual_ip,
    target_tls_fp: peer.tls_fp,
    server_ms: now,
  });
}

async function events(request, env, url) {
  const auth = await authenticate(request, env, url);
  if (!auth.ok) return auth.response;

  const nodeId = (url.searchParams.get("node_id") ?? "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(nodeId)) {
    return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
  }
  const since = Math.max(0, Number(url.searchParams.get("since") ?? 0) || 0);

  const now = Date.now();
  const node = await getNode(env, auth.network.network_id, nodeId);
  if (!node) return err(404, "unknown_node", "先 register 再拉事件");

  // GET 没有请求体：把参与签名的三个查询参数拼成同样的结构再算摘要。
  // 轮询本身幂等，不做 nonce 消费，否则每次心跳都要多写一行。
  const signedBody = {
    node_id: nodeId,
    since,
    // ts/since 一律按数字进摘要：查询串里是字符串，不归一化就会和客户端算出的摘要对不上
    ts: Number(url.searchParams.get("ts")),
    nonce: url.searchParams.get("nonce"),
  };
  const bad = await verifySignedRequest({
    env,
    op: "events",
    networkId: auth.network.network_id,
    body: { ...signedBody, sig: url.searchParams.get("sig") },
    pubkey: node.pubkey,
    now,
    trackReplay: false,
  });
  if (bad) return err(403, "bad_signature", bad);

  // 轮询即心跳，但按 HEARTBEAT_MS 节流，避免把 D1 写额度烧在心跳上
  if (now - node.last_seen >= HEARTBEAT_MS) {
    await touchNode(env, auth.network.network_id, nodeId, now);
  }

  // 首次拉取（since=0）只给最近 30 秒的事件：更早的 punch_request 已经没有意义，
  // 交给客户端处理不如在这里就挡掉
  const minCreatedAt = since === 0 ? now - 30_000 : 0;
  const rows = await pullEvents(env, auth.network.network_id, nodeId, since, MAX_EVENTS, minCreatedAt);
  const cursor = rows.length > 0 ? rows[rows.length - 1].id : since;

  return json({
    ok: true,
    cursor,
    events: rows.map((r) => ({
      seq: r.id,
      type: r.type,
      ...safeParse(r.payload),
    })),
    server_ms: now,
  });
}

async function leave(request, env, url) {
  const auth = await authenticate(request, env, url);
  if (!auth.ok) return auth.response;

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const nodeId = String(body.node_id ?? "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(nodeId)) {
    return err(400, "invalid_node_id", "node_id 必须是 32 位十六进制");
  }

  // 只能下线自己：要求 pubkey 与 node_id 匹配，且用这把私钥签了这次请求
  const pubkey = String(body.pubkey ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pubkey) || (await sha256Hex(hexToBytes(pubkey))).slice(0, 32) !== nodeId) {
    return err(403, "node_id_mismatch", "leave 需要提供与 node_id 对应的 pubkey");
  }

  const bad = await verifySignedRequest({
    env,
    op: "leave",
    networkId: auth.network.network_id,
    body,
    pubkey,
    now: Date.now(),
    trackReplay: true,
  });
  if (bad) return err(403, "bad_signature", bad);

  await deleteNode(env, auth.network.network_id, nodeId);
  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// 鉴权：令牌是 ADMIN_SECRET 的 HMAC，服务端无需存密钥
// ---------------------------------------------------------------------------

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
      return { ok: false, response: err(403, "wrong_secret", "加入密钥不正确") };
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

const memory = {
  networks: new Map(),
  nodes: new Map(),
  events: [],
  nonces: new Map(),
  reservations: new Map(),
  audit: [],
  seq: 0,
};
const migrated = new WeakSet(); // 每个 D1 绑定只建一次表

async function ready(env) {
  if (!env.DB) return "memory";
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

async function getNetwork(env, id) {
  if ((await ready(env)) === "memory") return memory.networks.get(id) ?? null;
  return env.DB.prepare("SELECT * FROM networks WHERE network_id = ?").bind(id).first();
}

async function putNetwork(env, net) {
  if ((await ready(env)) === "memory") {
    memory.networks.set(net.network_id, net);
    return;
  }
  await env.DB.prepare(
    "INSERT OR REPLACE INTO networks (network_id, name, cidr, created_at, join_hash) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(net.network_id, net.name, net.cidr, net.created_at, net.join_hash ?? "")
    .run();
}

async function getNode(env, networkId, nodeId) {
  if ((await ready(env)) === "memory") return memory.nodes.get(key(networkId, nodeId)) ?? null;
  return env.DB.prepare("SELECT * FROM nodes WHERE network_id = ? AND node_id = ?")
    .bind(networkId, nodeId)
    .first();
}

async function putNode(env, node) {
  if ((await ready(env)) === "memory") {
    memory.nodes.set(key(node.network_id, node.node_id), { ...node });
    return;
  }
  await env.DB.prepare(
    `INSERT INTO nodes (network_id, node_id, name, pubkey, tls_fp, virtual_ip, nat_type, advertise, candidates, last_seen)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(network_id, node_id) DO UPDATE SET
       name = excluded.name,
       pubkey = excluded.pubkey,
       tls_fp = excluded.tls_fp,
       virtual_ip = excluded.virtual_ip,
       nat_type = excluded.nat_type,
       advertise = excluded.advertise,
       candidates = excluded.candidates,
       last_seen = excluded.last_seen`,
  )
    .bind(
      node.network_id,
      node.node_id,
      node.name,
      node.pubkey,
      node.tls_fp,
      node.virtual_ip,
      node.nat_type,
      node.advertise,
      node.candidates,
      node.last_seen,
    )
    .run();
}

async function touchNode(env, networkId, nodeId, ts) {
  if ((await ready(env)) === "memory") {
    const node = memory.nodes.get(key(networkId, nodeId));
    if (node) node.last_seen = ts;
    return;
  }
  await env.DB.prepare("UPDATE nodes SET last_seen = ? WHERE network_id = ? AND node_id = ?")
    .bind(ts, networkId, nodeId)
    .run();
}

async function deleteNode(env, networkId, nodeId) {
  if ((await ready(env)) === "memory") {
    memory.nodes.delete(key(networkId, nodeId));
  } else {
    await env.DB.prepare("DELETE FROM nodes WHERE network_id = ? AND node_id = ?")
      .bind(networkId, nodeId)
      .run();
  }
  // 节点没了，自动预留跟着走；用户手填的留着，重装后还能拿回原地址
  await dropAutoReservations(env, networkId, nodeId);
}

async function listNodes(env, networkId) {
  if ((await ready(env)) === "memory") {
    return [...memory.nodes.values()].filter((n) => n.network_id === networkId);
  }
  const { results } = await env.DB.prepare("SELECT * FROM nodes WHERE network_id = ?")
    .bind(networkId)
    .all();
  return results ?? [];
}

// --- IP 预留 ---------------------------------------------------------------

async function listReservations(env, networkId) {
  if ((await ready(env)) === "memory") {
    return [...memory.reservations.values()].filter((r) => r.network_id === networkId);
  }
  const { results } = await env.DB.prepare("SELECT * FROM reservations WHERE network_id = ?")
    .bind(networkId)
    .all();
  return results ?? [];
}

async function putReservation(env, r) {
  if ((await ready(env)) === "memory") {
    memory.reservations.set(key(r.network_id, r.ip), { ...r });
    return;
  }
  await env.DB.prepare(
    `INSERT INTO reservations (network_id, ip, node_id, kind, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(network_id, ip) DO UPDATE SET
       node_id = excluded.node_id,
       kind = excluded.kind,
       note = excluded.note`,
  )
    .bind(r.network_id, r.ip, r.node_id, r.kind, r.note ?? "", r.created_at)
    .run();
}

async function deleteReservation(env, networkId, ip) {
  if ((await ready(env)) === "memory") {
    memory.reservations.delete(key(networkId, ip));
    return;
  }
  await env.DB.prepare("DELETE FROM reservations WHERE network_id = ? AND ip = ?")
    .bind(networkId, ip)
    .run();
}

/** 节点没了：自动预留一起删，用户指定的保留（换台机器重装还能拿回原地址）。 */
async function dropAutoReservations(env, networkId, nodeId) {
  if ((await ready(env)) === "memory") {
    for (const [k, r] of [...memory.reservations.entries()]) {
      if (r.network_id === networkId && r.node_id === nodeId && r.kind !== "user") {
        memory.reservations.delete(k);
      }
    }
    return;
  }
  await env.DB.prepare(
    "DELETE FROM reservations WHERE network_id = ? AND node_id = ? AND kind != 'user'",
  )
    .bind(networkId, nodeId)
    .run();
}

// --- 管理审计 --------------------------------------------------------------

async function audit(env, action, target, detail = "") {
  const row = { at: Date.now(), action, target, detail: String(detail).slice(0, 400) };
  if ((await ready(env)) === "memory") {
    memory.audit.push(row);
    if (memory.audit.length > 500) memory.audit.shift();
    return;
  }
  await env.DB.prepare(
    "INSERT INTO admin_actions (at, action, target, detail) VALUES (?, ?, ?, ?)",
  )
    .bind(row.at, row.action, row.target, row.detail)
    .run();
}

async function listAudit(env, limit = 100) {
  if ((await ready(env)) === "memory") {
    return memory.audit.slice(-limit).reverse();
  }
  const { results } = await env.DB.prepare(
    "SELECT at, action, target, detail FROM admin_actions ORDER BY id DESC LIMIT ?",
  )
    .bind(Math.min(500, Math.max(1, limit)))
    .all();
  return results ?? [];
}

async function pushEvent(env, networkId, nodeId, type, payload) {
  const now = Date.now();
  if ((await ready(env)) === "memory") {
    memory.seq += 1;
    memory.events.push({
      id: memory.seq,
      network_id: networkId,
      node_id: nodeId,
      type,
      payload: JSON.stringify(payload),
      created_at: now,
    });
    return;
  }
  await env.DB.prepare(
    "INSERT INTO events (network_id, node_id, type, payload, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(networkId, nodeId, type, JSON.stringify(payload), now)
    .run();
}

/** 节点被踢掉时清掉发给它的事件，否则它会一直读到过期的 punch_request。 */
async function dropNodeEvents(env, networkId, nodeId) {
  if ((await ready(env)) === "memory") {
    memory.events = memory.events.filter(
      (e) => !(e.network_id === networkId && e.node_id === nodeId),
    );
    return;
  }
  await env.DB.prepare("DELETE FROM events WHERE network_id = ? AND node_id = ?")
    .bind(networkId, nodeId)
    .run();
}

async function pullEvents(env, networkId, nodeId, since, limit, minCreatedAt = 0) {
  if ((await ready(env)) === "memory") {
    return memory.events
      .filter(
        (e) =>
          e.network_id === networkId &&
          e.node_id === nodeId &&
          e.id > since &&
          e.created_at >= minCreatedAt,
      )
      .slice(0, limit);
  }
  const { results } = await env.DB.prepare(
    `SELECT id, type, payload FROM events
      WHERE network_id = ? AND node_id = ? AND id > ? AND created_at >= ?
      ORDER BY id LIMIT ?`,
  )
    .bind(networkId, nodeId, since, minCreatedAt, limit)
    .all();
  return results ?? [];
}

function memoryNodes() {
  return memory.nodes.size;
}

function key(networkId, nodeId) {
  return `${networkId}/${nodeId}`;
}

// ---------------------------------------------------------------------------
// 地址分配：与客户端 derive_virtual_ip 完全一致
// ---------------------------------------------------------------------------

/**
 * 校验用户指定的虚拟地址。
 *
 * 服务端是唯一权威：客户端算出来的地址可能有冲突，这里必须拒绝而不是"帮它改"。
 * 返回错误响应，或 null 表示可用。
 */
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
  if ((await ready(env)) === "memory") {
    return new Set([...memory.networks.values()].map((n) => n.cidr));
  }
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
    virtual_ip: node.virtual_ip,
    nat_type: node.nat_type,
    tls_fp: node.tls_fp,
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
const NONCE_TTL_MS = 300_000;

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

/**
 * 校验一次签名请求。返回错误说明，或 null 表示通过。
 * `trackReplay` 为 true 时消费 nonce，重复提交会被拒。
 */
async function verifySignedRequest({ env, op, networkId, body, pubkey, now, trackReplay }) {
  const stamp = Number(body?.ts);
  if (!Number.isFinite(stamp)) return "缺少 ts（毫秒时间戳）";
  if (Math.abs(now - stamp) > TS_WINDOW_MS) return "ts 超出 ±120 秒窗口";

  const nonce = String(body?.nonce ?? "").toLowerCase();
  if (!/^[0-9a-f]{16,64}$/.test(nonce)) return "nonce 必须是 16~64 位十六进制";

  let digest;
  try {
    digest = await bodyDigest(body);
  } catch (e) {
    // 请求体里有浮点 / 超出安全范围的整数：是客户端的问题，不能变成 500
    return `请求体无法规范化：${e instanceof Error ? e.message : String(e)}`;
  }
  const message = signingMessage(op, networkId, stamp, nonce, digest);
  const mismatch = await verifySignature(pubkey, message, body?.sig);
  if (mismatch) return mismatch;

  if (trackReplay && !(await consumeNonce(env, `${networkId}:${nonce}`, now))) {
    return "nonce 已用过（疑似重放）";
  }
  return null;
}

async function consumeNonce(env, key, now) {
  if ((await ready(env)) === "memory") {
    const seen = memory.nonces.get(key);
    if (seen && now - seen < NONCE_TTL_MS) return false;
    memory.nonces.set(key, now);
    return true;
  }
  const { meta } = await env.DB.prepare(
    "INSERT INTO nonces (nonce, created_at) VALUES (?, ?) ON CONFLICT(nonce) DO NOTHING",
  )
    .bind(key, now)
    .run();
  return (meta?.changes ?? 0) > 0;
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

function limited(request, max = RATE_MAX) {
  const ip = request.headers.get("cf-connecting-ip") ?? "local";
  const bucket = `${ip}|${max}`;
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

async function sweep(env) {
  const now = Date.now();
  if (now - sweeper.last < SWEEP_INTERVAL_MS) return 0;
  sweeper.last = now;

  const staleCutoff = now - EVENT_TTL_MS;
  const nodeCutoff = now - NODE_TTL_MS;

  if (!env.DB) {
    memory.events = memory.events.filter((e) => e.created_at >= staleCutoff);
    for (const [key, node] of memory.nodes) {
      if (node.last_seen < nodeCutoff) memory.nodes.delete(key);
    }
    // 节点没了，自动预留跟着清；用户手填的（kind=user）一直留着
    for (const [k, r] of [...memory.reservations.entries()]) {
      if (r.kind === "user") continue;
      const owner = memory.nodes.get(key(r.network_id, r.node_id));
      if (!owner) memory.reservations.delete(k);
    }
    for (const [key, at] of memory.nonces) {
      if (at < now - NONCE_TTL_MS) memory.nonces.delete(key);
    }
    return 0;
  }

  const { meta } = await env.DB.prepare("DELETE FROM events WHERE created_at < ?")
    .bind(staleCutoff)
    .run();
  await env.DB.prepare("DELETE FROM nodes WHERE last_seen < ?").bind(nodeCutoff).run();
  await env.DB.prepare(
    `DELETE FROM reservations
      WHERE kind != 'user'
        AND NOT EXISTS (
          SELECT 1 FROM nodes n
           WHERE n.network_id = reservations.network_id AND n.node_id = reservations.node_id
        )`,
  ).run();
  await env.DB.prepare("DELETE FROM nonces WHERE created_at < ?")
    .bind(now - NONCE_TTL_MS)
    .run();
  return meta?.changes ?? 0;
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
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#1a1c1f;--muted:#6b7280;--line:#e5e7eb;--accent:#2563eb;--danger:#dc2626;--ok:#16a34a}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--muted:#9aa3ad;--line:#262b33;--accent:#5b8cff;--danger:#f87171;--ok:#4ade80}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line);background:var(--card)}
h1{font-size:16px;margin:0;font-weight:600}
main{max-width:1080px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
input{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
button{padding:7px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--danger);border-color:var(--danger)}
button.sm{padding:3px 8px;font-size:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:middle}
th{color:var(--muted);font-weight:500;font-size:12px}
tr:last-child td{border-bottom:0}
.muted{color:var(--muted)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.on{background:var(--ok)}.off{background:var(--muted)}
pre{white-space:pre-wrap;word-break:break-all;background:var(--bg);padding:10px;border-radius:8px;font-size:12px}
.hide{display:none}
</style>
</head>
<body>
<header><h1>qp2p 管理台</h1><span class="muted" id="who"></span><span style="flex:1"></span><button id="refresh" class="hide">刷新</button><button id="logout" class="hide">退出</button></header>
<main>
  <section id="login" class="card hide" style="max-width:420px;margin:40px auto">
    <h2 style="margin-top:0;font-size:15px">用管理员密钥登录</h2>
    <label>ADMIN_SECRET</label>
    <input id="secret" type="password" autocomplete="current-password" placeholder="部署时设置的变量">
    <div class="row" style="margin-top:12px"><button class="primary" id="doLogin">登录</button><span class="muted" id="loginMsg"></span></div>
    <p class="muted" style="font-size:12px;margin-bottom:0">登录后服务端签发 2 小时 HttpOnly cookie，密钥不会存进浏览器。</p>
  </section>

  <div id="dash" class="hide">
    <section class="card">
      <h2 style="margin:0 0 10px;font-size:15px">网络</h2>
      <table><thead><tr><th>名称</th><th>网段</th><th>节点</th><th>在线</th><th>预留</th><th>操作</th></tr></thead><tbody id="nets"></tbody></table>
      <div class="row" style="margin-top:12px">
        <input id="newName" placeholder="新网络名称" style="max-width:180px">
        <input id="newCidr" placeholder="网段（可空，如 10.90.0.0/16）" style="max-width:220px">
        <input id="newKey" placeholder="加入密钥（可空，自动生成）" style="max-width:220px">
        <button class="primary" id="createNet">新建</button>
      </div>
      <pre id="tokenOut" class="hide"></pre>
    </section>

    <section class="card hide" id="nodesCard">
      <h2 style="margin:0 0 10px;font-size:15px">节点 <span class="muted" id="nodesFor"></span></h2>
      <table><thead><tr><th>状态</th><th>名称</th><th>虚拟 IP</th><th>NAT</th><th>最后心跳</th><th>操作</th></tr></thead><tbody id="nodes"></tbody></table>
      <h2 style="margin:18px 0 10px;font-size:15px">IP 预留</h2>
      <table><thead><tr><th>IP</th><th>节点</th><th>类型</th><th>备注</th><th>操作</th></tr></thead><tbody id="resv"></tbody></table>
      <div class="row" style="margin-top:12px">
        <input id="resvIp" placeholder="要预留的 IP" style="max-width:160px">
        <input id="resvNode" placeholder="node_id（可空）" style="max-width:280px">
        <input id="resvNote" placeholder="备注" style="max-width:180px">
        <button id="addResv">预留</button>
      </div>
    </section>

    <section class="card">
      <h2 style="margin:0 0 10px;font-size:15px">操作审计</h2>
      <table><thead><tr><th>时间</th><th>动作</th><th>对象</th><th>详情</th></tr></thead><tbody id="audit"></tbody></table>
    </section>
  </div>
</main>
<script>
var current = null;
function $(id){return document.getElementById(id)}
function api(path, method, body){
  var opt = {method: method||'GET', credentials:'same-origin', headers:{}};
  if (body !== undefined) { opt.headers['content-type']='application/json'; opt.body=JSON.stringify(body); }
  return fetch(path, opt).then(function(r){
    return r.json().catch(function(){return {ok:false,error:'bad_json'}}).then(function(j){
      if (!r.ok || j.ok === false) throw new Error((j.error||String(r.status))+' '+(j.detail||''));
      return j;
    });
  });
}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function ago(ms){ if(!ms) return '—'; var d=Math.min(9999,Math.round((Date.now()-ms)/1000)); if(d<60)return d+' 秒前'; if(d<3600)return Math.round(d/60)+' 分钟前'; return Math.round(d/3600)+' 小时前'; }
function showDash(){
  $('login').classList.add('hide'); $('dash').classList.remove('hide');
  $('refresh').classList.remove('hide'); $('logout').classList.remove('hide');
  load();
}
function showLogin(){ $('dash').classList.add('hide'); $('login').classList.remove('hide'); $('refresh').classList.add('hide'); $('logout').classList.add('hide'); }
function load(){
  api('/v1/admin/networks').then(function(j){ renderNets(j.networks) }).catch(function(e){ if(/401/.test(e.message)) showLogin(); });
  api('/v1/admin/audit?limit=50').then(function(j){ renderAudit(j.actions) }).catch(function(){});
  if (current) loadNodes(current);
}
function renderNets(list){
  var t = $('nets'); t.innerHTML='';
  if (!list.length) t.innerHTML = '<tr><td colspan="6" class="muted">还没有网络，先新建一个</td></tr>';
  list.forEach(function(n){
    var tr=document.createElement('tr');
    tr.innerHTML = '<td><b>'+esc(n.name)+'</b><div class="muted" style="font-size:12px">'+esc(n.id)+'</div></td>'+
      '<td>'+esc(n.cidr)+'</td><td>'+n.nodes+'</td><td>'+n.online+'</td><td>'+n.reservations+'</td>';
    var td=document.createElement('td'); td.className='row';
    td.appendChild(btn('节点','sm',function(){ current=n.id; loadNodes(n.id); }));
    td.appendChild(btn('改网段','sm',function(){
      var v=prompt('新网段（10.x.0.0/16）。落在网段外的节点会被重新分配地址', n.cidr);
      if(v) api('/v1/admin/networks/'+n.id,'PATCH',{cidr:v}).then(function(){ load(); }).catch(function(e){alert(e.message)});
    }));
    td.appendChild(btn('换密钥','sm',function(){
      if(!confirm('换掉「'+n.name+'」的加入密钥？旧令牌立刻失效')) return;
      api('/v1/admin/networks/'+n.id+'/rotate','POST',{}).then(function(j){
        $('tokenOut').classList.remove('hide'); $('tokenOut').textContent='新令牌（只显示这一次）：\\n'+j.token;
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
}
function btn(text, cls, fn){ var b=document.createElement('button'); b.textContent=text; b.className=cls; b.onclick=fn; return b; }
function loadNodes(id){
  $('nodesCard').classList.remove('hide'); $('nodesFor').textContent='· '+id;
  api('/v1/admin/networks/'+id+'/nodes').then(function(j){
    var t=$('nodes'); t.innerHTML='';
    if(!j.nodes.length) t.innerHTML='<tr><td colspan="6" class="muted">还没有节点</td></tr>';
    j.nodes.forEach(function(n){
      var tr=document.createElement('tr');
      tr.innerHTML='<td><span class="dot '+(n.online?'on':'off')+'"></span>'+(n.online?'在线':'离线')+'</td>'+
        '<td>'+esc(n.name)+(n.reserved?' <span class="muted" style="font-size:12px">已固定</span>':'')+'</td>'+
        '<td>'+esc(n.virtual_ip)+'</td><td>'+esc(n.nat_type)+'</td><td class="muted">'+ago(n.last_seen)+'</td>';
      var td=document.createElement('td'); td.className='row';
      td.appendChild(btn('踢下线','sm danger',function(){
        if(!confirm('把「'+n.name+'」踢下线？')) return;
        api('/v1/admin/networks/'+id+'/nodes/'+n.node_id+'/kick','POST',{}).then(function(){loadNodes(id)}).catch(function(e){alert(e.message)});
      }));
      td.appendChild(btn('固定此 IP','sm',function(){
        api('/v1/admin/networks/'+id+'/reservations','POST',{ip:n.virtual_ip,node_id:n.node_id,note:'页面固定'})
          .then(function(){loadNodes(id)}).catch(function(e){alert(e.message)});
      }));
      tr.appendChild(td); t.appendChild(tr);
    });
    var r=$('resv'); r.innerHTML='';
    if(!j.reservations.length) r.innerHTML='<tr><td colspan="5" class="muted">没有预留</td></tr>';
    j.reservations.forEach(function(x){
      var tr=document.createElement('tr');
      tr.innerHTML='<td>'+esc(x.ip)+'</td><td class="muted">'+esc(x.node_id||'—')+'</td><td>'+(x.kind==='user'?'手动':'自动')+'</td><td class="muted">'+esc(x.note||'')+'</td>';
      var td=document.createElement('td');
      td.appendChild(btn('释放','sm danger',function(){
        api('/v1/admin/networks/'+id+'/reservations/'+x.ip,'DELETE').then(function(){loadNodes(id)}).catch(function(e){alert(e.message)});
      }));
      tr.appendChild(td); r.appendChild(tr);
    });
  }).catch(function(e){ if(/401/.test(e.message)) showLogin(); });
}
function renderAudit(list){
  var t=$('audit'); t.innerHTML='';
  if(!list || !list.length){ t.innerHTML='<tr><td colspan="4" class="muted">还没有操作记录</td></tr>'; return; }
  list.forEach(function(a){
    var tr=document.createElement('tr');
    tr.innerHTML='<td class="muted">'+new Date(a.at).toLocaleString()+'</td><td>'+esc(a.action)+'</td><td>'+esc(a.target)+'</td><td class="muted">'+esc(a.detail)+'</td>';
    t.appendChild(tr);
  });
}
$('doLogin').onclick=function(){
  $('loginMsg').textContent='登录中…';
  api('/v1/admin/login','POST',{secret:$('secret').value}).then(function(){
    $('secret').value=''; $('loginMsg').textContent=''; showDash();
  }).catch(function(e){ $('loginMsg').textContent='登录失败：'+e.message; });
};
$('secret').addEventListener('keydown',function(e){ if(e.key==='Enter') $('doLogin').click(); });
$('refresh').onclick=load;
$('logout').onclick=function(){ api('/v1/admin/logout','POST',{}).then(showLogin).catch(showLogin); };
$('createNet').onclick=function(){
  var body={name:$('newName').value.trim()};
  if($('newCidr').value.trim()) body.cidr=$('newCidr').value.trim();
  if($('newKey').value.trim()) body.join_key=$('newKey').value.trim();
  api('/v1/admin/networks','POST',body).then(function(j){
    $('tokenOut').classList.remove('hide');
    $('tokenOut').textContent='加入令牌（只显示这一次，请立刻保存）：\\n'+j.token+'\\n\\n客户端命令：\\nqp2p join '+j.token+' --name 设备名';
    $('newName').value=''; $('newCidr').value=''; $('newKey').value='';
    load();
  }).catch(function(e){ alert(e.message); });
};
$('addResv').onclick=function(){
  if(!current) return;
  api('/v1/admin/networks/'+current+'/reservations','POST',{ip:$('resvIp').value.trim(),node_id:$('resvNode').value.trim(),note:$('resvNote').value.trim()})
    .then(function(){ $('resvIp').value='';$('resvNode').value='';$('resvNote').value=''; loadNodes(current); })
    .catch(function(e){alert(e.message)});
};
api('/v1/admin/networks').then(function(){ showDash() }).catch(function(){ showLogin() });
</script>
</body>
</html>`;
