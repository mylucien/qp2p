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

const VERSION = "2.0.0";
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
    created_at INTEGER NOT NULL
  )`,
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
  if (path === "/v1/health") return health(request, env);
  if (path === "/v1/admin/networks" && method === "POST") return createNetwork(request, env);

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
    "POST /v1/admin/networks   需要 X-Admin-Secret",
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
  if (!env.ADMIN_SECRET) {
    return err(
      503,
      "admin_secret_unset",
      "请在 Settings → Variables 添加 ADMIN_SECRET，然后重新部署",
    );
  }
  const provided = request.headers.get("x-admin-secret") ?? "";
  if (!timingSafeEqual(provided, env.ADMIN_SECRET)) {
    return err(401, "invalid_admin_secret");
  }

  const body = await readJson(request);
  if (body === null) return err(400, "invalid_json");

  const name = String(body.name ?? "").trim().slice(0, 48);
  const id = slug(name) || randomId();
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(id)) {
    return err(400, "invalid_name", "网络名只能包含字母、数字、连字符");
  }

  const existing = await getNetwork(env, id);
  if (existing) {
    // 幂等：重复创建返回同一个网络和同一把密钥
    return json({
      ok: true,
      network: { id: existing.network_id, name: existing.name, cidr: existing.cidr },
      token: await tokenFor(id, env.ADMIN_SECRET),
      note: "该网络已存在，返回同一把密钥",
    });
  }

  const cidr = body.cidr ? normalizeCidr(String(body.cidr)) : await pickCidr(env, id);
  if (!cidr) return err(400, "invalid_cidr", "只接受 10.x.0.0/16 形式");

  const net = { network_id: id, name: name || id, cidr, created_at: Date.now() };
  await putNetwork(env, net);

  return json({
    ok: true,
    network: { id, name: net.name, cidr },
    token: await tokenFor(id, env.ADMIN_SECRET),
    note: "把这把密钥分发给要加入网络的节点；同一网络重复创建会得到同一把密钥",
  });
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

  // 签名覆盖 op / 网络 / node / 时间戳 / 候选：
  // 没有它，同网络任何成员都能用别人的 node_id 把候选改成自己的地址（MITM）
  const message = needCandidates
    ? signPayload("register", network.network_id, nodeId, candidates.join(","), body.ts)
    : signPayload("join", network.network_id, nodeId, body.ts);
  const bad = await verifyNodeSignature({ pubkey, message, sig: body.sig, ts: body.ts, now });
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
  const virtualIp = existing?.virtual_ip || (await assignIp(network, nodeId, others));

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

  const message = signPayload("connect", auth.network.network_id, from, target, body.ts);
  const bad = await verifyNodeSignature({
    pubkey: self.pubkey,
    message,
    sig: body.sig,
    ts: body.ts,
    now,
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
  const ts = url.searchParams.get("ts");

  const now = Date.now();
  const node = await getNode(env, auth.network.network_id, nodeId);
  if (!node) return err(404, "unknown_node", "先 register 再拉事件");

  const message = signPayload("events", auth.network.network_id, nodeId, ts);
  const bad = await verifyNodeSignature({
    pubkey: node.pubkey,
    message,
    sig: url.searchParams.get("sig"),
    ts,
    now,
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

  const message = signPayload("leave", auth.network.network_id, nodeId, body.ts);
  const bad = await verifyNodeSignature({ pubkey, message, sig: body.sig, ts: body.ts, now: Date.now() });
  if (bad) return err(403, "bad_signature", bad);

  await deleteNode(env, auth.network.network_id, nodeId);
  return json({ ok: true });
}

// ---------------------------------------------------------------------------
// 鉴权：令牌是 ADMIN_SECRET 的 HMAC，服务端无需存密钥
// ---------------------------------------------------------------------------

async function authenticate(request, env, url) {
  if (!env.ADMIN_SECRET) {
    return { ok: false, response: err(503, "admin_secret_unset", "服务端未设置 ADMIN_SECRET") };
  }

  const header = request.headers.get("authorization") ?? "";
  const token = header.toLowerCase().startsWith("bearer ")
    ? header.slice(7).trim()
    : url.searchParams.get("token") ?? "";

  if (!token.startsWith(TOKEN_PREFIX)) {
    return { ok: false, response: err(401, "invalid_token", `令牌格式应为 ${TOKEN_PREFIX}<网络>_<密钥>`) };
  }

  const parsed = parseToken(token);
  if (!parsed) return { ok: false, response: err(401, "invalid_token") };

  const expected = await tokenFor(parsed.networkId, env.ADMIN_SECRET);
  if (!timingSafeEqual(expected, token)) {
    return { ok: false, response: err(403, "wrong_secret", "网络密钥不匹配") };
  }

  let network = await getNetwork(env, parsed.networkId);
  if (!network) {
    // 令牌有效但注册表丢了（换库/换实例）：按同一算法补回，网段保持一致
    network = {
      network_id: parsed.networkId,
      name: parsed.networkId,
      cidr: await pickCidr(env, parsed.networkId),
      created_at: Date.now(),
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

async function tokenFor(networkId, adminSecret) {
  const mac = await hmacHex(adminSecret, `token:${networkId}`);
  return `${TOKEN_PREFIX}${networkId}_${mac.slice(0, 40)}`;
}

// ---------------------------------------------------------------------------
// 存储：D1 优先，未绑定时退回 isolate 内存
// ---------------------------------------------------------------------------

const memory = { networks: new Map(), nodes: new Map(), events: [], seq: 0 };
const migrated = new WeakSet(); // 每个 D1 绑定只建一次表

async function ready(env) {
  if (!env.DB) return "memory";
  if (!migrated.has(env.DB)) {
    for (const sql of DDL_STATEMENTS) {
      await env.DB.prepare(sql).run();
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
    "INSERT OR REPLACE INTO networks (network_id, name, cidr, created_at) VALUES (?, ?, ?, ?)",
  )
    .bind(net.network_id, net.name, net.cidr, net.created_at)
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
    return;
  }
  await env.DB.prepare("DELETE FROM nodes WHERE network_id = ? AND node_id = ?")
    .bind(networkId, nodeId)
    .run();
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

async function assignIp(network, nodeId, others) {
  const used = new Set(others.map((n) => n.virtual_ip).filter(Boolean));
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
// 请求签名：每个写操作都要节点私钥签名，令牌只证明"能进这个网络"
// ---------------------------------------------------------------------------

const SIGN_PREFIX = "qp2p1";
const TS_WINDOW_MS = 120_000;

/**
 * 签名内容（用 `|` 连接，ts 固定在最后，客户端必须逐字一致）：
 *   qp2p1|join|<network>|<node_id>|<ts>
 *   qp2p1|register|<network>|<node_id>|<candidates 逗号连接>|<ts>
 *   qp2p1|connect|<network>|<from>|<target>|<ts>
 *   qp2p1|events|<network>|<node_id>|<ts>
 *   qp2p1|leave|<network>|<node_id>|<ts>
 */
function signPayload(...parts) {
  return [SIGN_PREFIX, ...parts.map((p) => String(p ?? ""))].join("|");
}

async function verifyNodeSignature({ pubkey, message, sig, ts, now }) {
  const stamp = Number(ts);
  if (!Number.isFinite(stamp)) return "缺少 ts（毫秒时间戳）";
  if (Math.abs(now - stamp) > TS_WINDOW_MS) return "ts 超出 ±120 秒窗口";

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
  "access-control-allow-methods": "GET, POST, OPTIONS",
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
    return 0;
  }

  const { meta } = await env.DB.prepare("DELETE FROM events WHERE created_at < ?")
    .bind(staleCutoff)
    .run();
  await env.DB.prepare("DELETE FROM nodes WHERE last_seen < ?").bind(nodeCutoff).run();
  return meta?.changes ?? 0;
}
