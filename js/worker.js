/**
 * Cloudflare Worker — QUIC P2P 信令服务
 * 版本：v4.3
 *
 * 依赖：
 *   - D1 数据库（绑定名 DB）
 *   - 环境变量 AUTH_SECRET：HMAC-SHA256 签名密钥（至少 32 字节随机字符串）
 *
 * wrangler.toml 最小配置示例：
 *   name = "quic-signal"
 *   compatibility_date = "2024-01-01"
 *
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "quic-signal"
 *   database_id = "<your-d1-id>"
 *
 *   [vars]
 *   AUTH_SECRET = "<your-secret>"
 *
 *   [triggers]
 *   crons = ["0 2 * * *"]
 *
 * D1 建表 SQL（首次部署前执行）：
 *   CREATE TABLE IF NOT EXISTS edges (
 *     edge_id            TEXT PRIMARY KEY,
 *     tunnel_url         TEXT NOT NULL UNIQUE,
 *     virtual_ip         TEXT,
 *     candidates         TEXT NOT NULL,
 *     quic_conn_id       TEXT NOT NULL,
 *     group_name         TEXT NOT NULL DEFAULT '',
 *     group_password_hash TEXT NOT NULL DEFAULT '',
 *     status             TEXT NOT NULL DEFAULT 'online',
 *     last_seen          INTEGER NOT NULL,
 *     registered_at      INTEGER NOT NULL
 *   );
 *   CREATE INDEX IF NOT EXISTS idx_status_last_seen ON edges (status, last_seen);
 *   CREATE INDEX IF NOT EXISTS idx_group_name       ON edges (group_name);
 *
 * 已有库迁移（v4.2 → v4.3）：
 *   -- tunnel_url 加唯一索引（Worker 用它作为身份锚查询）
 *   CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnel_url ON edges (tunnel_url);
 *
 * v4.3 变更说明：
 *   - edge_id 改为由 Worker 生成和管理，Edge 不再自行维护
 *   - /register 以 tunnel_url 作为身份锚：
 *       首次注册（tunnel_url 不存在）→ Worker 生成 UUID 作为 edge_id，INSERT
 *       续约（tunnel_url 已存在）→ UPDATE，返回已有 edge_id
 *   - /register 请求体移除 edge_id 字段，响应体新增返回 edge_id
 *   - /token 改为以 tunnel_url 换取 Token（原为 edge_id）
 *   - /unregister 改为以 tunnel_url 标记下线（原为 edge_id）
 *
 * 分组逻辑说明：
 *   - group_name 相同的节点才能互连
 *   - group_password 为空 = 开放组，不校验密码，只要 group_name 相同即可连接
 *   - group_password 非空 = 私有组，双方密码 hash 必须一致
 *   - 两侧只要有一侧密码为空，视为开放组（允许连接）
 */

// ─────────────────────────────────────────────────────────────────────────────
// 常量
// ─────────────────────────────────────────────────────────────────────────────

const TOKEN_TTL_MS        = 24 * 60 * 60 * 1000; // 令牌有效期 24h
const TUNNEL_PUSH_TIMEOUT = 3000;                 // 推送超时 3s
const T_WINDOW_NORMAL     = 500;                  // 标准网络打洞同步窗口 ms
const T_WINDOW_POOR       = 800;                  // 差网络打洞同步窗口 ms
const OFFLINE_CUTOFF_SEC  = 86400;                // 节点离线判定：24h 未活跃

// candidate type 优先级：数字越小越优先
const CANDIDATE_PRIORITY = { host: 0, srflx: 1, relay: 2 };

// ─────────────────────────────────────────────────────────────────────────────
// 入口
// ─────────────────────────────────────────────────────────────────────────────

export default {
  /**
   * HTTP 请求入口
   */
  async fetch(request, env) {
    const url = new URL(request.url);

    // 健康检查（免鉴权）
    if (url.pathname === '/health' && request.method === 'GET') {
      return json({ ok: true, ts: Date.now() });
    }

    // 所有其他接口均需鉴权
    const authErr = await verifyAuth(request, env);
    if (authErr) return authErr;

    try {
      // 路由
      // /token 无需 Bearer，verifyAuth 已对其跳过，此处放最前避免与其他路由混淆
      if (url.pathname === '/token'      && request.method === 'POST') return handleToken(request, env);
      if (url.pathname === '/register'   && request.method === 'POST') return handleRegister(request, env);
      if (url.pathname === '/unregister' && request.method === 'POST') return handleUnregister(request, env);
      if (url.pathname === '/connect'    && request.method === 'POST') return handleConnect(request, env);
      if (url.pathname.startsWith('/peers/') && request.method === 'GET') return handlePeers(url, env);

      return err(404, 'not_found');
    } catch (e) {
      console.error(e);
      return err(500, 'internal_error', e.message);
    }
  },

  /**
   * Cron Trigger 入口 — 每日清理过期节点
   */
  async scheduled(_event, env, _ctx) {
    const now = nowSec();

    // 24h 未活跃的在线节点标为 offline
    const markResult = await env.DB.prepare(
      `UPDATE edges SET status = 'offline'
       WHERE status = 'online' AND last_seen < ?`
    ).bind(now - OFFLINE_CUTOFF_SEC).run();
    console.log(`[cron] marked offline: ${markResult.meta.changes} node(s)`);

    // 7 天未活跃的节点物理删除，防止表无限增长
    const deleteResult = await env.DB.prepare(
      `DELETE FROM edges WHERE last_seen < ?`
    ).bind(now - 7 * 86400).run();
    console.log(`[cron] deleted stale: ${deleteResult.meta.changes} node(s)`);
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// 鉴权
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 颁发 Bearer Token
 * 请求体：{ tunnel_url: string, secret: string }
 * secret 须与 env.AUTH_SECRET 一致（edge 在部署时静态配置）
 *
 * v4.3 变更：原以 edge_id 换取 Token，现改为以 tunnel_url 换取。
 * Token 的 sub 字段存储 tunnel_url，verifyAuth 后续可按需从 Token 中提取。
 */
async function handleToken(request, env) {
  const body = await parseBody(request);
  if (!body?.tunnel_url || !body?.secret) return err(400, 'missing_fields', 'tunnel_url, secret required');

  // 校验 tunnel_url 格式
  try {
    const u = new URL(body.tunnel_url);
    if (u.protocol !== 'https:') return err(400, 'invalid_tunnel_url', 'must be https');
  } catch {
    return err(400, 'invalid_tunnel_url', 'not a valid URL');
  }

  // 对比 secret（恒定时间比较防时序攻击）
  if (!safeEqual(body.secret, env.AUTH_SECRET)) return err(401, 'invalid_secret');

  const token = await signToken(body.tunnel_url, env.AUTH_SECRET);
  return json({ token, expires_in: TOKEN_TTL_MS / 1000 });
}

/**
 * 验证请求头中的 Bearer Token
 * Authorization: Bearer <token>
 */
async function verifyAuth(request, env) {
  // /token 接口自带 secret 校验，跳过 Bearer 验证
  const url = new URL(request.url);
  if (url.pathname === '/token') return null;

  const header = request.headers.get('Authorization') ?? '';
  const token  = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token) return err(401, 'missing_token');

  const payload = await verifyToken(token, env.AUTH_SECRET);
  if (!payload) return err(401, 'invalid_token');

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// 接口处理
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /register
 * 节点注册或续约
 *
 * v4.3 变更：
 *   - 移除 edge_id 入参，改由 Worker 以 tunnel_url 为锚生成/复用
 *   - 响应体新增 edge_id 字段，Edge 收到后持久化到本地 data_dir/edge_id
 *
 * 请求体：
 * {
 *   tunnel_url:      string,        // 必填，cloudflared 暴露的 HTTPS endpoint（身份锚）
 *   quic_conn_id:    string,        // 必填，打洞使用的固定 Connection ID
 *   candidates:      Candidate[],   // 必填，[{ addr: "ip:port", type: "host"|"srflx" }]
 *   virtual_ip?:     string,        // 可选，虚拟 IP（如 "10.0.0.1"）
 *   group_name?:     string,        // 可选，组名称，默认空字符串（无分组限制）
 *   group_password?: string,        // 可选，组密码明文，空 = 开放组；非空时 SHA-256 哈希后存储
 * }
 *
 * 响应：
 * {
 *   ok:            true,
 *   edge_id:       string,   // Worker 分配的节点唯一 ID，Edge 应持久化到 data_dir/edge_id
 *   registered_at: number,   // Unix 时间戳（秒）
 * }
 */
async function handleRegister(request, env) {
  const body = await parseBody(request);
  const { tunnel_url, quic_conn_id, candidates, virtual_ip,
          group_name, group_password } = body ?? {};

  // 参数校验
  if (!tunnel_url)   return err(400, 'missing_field', 'tunnel_url');
  if (!quic_conn_id) return err(400, 'missing_field', 'quic_conn_id');
  if (!Array.isArray(candidates) || candidates.length === 0)
    return err(400, 'invalid_candidates', 'candidates must be non-empty array');

  // 校验 candidates 格式
  for (const c of candidates) {
    if (!c.addr || !['host', 'srflx', 'relay'].includes(c.type))
      return err(400, 'invalid_candidates', `each candidate needs addr and type(host|srflx|relay), got: ${JSON.stringify(c)}`);
  }

  // 校验 tunnel_url 格式（必须是 HTTPS）
  try {
    const u = new URL(tunnel_url);
    if (u.protocol !== 'https:') return err(400, 'invalid_tunnel_url', 'must be https');
  } catch {
    return err(400, 'invalid_tunnel_url', 'not a valid URL');
  }

  // 处理分组字段
  const groupName         = (group_name ?? '').trim();
  const groupPasswordHash = group_password ? await sha256Hex(group_password) : '';

  const now = nowSec();

  // 以 tunnel_url 为身份锚查询是否已有记录
  const existing = await env.DB.prepare(
    `SELECT edge_id, registered_at FROM edges WHERE tunnel_url = ?`
  ).bind(tunnel_url).first();

  // 首次注册生成新 edge_id，续约复用已有 edge_id
  const edge_id       = existing?.edge_id ?? crypto.randomUUID();
  const registered_at = existing?.registered_at ?? now;

  await env.DB.prepare(`
    INSERT INTO edges (edge_id, tunnel_url, virtual_ip, candidates, quic_conn_id,
                       group_name, group_password_hash, status, last_seen, registered_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?, ?)
    ON CONFLICT(edge_id) DO UPDATE SET
      tunnel_url          = excluded.tunnel_url,
      virtual_ip          = excluded.virtual_ip,
      candidates          = excluded.candidates,
      quic_conn_id        = excluded.quic_conn_id,
      group_name          = excluded.group_name,
      group_password_hash = excluded.group_password_hash,
      status              = 'online',
      last_seen           = excluded.last_seen
  `).bind(
    edge_id,
    tunnel_url,
    virtual_ip ?? null,
    JSON.stringify(candidates),
    quic_conn_id,
    groupName,
    groupPasswordHash,
    now,
    registered_at,
  ).run();

  return json({ ok: true, edge_id, registered_at });
}

/**
 * POST /unregister
 * 主动下线
 *
 * v4.3 变更：原以 edge_id 标记下线，现改为以 tunnel_url 标记（与注册保持一致）
 *
 * 请求体：{ tunnel_url: string }
 */
async function handleUnregister(request, env) {
  const body = await parseBody(request);
  if (!body?.tunnel_url) return err(400, 'missing_field', 'tunnel_url');

  await env.DB.prepare(
    `UPDATE edges SET status = 'offline', last_seen = ? WHERE tunnel_url = ?`
  ).bind(nowSec(), body.tunnel_url).run();

  return json({ ok: true });
}

/**
 * POST /connect
 * 发起 P2P 连接请求
 *
 * 请求体：
 * {
 *   from:          string,        // 发起方 edge_id（由 /register 响应获得）
 *   target:        string,        // 目标方 edge_id
 *   candidates:    Candidate[],   // 发起方最新 candidates（此次连接时实时提供）
 *   poor_network?: boolean,       // 可选，差网络标志，影响 T 窗口大小
 * }
 *
 * 响应：
 * {
 *   ok:                true,
 *   t:                 number,        // 建议打洞时间戳（Unix ms）
 *   target_candidates: Candidate[],   // 按优先级排序后的目标方 candidates
 *   target_conn_id:    string,        // 目标方 quic_conn_id
 *   target_virtual_ip: string|null,   // 目标方虚拟 IP（供 edge-agent 写 VirtualIpRegistry）
 * }
 */
async function handleConnect(request, env) {
  const body = await parseBody(request);
  const { from, target, candidates: fromCandidates, poor_network } = body ?? {};

  if (!from)     return err(400, 'missing_field', 'from');
  if (!target)   return err(400, 'missing_field', 'target');
  if (!Array.isArray(fromCandidates) || fromCandidates.length === 0)
    return err(400, 'invalid_candidates', 'from candidates required');
  if (from === target) return err(400, 'self_connect', 'from and target must differ');

  // 查询发起方（同时取 group 字段用于组校验）
  const fromRow = await env.DB.prepare(
    `SELECT status, virtual_ip, group_name, group_password_hash FROM edges WHERE edge_id = ?`
  ).bind(from).first();
  if (!fromRow)                    return err(403, 'from_not_registered', 'caller must register first');
  if (fromRow.status !== 'online') return err(403, 'from_offline', 'caller is marked offline, re-register first');

  // 查询目标节点（同时取 group 字段）
  const targetRow = await env.DB.prepare(
    `SELECT tunnel_url, candidates, quic_conn_id, virtual_ip, status,
            group_name, group_password_hash FROM edges WHERE edge_id = ?`
  ).bind(target).first();
  if (!targetRow)                    return err(404, 'target_not_found');
  if (targetRow.status !== 'online') return err(410, 'target_offline');

  // ── 组校验 ──────────────────────────────────────────────────
  // 规则 1：group_name 必须相同（空字符串视为"无分组"，两个空也算相同）
  if (fromRow.group_name !== targetRow.group_name)
    return err(403, 'group_mismatch', 'nodes belong to different groups');

  // 规则 2：双方都设了密码（hash 非空）才校验；任意一方为空视为开放组，跳过密码校验
  const fromHasPassword   = fromRow.group_password_hash   !== '';
  const targetHasPassword = targetRow.group_password_hash !== '';
  if (fromHasPassword && targetHasPassword) {
    if (fromRow.group_password_hash !== targetRow.group_password_hash)
      return err(403, 'group_mismatch', 'wrong group password');
  }
  // ────────────────────────────────────────────────────────────

  // 解析目标 candidates 并按优先级排序（host → srflx → relay）
  let targetCandidates = [];
  try {
    targetCandidates = JSON.parse(targetRow.candidates);
  } catch {
    return err(500, 'corrupt_candidates', 'target candidates parse error');
  }
  const sortedTargetCandidates = sortCandidates(targetCandidates);

  // 发起方 candidates 同样排序（给 B 用）
  const sortedFromCandidates = sortCandidates(fromCandidates);

  // 计算建议打洞时间 T（当前时间 + 窗口）
  const windowMs = poor_network ? T_WINDOW_POOR : T_WINDOW_NORMAL;
  const t = Date.now() + windowMs;

  // 构造推送给 B 的通知 payload（附带 from_virtual_ip 供 B 写 VirtualIpRegistry）
  const notifyPayload = {
    type:             'hole_punch',
    from,
    from_candidates:  sortedFromCandidates,
    from_conn_id:     null,          // B 只需知道打向哪些地址，CID 由 A 自己发 Initial 包携带
    from_virtual_ip:  fromRow.virtual_ip ?? null,
    t,
  };

  // 发起方已确认合法，立即刷新 last_seen（不等推送结果，避免推送超时导致 last_seen 漏更新）
  await env.DB.prepare(
    `UPDATE edges SET last_seen = ? WHERE edge_id = ?`
  ).bind(nowSec(), from).run();

  // 推送 B（3s 超时）与准备 A 的响应数据并发
  const pushPromise    = pushTunnel(targetRow.tunnel_url, notifyPayload);
  const timeoutPromise = sleep(TUNNEL_PUSH_TIMEOUT).then(() => ({ timedOut: true }));
  const pushResult     = await Promise.race([pushPromise, timeoutPromise]);

  // 若推送超时或失败，通知 A 走中继，不修改 B 的状态
  if (pushResult?.timedOut || !pushResult?.ok) {
    console.warn(`[connect] push to ${target} failed:`, pushResult);
    return err(502, 'target_unreachable', 'tunnel push failed or timed out, fallback to relay');
  }

  return json({
    ok:                true,
    t,
    target_candidates: sortedTargetCandidates,
    target_conn_id:    targetRow.quic_conn_id,
    target_virtual_ip: targetRow.virtual_ip ?? null,
  });
}

/**
 * GET /peers/:id
 * 查询节点信息（调试/监控）
 */
async function handlePeers(url, env) {
  const id = url.pathname.replace('/peers/', '').trim();
  if (!id) return err(400, 'missing_id');

  const row = await env.DB.prepare(
    `SELECT edge_id, virtual_ip, candidates, quic_conn_id, status, last_seen, registered_at
     FROM edges WHERE edge_id = ?`
  ).bind(id).first();

  if (!row) return err(404, 'not_found');

  let parsedCandidates;
  try {
    parsedCandidates = JSON.parse(row.candidates);
  } catch {
    parsedCandidates = [];
  }

  return json({
    edge_id:       row.edge_id,
    virtual_ip:    row.virtual_ip,
    candidates:    parsedCandidates,
    quic_conn_id:  row.quic_conn_id,
    status:        row.status,
    last_seen:     row.last_seen,
    registered_at: row.registered_at,
    // tunnel_url 不对外暴露，避免泄露内部 endpoint
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 向目标节点的 Tunnel endpoint 推送打洞通知
 * POST <tunnel_url>/notify
 */
async function pushTunnel(tunnelUrl, payload) {
  const notifyUrl = tunnelUrl.replace(/\/$/, '') + '/notify';
  try {
    const resp = await fetch(notifyUrl, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    return { ok: resp.ok, status: resp.status };
  } catch (e) {
    console.warn(`[pushTunnel] failed: ${notifyUrl}`, e.message);
    return { ok: false, error: e.message };
  }
}

/**
 * 按 candidate 类型排序：host(0) → srflx(1) → relay(2)
 * 同类型内保持原始顺序（稳定排序）
 */
function sortCandidates(candidates) {
  return [...candidates].sort((a, b) => {
    const pa = CANDIDATE_PRIORITY[a.type] ?? 99;
    const pb = CANDIDATE_PRIORITY[b.type] ?? 99;
    return pa - pb;
  });
}

/**
 * 签发 JWT-like Token（HMAC-SHA256）
 * 结构：base64url(header).base64url(payload).base64url(signature)
 * sub 字段存储 tunnel_url
 */
async function signToken(tunnelUrl, secret) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: tunnelUrl, iat: Date.now(), exp: Date.now() + TOKEN_TTL_MS }));
  const data    = `${header}.${payload}`;
  const sig     = await hmacSign(data, secret);
  return `${data}.${sig}`;
}

/**
 * 验证 Token，返回 payload 或 null
 */
async function verifyToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, sig] = parts;

  // 先验签，再解析，避免先处理恶意 payload
  const expectedSig = await hmacSign(`${header}.${payload}`, secret);
  if (!safeEqual(sig, expectedSig)) return null;

  // 验证 header：alg 必须是 HS256，防止 alg:none 伪造
  let h;
  try { h = JSON.parse(atob(header.replace(/-/g, '+').replace(/_/g, '/'))); }
  catch { return null; }
  if (h.alg !== 'HS256') return null;

  // 解析 payload
  let p;
  try { p = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))); }
  catch { return null; }

  if (!p.sub)             return null; // sub 必须存在
  if (p.exp < Date.now()) return null; // 已过期
  return p;
}

/**
 * HMAC-SHA256 签名，返回 base64url 字符串
 */
async function hmacSign(data, secret) {
  const enc     = new TextEncoder();
  const keyData = enc.encode(secret);
  const key     = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig     = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  // 用 Uint8Array 直接编码，避免 String.fromCharCode 对 >127 字节产生多字节字符导致 btoa 崩溃
  return b64urlBytes(new Uint8Array(sig));
}

/**
 * 恒定时间字符串比较（防时序攻击）
 * 不提前 return，始终走完全程，避免泄露长度信息
 */
function safeEqual(a, b) {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length; // 长度不同时 diff 非零
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** base64url 编码（字符串输入） */
function b64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** base64url 编码（Uint8Array 输入，避免 btoa 多字节问题） */
function b64urlBytes(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** 解析 JSON 请求体，出错返回 null */
async function parseBody(request) {
  try { return await request.json(); }
  catch { return null; }
}

/**
 * SHA-256 哈希，返回小写 hex 字符串。
 * 用于 group_password 存储：明文不落库，只存 hash。
 * 注意：此处不加盐，因为 group_password 的作用是"共享访问凭证"而非用户私密密码，
 * 加盐会导致不同节点无法比对相同密码的 hash。
 */
async function sha256Hex(str) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** 当前 Unix 时间戳（秒）*/
function nowSec() { return Math.floor(Date.now() / 1000); }

/** sleep Promise */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/** 返回 JSON 响应 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** 返回错误响应 */
function err(status, code, detail) {
  return json({ ok: false, error: code, ...(detail ? { detail } : {}) }, status);
}
