/**
 * Worker 效率回归测试：每类请求的 D1 查询 / 写入次数不得退化，广播事件的触发条件要对。
 *
 *   node signal/efficiency.mjs
 *
 * 用真实 worker.js + 带计数的 SQLite（冒充 D1）。数字是这次优化后的实测值，
 * 阈值留了一点余量，但"失败路径不写 nonce""没变化不写预留"这类约束是硬的。
 */
import { DatabaseSync } from "node:sqlite";

import worker, { canonicalJson } from "./worker.js";

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const h2b = (t) => Uint8Array.from(t.match(/../g).map((x) => parseInt(x, 16)));
const sha = async (s) =>
  hex(new Uint8Array(await crypto.subtle.digest("SHA-256", typeof s === "string" ? new TextEncoder().encode(s) : s)));

// ---- 带计数的 D1 ----------------------------------------------------------
const db = new DatabaseSync(":memory:");
let stats = null;
const reset = () => (stats = { queries: 0, writes: 0, by: {} });
const tag = (sql) => {
  const s = sql.replace(/\s+/g, " ").trim();
  const m = /(?:FROM|INTO|UPDATE)\s+(\w+)/i.exec(s);
  return `${s.split(" ")[0].toUpperCase()} ${m?.[1] ?? "?"}`;
};
const note = (sql, changed = 0) => {
  if (!stats) return;
  stats.queries += 1;
  stats.writes += changed;
  const k = tag(sql);
  stats.by[k] = (stats.by[k] ?? 0) + 1;
};
const D1 = {
  prepare(sql) {
    const st = db.prepare(sql);
    let params = [];
    const api = {
      bind: (...a) => ((params = a), api),
      run: () => {
        const n = Number(st.run(...params).changes ?? 0);
        note(sql, n);
        return { success: true, meta: { changes: n } };
      },
      first: () => (note(sql), st.get(...params) ?? null),
      all: () => (note(sql), { results: st.all(...params) }),
    };
    return api;
  },
};

const env = { DB: D1, ADMIN_SECRET: "eff-secret" };
const ctx = { waitUntil: () => {} };
let ip = 0;
async function call(method, path, { token, admin, body, query } = {}) {
  const url = new URL("https://qp2p.test" + path);
  for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, String(v));
  const headers = { "content-type": "application/json", "cf-connecting-ip": `9.8.${(ip++ >> 8) & 255}.${ip & 255}` };
  if (token) headers.authorization = `Bearer ${token}`;
  if (admin) headers["x-admin-secret"] = admin;
  const res = await worker.fetch(
    new Request(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }),
    env,
    ctx,
  );
  return { status: res.status, body: await res.json().catch(() => null) };
}
async function ident() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubkey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  return { pubkey, nodeId: (await sha(h2b(pubkey))).slice(0, 32), priv: pair.privateKey };
}
async function sign(node, op, net, body) {
  const ts = Date.now();
  const nonce = hex(crypto.getRandomValues(new Uint8Array(8)));
  const payload = { ...body, ts, nonce };
  const digest = await sha(canonicalJson(payload));
  const msg = `qp2p1|${op}|${net}|${ts}|${nonce}|${digest}`;
  const sig = hex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, node.priv, new TextEncoder().encode(msg))));
  return { ...payload, sig };
}
const register = async (n, net, token, i, candidates) =>
  call("POST", "/v1/register", {
    token,
    body: await sign(n, "register", net, {
      node_id: n.nodeId, pubkey: n.pubkey, name: `n${i}`, tls_fp: "ab".repeat(32), nat_type: "cone",
      candidates: candidates ?? [`203.0.113.${(i % 250) + 1}:51820`],
    }),
  });
const poll = async (n, net, token, since = 0) => {
  const b = await sign(n, "events", net, { node_id: n.nodeId, since });
  return call("GET", "/v1/events", { token, query: { node_id: n.nodeId, since, ts: b.ts, nonce: b.nonce, sig: b.sig } });
};
const connect = async (from, target, net, token) =>
  call("POST", "/v1/connect", { token, body: await sign(from, "connect", net, { from: from.nodeId, target }) });

let passed = 0;
let failed = 0;
function check(name, ok, detail) {
  if (ok) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    const text = typeof detail === "string" ? detail : JSON.stringify(detail);
    console.log(`  FAIL ${name} → ${text.length > 300 ? `${text.slice(0, 300)}…` : text}`);
  }
}
async function measure(fn) {
  reset();
  const result = await fn();
  const s = stats;
  stats = null;
  return { s, result };
}
const presence = (events) => (events ?? []).filter((e) => e.type === "peer_online");

// ---- 场景 ----------------------------------------------------------------
const N = 50;
const created = await call("POST", "/v1/admin/networks", { admin: env.ADMIN_SECRET, body: { name: "eff" } });
const token = created.body.token;
const net = created.body.network.id;
const nodes = [];

console.log("\n1. 新节点注册会广播上线");
for (let i = 0; i < N; i += 1) {
  const n = await ident();
  nodes.push(n);
  await register(n, net, token, i);
}
const [me, other] = nodes;
const mePoll = await poll(me, net, token, 0);
const seen = presence(mePoll.body.events).map((e) => e.node_id);
check("先注册的节点能读到后注册节点的上线广播", seen.includes(other.nodeId), seen.length);
check("广播携带候选地址与 NAT 类型", presence(mePoll.body.events).every((e) => e.candidates.length > 0 && e.nat_type === "cone"), presence(mePoll.body.events)[0]);
let cursor = mePoll.body.cursor;

console.log("\n2. 定时 register（地址没变）：便宜，且不广播");
let m = await measure(() => register(me, net, token, 0));
check("register 成功", m.result.status === 200, m.result.body);
check(`查询 ≤ 5 次（现 ${m.s.queries}；旧版 8）`, m.s.queries <= 5, m.s.by);
check(`只写 1 行：节点心跳（现 ${m.s.writes}；旧版 3）`, m.s.writes === 1, m.s.by);
check("没有写 nonce", !("INSERT nonces" in m.s.by), m.s.by);
check("成员只读一次", (m.s.by["SELECT nodes"] ?? 0) === 1, m.s.by);
let pulled = await poll(me, net, token, cursor);
check("地址没变不广播", presence(pulled.body.events).length === 0, pulled.body.events);
cursor = pulled.body.cursor;

console.log("\n3. 候选地址变了会广播");
await register(me, net, token, 0, ["198.51.100.77:40000"]);
// 事件 ID 全局递增：用已知游标只拉增量（从 0 拉会先被 50 个节点的上线广播占满单页）
pulled = await poll(other, net, token, cursor);
const moved = presence(pulled.body.events).filter((e) => e.node_id === me.nodeId).at(-1);
check("对端能读到新地址", moved?.candidates?.[0] === "198.51.100.77:40000", presence(pulled.body.events).slice(-2));
cursor = pulled.body.cursor;

console.log("\n4. 轮询（events）");
m = await measure(() => poll(me, net, token, cursor));
check(`无事件、无需写心跳：查询 ≤ 3、写 0（现 ${m.s.queries}/${m.s.writes}）`, m.s.queries <= 3 && m.s.writes === 0, m.s.by);
db.exec(`UPDATE nodes SET last_seen = ${Date.now() - 56_000} WHERE node_id='${me.nodeId}'`);
m = await measure(() => poll(me, net, token, cursor));
check("55 秒阈值：过了就写一次心跳", m.s.writes === 1 && m.s.by["UPDATE nodes"] === 1, m.s.by);
db.exec(`UPDATE nodes SET last_seen = ${Date.now() - 54_000} WHERE node_id='${me.nodeId}'`);
m = await measure(() => poll(me, net, token, cursor));
check("没到阈值不写", m.s.writes === 0, m.s.by);

console.log("\n5. 睡眠后回来（没重新注册）也要广播");
db.exec(`UPDATE nodes SET last_seen = ${Date.now() - 200_000} WHERE node_id='${me.nodeId}'`);
const before = (await poll(other, net, token, 0)).body.cursor;
await poll(me, net, token, cursor); // me 睡醒后的第一次轮询
pulled = await poll(other, net, token, before);
check("对端收到 me 回来的广播", presence(pulled.body.events).some((e) => e.node_id === me.nodeId), pulled.body.events);
const again = await poll(me, net, token, cursor);
const afterAgain = await poll(other, net, token, pulled.body.cursor);
check("只广播一次", presence(afterAgain.body.events).length === 0, afterAgain.body.events);
cursor = again.body.cursor;

console.log("\n6. connect 失败路径不写入");
db.exec(`UPDATE nodes SET last_seen = ${Date.now() - 200_000} WHERE node_id='${other.nodeId}'`);
m = await measure(() => connect(me, other.nodeId, net, token));
check("对端离线 → 410", m.result.status === 410, m.result.body);
check(`写入 0 行（旧版会写一行 nonce）`, m.s.writes === 0, m.s.by);
db.exec(`DELETE FROM nodes WHERE node_id='${other.nodeId}'`);
m = await measure(() => connect(me, other.nodeId, net, token));
check("对端不存在 → 404 且写入 0 行", m.result.status === 404 && m.s.writes === 0, [m.result.body, m.s.by]);

console.log("\n7. connect 成功路径：占 nonce + 写事件，重放被拒");
const third = nodes[2];
const body = await sign(me, "connect", net, { from: me.nodeId, target: third.nodeId });
m = await measure(() => call("POST", "/v1/connect", { token, body }));
check("撮合成功", m.result.status === 200, m.result.body);
check("写 nonce + 写 punch_request", m.s.by["INSERT nonces"] === 1 && m.s.by["INSERT events"] === 1, m.s.by);
const replay = await call("POST", "/v1/connect", { token, body });
check("重放被拒", replay.status === 403 && String(replay.body.detail).includes("重放"), replay.body);

console.log("\n8. 查询计划：广播不能让 events 退化成全表扫描");
const plan = db
  .prepare(
    `EXPLAIN QUERY PLAN SELECT id, type, payload FROM events
      WHERE network_id = ? AND node_id IN (?, '*') AND id > ? AND created_at >= ?
      ORDER BY id LIMIT ?`,
  )
  .all("n", "x", 0, 0, 50)
  .map((r) => r.detail)
  .join(" | ");
check("走 events_by_node 索引", /SEARCH events USING INDEX events_by_node/.test(plan) && !/SCAN events/.test(plan), plan);

console.log(`\n结果：${passed} 通过，${failed} 失败`);
process.exit(failed === 0 ? 0 : 1);
