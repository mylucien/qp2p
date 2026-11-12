/**
 * WebSocket 真机验收（手动运行，CI 不跑）。
 *
 *   ADMIN_SECRET=xxx node signal/ws-live.mjs https://your-worker.example
 *
 * 覆盖本地测不出来的两件事：
 *   1. **V9**：`ping`/`pong` 由运行时自动应答，`getWebSocketAutoResponseTimestamp`
 *      必须跟着推进。它不推进的话所有 WS 节点会被同时判成离线（在线判定的单点依赖）。
 *   2. 真机投递：connect_ok 与 punch_request 是直接推进 socket 的，不靠下一次拉取。
 *
 * 注意：Node 的全局 WebSocket 不能带自定义请求头，所以令牌走 `?token=`——
 * 服务端两条路都支持（浏览器原生 WebSocket 也不能带头，本来就是为它留的）。
 */

import { canonicalJson } from "./worker.js";

const BASE = (process.argv[2] ?? "").replace(/\/+$/, "");
const ADMIN = process.env.ADMIN_SECRET ?? "";

if (!BASE || !ADMIN) {
  console.error("用法：ADMIN_SECRET=xxx node signal/ws-live.mjs https://你的-worker");
  process.exit(2);
}

// 要超过服务端的 WS_GRACE（75 秒）才能观察"不发 ping 会掉线"，默认留 5 秒余量
const PING_WAIT_MS = Number(process.env.PING_WAIT_MS ?? 80_000);
let passed = 0;
let failed = 0;

function check(name, ok, extra) {
  if (ok) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${name}${extra !== undefined ? ` → ${JSON.stringify(extra)}` : ""}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function sha256Hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return hex(new Uint8Array(d));
}

function nonce() {
  return hex(crypto.getRandomValues(new Uint8Array(8)));
}

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubkey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", hexToBytes(pubkey)));
  return { pubkey, nodeId: hex(digest).slice(0, 32), privateKey: pair.privateKey };
}

async function sign(node, op, netId, body) {
  const digest = await sha256Hex(canonicalJson(body));
  const message = `qp2p1|${op}|${netId}|${body.ts}|${body.nonce}|${digest}`;
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, node.privateKey, new TextEncoder().encode(message));
  return hex(new Uint8Array(sig));
}

async function api(method, path, { token, body, admin, headers = {} } = {}) {
  const h = { "content-type": "application/json", ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (admin) h["x-admin-secret"] = admin;
  const res = await fetch(BASE + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { _raw: text.slice(0, 300) };
  }
  return { status: res.status, body: parsed };
}

/** 连一条 socket，等 hello。 */
async function connect(token, node, netId, caps = [], since = 0) {
  const ts = Date.now();
  const n = nonce();
  const capsStr = [...caps].sort().join(",");
  const payload = { node_id: node.nodeId, since, ts, nonce: n, caps: capsStr };
  const sig = await sign(node, "ws", netId, payload);
  const qs = new URLSearchParams({
    node_id: node.nodeId,
    since: String(since),
    ts: String(ts),
    nonce: n,
    caps: capsStr,
    sig,
    token,
  });
  const url = `${BASE.replace(/^http/, "ws")}/v1/ws?${qs}`;
  const ws = new WebSocket(url);
  const inbox = [];

  const hello = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("等 hello 超时（10 秒）")), 10_000);
    ws.addEventListener("message", (ev) => {
      const raw = String(ev.data);
      if (raw === "pong") return;
      let msg = null;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }
      inbox.push(msg);
      if (msg.t === "hello") {
        clearTimeout(timer);
        resolve(msg);
      }
    });
    ws.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("握手失败（连接被拒）"));
    });
    ws.addEventListener("close", (ev) => {
      clearTimeout(timer);
      reject(new Error(`握手后被关闭 code=${ev.code} ${ev.reason ?? ""}`));
    });
  });

  return { ws, hello, inbox };
}

/** 管理面看到的单个节点。`via` 说明判定依据，`online` 是最终结论。 */
async function nodeStatus(netId, nodeId) {
  const r = await api("GET", `/v1/admin/networks/${netId}/nodes`, { admin: ADMIN });
  return (r.body.nodes ?? []).find((n) => n.node_id === nodeId) ?? null;
}

async function main() {
  const name = `wslive-${Date.now().toString(36)}`;

  console.log(`\n目标 ${BASE}`);
  console.log("\n1. 建网与登记");
  const mk = await api("POST", "/v1/admin/networks", { admin: ADMIN, body: { name, join_key: `jk-${name}` } });
  check("建网", mk.status === 200 || mk.status === 201, mk.body);
  const token = mk.body.token;
  const netId = mk.body.network?.id;
  check("拿到网络 id", !!netId, netId);

  const alice = await identity();
  const bob = await identity();

  async function join(node, label) {
    const ts = Date.now();
    const n = nonce();
    const body = {
      node_id: node.nodeId,
      pubkey: node.pubkey,
      name: label,
      tls_fp: "bb".repeat(32),
      nat_type: "eim",
      candidates: [`203.0.113.${label === "alice" ? 10 : 11}:9000`],
      ts,
      nonce: n,
    };
    body.sig = await sign(node, "join", netId, body);
    return api("POST", "/v1/join", { token, body });
  }

  const joinedAt = Date.now();
  const aJ = await join(alice, "alice");
  check("alice join", aJ.status === 200, aJ.body);
  const bJ = await join(bob, "bob");
  check("bob join", bJ.status === 200, bJ.body);

  console.log("\n2. 握手与 hello");
  const a = await connect(token, alice, netId, ["offline_evt"]);
  check("alice 收到 hello", a.hello?.t === "hello", a.hello);
  check("hello 带 limits.ping_every_ms", a.hello?.limits?.ping_every_ms === 25_000, a.hello?.limits);
  check("hello 带 epoch", typeof a.hello?.epoch === "string" && a.hello.epoch.length > 0, a.hello?.epoch);
  const b = await connect(token, bob, netId);
  check("bob 收到 hello", b.hello?.t === "hello");

  // V9：在线判定完全依赖 `getWebSocketAutoResponseTimestamp`。验证方式是看
  // "不发 ping 会掉线、发了就回来"——这是走真实业务路径的观察，比读内部状态可靠。
  console.log("\n3. V9：自动应答是否驱动在线判定");
  const s0 = await nodeStatus(netId, alice.nodeId);
  check("节点列表里 alice 的判定依据是 ws", s0?.via === "ws", s0);
  check("刚连上算在线", s0?.online === true, s0);

  // 服务端宽限 75 秒；这段时间一个 ping 都不发，时间戳会停在建立连接的时刻
  const graceSec = Math.round(PING_WAIT_MS / 1000);
  console.log(`  故意不发 ping，等 ${graceSec} 秒（超过 75 秒宽限）…`);
  await sleep(PING_WAIT_MS);
  const s1 = await nodeStatus(netId, alice.nodeId);
  check("超过宽限没 ping → 判离线（说明判定真的看时间戳）", s1?.online === false, s1);

  a.ws.send("ping");
  console.log("  发了 ping，等 3 秒…");
  await sleep(3_000);
  const s2 = await nodeStatus(netId, alice.nodeId);
  check("ping 之后立刻回到在线（时间戳被刷新）→ V9 通过", s2?.online === true, s2);

  console.log("\n4. 真机投递：connect_ok 与 punch_request");
  // 第 3 节为了验 V9 让 alice 闲置了 80 秒；bob 同样没发过 ping，这会儿也过期了。
  // 撮合前先把两边都唤醒，否则拿到的是 target_offline 而不是 connect_ok。
  a.ws.send("ping");
  b.ws.send("ping");
  await sleep(2_000);
  b.inbox.length = 0;
  a.ws.send(JSON.stringify({ t: "connect", req: 11, target: bob.nodeId }));
  const t0 = Date.now();
  while (Date.now() - t0 < 8_000 && !a.inbox.some((m) => m.t === "connect_ok")) await sleep(150);
  const okMsg = a.inbox.find((m) => m.t === "connect_ok");
  check("收到 connect_ok 且 req 对得上", okMsg?.req === 11, okMsg);
  check("connect_ok 用 punch_at 承载打洞时间", typeof okMsg?.punch_at === "number", okMsg);
  check("connect_ok 带对端候选", Array.isArray(okMsg?.target_candidates), okMsg);

  const t1 = Date.now();
  while (Date.now() - t1 < 8_000 && !b.inbox.some((m) => m.type === "punch_request")) await sleep(150);
  const punch = b.inbox.find((m) => m.type === "punch_request");
  check("bob 直接收到 punch_request", !!punch && punch.from === alice.nodeId, punch);
  check("punch_request 有 seq 与 punch_at", typeof punch?.seq === "number" && typeof punch?.punch_at === "number", punch);

  console.log("\n5. resume 与关闭");
  b.inbox.length = 0;
  b.ws.send(JSON.stringify({ t: "resume", since: 0 }));
  const t2 = Date.now();
  while (Date.now() - t2 < 5_000 && !b.inbox.some((m) => m.t === "resume_ok")) await sleep(150);
  check("收到 resume_ok", b.inbox.some((m) => m.t === "resume_ok"), b.inbox.map((m) => m.t));

  a.ws.close(1000, "done");
  b.ws.close(1000, "done");
  await sleep(1_500);

  // ---- 回归：评审报告里的三处缺陷 ----
  console.log("\n6. 回归：长连接节点 2 分钟后仍可撮合");
  const closes = [];
  a.ws.addEventListener("close", (ev) => closes.push({ who: "alice", code: ev.code }));
  b.ws.addEventListener("close", (ev) => closes.push({ who: "bob", code: ev.code }));

  // 真实客户端每 25 秒发一次 ping；这里照做，等"注册已过去 130 秒"
  while (Date.now() - joinedAt < 130_000) {
    a.ws.send("ping");
    b.ws.send("ping");
    await sleep(25_000);
  }
  const stale = await nodeStatus(netId, bob.nodeId);
  check("bob 仍然在线（via=ws）", stale?.online === true && stale?.via === "ws", stale);

  b.inbox.length = 0;
  a.ws.send(JSON.stringify({ t: "connect", req: 901, target: bob.nodeId }));
  const t3 = Date.now();
  while (Date.now() - t3 < 8_000 && !a.inbox.some((m) => m.req === 901)) await sleep(150);
  const late = a.inbox.find((m) => m.req === 901);
  check(
    "注册过去 130 秒后仍能撮合（原来报 target_stale）",
    late?.t === "connect_ok",
    late,
  );

  console.log("\n7. 回归：换密钥把旧连接踢下线");
  const rot = await api("POST", `/v1/admin/networks/${netId}/rotate`, { admin: ADMIN, body: {} });
  check("rotate 返回新令牌", rot.status === 200 && !!rot.body.token, rot.status);
  await sleep(2_000);
  check(
    "两条旧连接都以 4401 关闭",
    closes.length >= 2 && closes.every((c) => c.code === 4401),
    closes,
  );

  console.log("\n8. 回归：旧游标不再饿死客户端");
  const since = 999_999;
  const b2 = await connect(rot.body.token, bob, netId, [], since);
  check("带旧游标的握手仍然成功", b2.hello?.t === "hello", b2.hello);
  check("hello 的 cursor 已经把旧游标压回真实范围", b2.hello?.cursor < since, b2.hello?.cursor);
  await sleep(1_500);
  const replayed = b2.inbox.filter((m) => m.t === "event");
  check("并且补发了真实事件（不是空列表）", replayed.length > 0, b2.inbox.map((m) => m.t));
  b2.ws.close(1000, "done");
  await sleep(500);

  console.log("\n9. 清理");
  const del = await api("DELETE", `/v1/admin/networks/${netId}`, { admin: ADMIN, body: { confirm: netId } });
  check("删除测试网络", del.status === 200 && del.body.ok === true, del.body);

  console.log(`\n结果：${passed} 通过，${failed} 失败`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\n中断：", e?.message ?? e);
  process.exit(1);
});
