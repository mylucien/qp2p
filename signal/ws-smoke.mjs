/**
 * WebSocket 本地冒烟（P3）。
 *
 *   node signal/ws-smoke.mjs
 *
 * 走的是真实入口：worker.fetch → wsEntry → DO.resolve → NetworkRoom.acceptWs，
 * 只有 WebSocketPair 是替身（真机的由运行时提供）。断言覆盖握手验签、hello、
 * 抢占旧连接、connect/resume/leave、限流、关闭码规范化、liveness 与 peer_offline。
 *
 * 真机上"自动应答时间戳会不会推进"（V9）这里验不了，用 socket._autoAt 模拟。
 */

import worker, { canonicalJson } from "./worker.js";
import { fakeD1 } from "./fake-d1.mjs";
import { fakeRoomBinding } from "./fake-room.mjs";
import { installWebSocketPair } from "./fake-ws.mjs";

const ADMIN_SECRET = "ws-smoke-secret";
const BASE = "https://qp2p.test";
const ctx = { waitUntil: () => {} };

let passed = 0;
let failed = 0;
let ipSeq = 0;

function check(name, ok, extra) {
  if (ok) {
    passed += 1;
    console.log(`  ok   ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${name}${extra !== undefined ? ` → ${JSON.stringify(extra)}` : ""}`);
  }
}

// --- 小工具 -----------------------------------------------------------------

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

function randomNonce() {
  return hex(crypto.getRandomValues(new Uint8Array(8)));
}

/** 每次请求换一个 IP，避免各用例互相吃满限流桶。 */
function nextIp() {
  ipSeq += 1;
  return `198.19.${Math.floor(ipSeq / 250)}.${(ipSeq % 250) + 1}`;
}

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubkey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", hexToBytes(pubkey)));
  return { pubkey, nodeId: hex(digest).slice(0, 32), privateKey: pair.privateKey };
}

async function sign(node, op, net, body) {
  const digest = await sha256Hex(canonicalJson(body));
  const message = `qp2p1|${op}|${net}|${body.ts}|${body.nonce}|${digest}`;
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, node.privateKey, new TextEncoder().encode(message));
  return hex(new Uint8Array(sig));
}

async function call(env, method, path, { token, body, admin, headers = {} } = {}) {
  const h = { "content-type": "application/json", "cf-connecting-ip": nextIp(), ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (admin) h["x-admin-secret"] = admin;
  const res = await worker.fetch(
    new Request(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }),
    env,
    ctx,
  );
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { _raw: text.slice(0, 200) };
  }
  return { status: res.status, body: parsed };
}

/** 握手。返回 101 响应或错误响应。 */
async function openWs(env, token, node, net, opts = {}) {
  const ts = Date.now();
  const nonce = randomNonce();
  const since = opts.since ?? 0;
  const caps = [...(opts.caps ?? [])].sort().join(",");
  const payload = { node_id: node.nodeId, since, ts, nonce, caps };
  const sig = await sign(node, "ws", net.id, payload);
  const qs = new URLSearchParams({
    node_id: node.nodeId,
    since: String(since),
    ts: String(ts),
    nonce,
    caps,
    sig,
  });
  const res = await worker.fetch(
    new Request(`${BASE}/v1/ws?${qs}`, {
      method: "GET",
      headers: {
        upgrade: "websocket",
        authorization: `Bearer ${token}`,
        "cf-connecting-ip": opts.ip ?? nextIp(),
      },
    }),
    env,
    ctx,
  );
  return res;
}

async function main() {
  const restore = installWebSocketPair();
  try {
    await run();
  } finally {
    restore();
  }
  console.log(`\n结果：${passed} 通过，${failed} 失败`);
  process.exit(failed === 0 ? 0 : 1);
}

async function run() {
  const env = { ADMIN_SECRET, DB: fakeD1() };
  env.ROOM = fakeRoomBinding(env);

  console.log("\n1. 准备工作");
  const mk = await call(env, "POST", "/v1/admin/networks", {
    admin: ADMIN_SECRET,
    body: { name: "ws-net", join_key: "ws-join-key-0001" },
  });
  check("建网", mk.status === 201 || mk.status === 200, mk.body);
  const token = mk.body.token;
  const net = { id: mk.body.network.id, cidr: mk.body.network.cidr };
  check("拿到网络 id 与令牌", /^[a-z0-9-]+$/.test(net.id ?? "") && !!token, { net, tokenLen: token?.length });

  const alice = await identity();
  const bob = await identity();

  async function join(node, name, candidates) {
    const ts = Date.now();
    const nonce = randomNonce();
    const body = {
      node_id: node.nodeId,
      pubkey: node.pubkey,
      name,
      tls_fp: "aa".repeat(32),
      nat_type: "eim",
      candidates,
      ts,
      nonce,
    };
    body.sig = await sign(node, "join", net.id, body);
    return call(env, "POST", "/v1/join", { token, body });
  }

  const aJoin = await join(alice, "alice", ["198.18.9.1:9000"]);
  check("alice join", aJoin.status === 200 && aJoin.body.ok === true, aJoin.body);
  const bJoin = await join(bob, "bob", ["198.18.9.2:9000"]);
  check("bob join", bJoin.status === 200 && bJoin.body.ok === true, bJoin.body);

  const room = env.ROOM.roomOf(net.id);

  console.log("\n1.5 预留备份到 D1（重新部署后能恢复）");
  // join 之后会有一条空载体产生的 auto 预留，备份是异步写 D1 的，等它落地
  await new Promise((r) => setTimeout(r, 300));
  const before = room.listReservations();
  check("join 产生了预留", before.length >= 1, before);

  // 模拟"重新部署"：DO 是全新的，只有 D1 里那份旧数据
  room.sql.exec("DELETE FROM reservations");
  room.sql.exec("DELETE FROM meta WHERE k = 'reservations_restored'");
  room._reservationsReady = false;
  check("清空 DO 后没有预留", room.listReservations().length === 0);

  await room.ensureReservations();
  const restored = room.listReservations();
  check(
    "从 D1 恢复回来",
    restored.length === before.length,
    { before: before.length, after: restored.length },
  );
  check(
    "恢复的地址与原来一致",
    before.every((b) => restored.some((r) => r.ip === b.ip && r.node_id === b.node_id)),
    { before, restored },
  );

  console.log("\n2. 握手前置条件");
  const noUpgrade = await call(env, "GET", `/v1/ws?node_id=${alice.nodeId}`, { token });
  check("缺 Upgrade → 426", noUpgrade.status === 426, noUpgrade.body);

  const legacyEnv = { ADMIN_SECRET, DB: fakeD1() };
  const legacyRes = await worker.fetch(
    new Request(`${BASE}/v1/ws`, { headers: { upgrade: "websocket", authorization: `Bearer ${token}` } }),
    legacyEnv,
    ctx,
  );
  check("未绑定 DO → 501", legacyRes.status === 501, await legacyRes.text());

  const unknown = await identity();
  const r404 = await openWs(env, token, unknown, net);
  check("未登记节点 → 404", r404.status === 404, r404.status);

  const badSig = await worker.fetch(
    new Request(
      `${BASE}/v1/ws?node_id=${alice.nodeId}&since=0&ts=${Date.now()}&nonce=${randomNonce()}&caps=&sig=${"00".repeat(64)}`,
      { headers: { upgrade: "websocket", authorization: `Bearer ${token}`, "cf-connecting-ip": nextIp() } },
    ),
    env,
    ctx,
  );
  check("签名错误 → 403", badSig.status === 403, badSig.status);

  // 曾经用 slice(0,16) 静默截断，导致客户端签的是全量、服务端算的是截断后的，
  // 表现为永远 bad_signature。现在必须明确拒绝。
  const manyCaps = Array.from({ length: 17 }, (_, i) => `cap${i}`);
  const tooMany = await openWs(env, token, alice, net, { caps: manyCaps });
  check("caps 超过 16 项 → 400", tooMany.status === 400, tooMany.status);

  console.log("\n3. 握手成功与 hello");
  const resA = await openWs(env, token, alice, net, { caps: ["offline_evt"] });
  check("alice 升级 101", resA.status === 101, resA.status);
  const sockA = resA.webSocket;
  const serverA = room.state.getWebSockets()[0];
  const hello = sockA.last();
  check("hello.t=hello", hello?.t === "hello", hello);
  check("hello.v=1", hello?.v === 1, hello?.v);
  check("hello 带 cursor/epoch/limits", typeof hello?.cursor === "number" && !!hello?.epoch && !!hello?.limits, hello);
  check("limits 含 ping_every_ms=25000", hello?.limits?.ping_every_ms === 25000, hello?.limits);
  check("attachment 记下 caps", serverA.deserializeAttachment().caps.join(",") === "offline_evt", serverA.deserializeAttachment());

  console.log("\n4. 同 node 的第二条连接抢占旧连接");
  const resA2 = await openWs(env, token, alice, net, { caps: ["offline_evt"] });
  check("第二条也升级成功", resA2.status === 101, resA2.status);
  check("旧 socket 收到 4000", sockA.closed?.code === 4000, sockA.closed);
  const sockA2 = resA2.webSocket;
  const serverA2 = room.state.getWebSockets()[0];
  check("state 里只剩一条 socket", room.state.getWebSockets().length === 1, room.state.getWebSockets().length);
  check("存活的是新连接", serverA2.deserializeAttachment().node === alice.nodeId);

  console.log("\n5. connect 消息");
  // bob 还没连，先测 target_offline
  serverA2.recv.length = 0;
  await room.webSocketMessage(serverA2, JSON.stringify({ t: "connect", req: 1, target: bob.nodeId }));
  const off = sockA2.last();
  check("目标无 socket 且刚 join → connect_ok", off?.t === "connect_ok", off);

  const resB = await openWs(env, token, bob, net);
  check("bob 升级 101", resB.status === 101, resB.status);
  const sockB = resB.webSocket;
  const serverB = room.state.getWebSockets().find((s) => s.deserializeAttachment().node === bob.nodeId);
  check("两条 socket 并存", room.state.getWebSockets().length === 2, room.state.getWebSockets().length);

  sockA2.clear();
  sockB.clear();
  await room.webSocketMessage(serverA2, JSON.stringify({ t: "connect", req: 7, target: bob.nodeId }));
  const ok = sockA2.last();
  check("connect_ok 回显 req", ok?.t === "connect_ok" && ok?.req === 7, ok);
  check("connect_ok 带候选与指纹", Array.isArray(ok?.target_candidates) && !!ok?.target_tls_fp, ok);
  check("connect_ok 用 punch_at 承载打洞时间", typeof ok?.punch_at === "number" && ok.t === "connect_ok", ok);
  const punch = sockB.of("event").find((e) => e.type === "punch_request");
  check("bob 直接收到 punch_request（不落库等下一次拉取）", !!punch && punch.from === alice.nodeId, punch);
  check("punch_request 带 seq", typeof punch?.seq === "number" && punch.seq > 0, punch?.seq);

  sockA2.clear();
  await room.webSocketMessage(serverA2, JSON.stringify({ t: "connect", req: 8, target: alice.nodeId }));
  const selfErr = sockA2.last();
  check("连自己 → error", selfErr?.t === "error" && selfErr?.error === "self_connect", selfErr);

  console.log("\n6. resume 补发");
  // 直接往 bob 写一条事件，再用 resume 拉
  const seq = room.emit(bob.nodeId, "peer_online", { node_id: alice.nodeId, name: "alice" });
  sockB.clear();
  await room.webSocketMessage(serverB, JSON.stringify({ t: "resume", since: seq - 1 }));
  const resumed = sockB.of("event").find((e) => e.seq === seq);
  check("resume 补上这条事件", !!resumed && resumed.type === "peer_online", sockB.recv);
  check("resume 结束有 resume_ok", sockB.of("resume_ok").length === 1, sockB.of("resume_ok"));

  console.log("\n7. 消息限流与上限");
  const resC = await openWs(env, token, (await identity()), net); // 未登记，只为占位
  check("未登记仍 404（限流前先验节点）", resC.status === 404);

  let lastRate = null;
  for (let i = 0; i < 25; i += 1) {
    await room.webSocketMessage(serverB, JSON.stringify({ t: "ping_app_level", i }));
    if (serverB.closed) {
      lastRate = serverB.closed;
      break;
    }
  }
  check("第 21 条后按 4429 关闭", lastRate?.code === 4429, lastRate);

  const resD = await openWs(env, token, bob, net);
  check("bob 重连成功", resD.status === 101, resD.status);
  const sockD = resD.webSocket;
  const serverD = room.state.getWebSockets().find((s) => s.deserializeAttachment().node === bob.nodeId);
  await room.webSocketMessage(serverD, "x".repeat(5000));
  check("超大消息按 4429 关闭", sockD.closed?.code === 4429, sockD.closed);

  // 上限按**字节**算：1500 个汉字只有 1500 个字符，但 4500 字节，必须被判超限
  const resD2 = await openWs(env, token, bob, net);
  const serverD2 = room.state
    .getWebSockets()
    .find((s) => s.deserializeAttachment().node === bob.nodeId);
  await room.webSocketMessage(serverD2, "汉".repeat(1500));
  check("中文按字节判定超限", resD2.webSocket.closed?.code === 4429, resD2.webSocket.closed);

  const resE = await openWs(env, token, bob, net);
  const serverE = room.state.getWebSockets().find((s) => s.deserializeAttachment().node === bob.nodeId);
  check("非法 JSON 不关闭连接", await (async () => {
    await room.webSocketMessage(serverE, "{not json");
    return serverE.closed === null;
  })());

  console.log("\n8. 关闭码规范化与 last_seen");
  await room.webSocketClose(serverE, 1006, "abnormal");
  check("1006 回关成 1000", resE.webSocket.closed?.code === 1000, resE.webSocket.closed);
  check("关闭后 socket 从列表摘除", !room.state.getWebSockets().includes(serverE));

  const bobRow = room.getNode(bob.nodeId);
  check("关闭时写了 last_seen", bobRow.last_seen > 0);

  console.log("\n9. liveness 走 socket 分支");
  const resF = await openWs(env, token, bob, net);
  const serverF = room.state.getWebSockets().find((s) => s.deserializeAttachment().node === bob.nodeId);
  const live = room.liveness(room.getNode(bob.nodeId), Date.now());
  check("有 socket 时 via=ws", live.via === "ws", live);
  check("刚连上算在线", live.online === true, live);

  // 管理面必须也按 socket 判定：以前它只看 last_seen，长连接节点会被显示成离线
  const list = await call(env, "GET", `/v1/admin/networks/${net.id}/nodes`, { admin: ADMIN_SECRET });
  const bobAdminRow = list.body.nodes?.find((n) => n.node_id === bob.nodeId);
  check(
    "管理面把长连接节点标成 ws 在线",
    bobAdminRow?.via === "ws" && bobAdminRow?.online === true,
    bobAdminRow,
  );

  serverF._autoAt = Date.now() - 100_000; // 超过 WS_GRACE(75s)
  const stale = room.liveness(room.getNode(bob.nodeId), Date.now());
  check("时间戳过旧 → 离线", stale.online === false, stale);

  serverF._autoAt = Date.now() - 1_000;
  const fresh = room.liveness(room.getNode(bob.nodeId), Date.now());
  check("时间戳刷新后 → 在线", fresh.online === true, fresh);

  console.log("\n10. peer_offline 只推给声明能力的 socket");
  const aliceSock = room.state.getWebSockets().find((s) => s.deserializeAttachment().node === alice.nodeId);
  check("alice 声明了 offline_evt", aliceSock.deserializeAttachment().caps.includes("offline_evt"));
  resF.webSocket.clear();
  await room.webSocketClose(serverF, 1000, "bye");
  const offline = resF.webSocket.of("event").find((e) => e.type === "peer_offline");
  check("bob 自己不收自己的 peer_offline", !offline, resF.webSocket.recv);

  const bobSock2 = await (async () => {
    // 用一个不声明 offline_evt 的 bob 连接，确认它收不到 alice 的离线推送
    const r = await openWs(env, token, bob, net);
    return { res: r, server: room.state.getWebSockets().find((s) => s.deserializeAttachment().node === bob.nodeId) };
  })();
  resA2.webSocket.clear();
  await room.webSocketClose(serverA2, 1000, "bye");
  const bobOffline = bobSock2.res.webSocket.of("event").find((e) => e.type === "peer_offline");
  check("未声明 offline_evt 的 socket 收不到", !bobOffline, bobSock2.res.webSocket.recv);

  console.log("\n11. 踢人：先给原因再关");
  const resG = await openWs(env, token, bob, net);
  const serverG = room.state.getWebSockets().find((s) => s.deserializeAttachment().node === bob.nodeId);
  const kickRes = await call(env, "POST", `/v1/admin/networks/${net.id}/nodes/${bob.nodeId}/kick`, {
    admin: ADMIN_SECRET,
    body: {},
  });
  check(
    "踢人接口成功",
    kickRes.status === 200 && kickRes.body.ok === true && kickRes.body.node?.node_id === bob.nodeId,
    kickRes.body,
  );
  const kickMsg = resG.webSocket.of("kick")[0];
  check("先收到 kick 消息", !!kickMsg, resG.webSocket.recv);
  check("随后以 4401 关闭", resG.webSocket.closed?.code === 4401, resG.webSocket.closed);
  check("节点记录已删除", room.getNode(bob.nodeId) === null);

  console.log("\n12. purge 关闭全部连接");
  const resH = await openWs(env, token, alice, net, { caps: ["offline_evt"] });
  check("alice 重新连上", resH.status === 101, resH.status);
  const alive = room.state.getWebSockets();
  check("purge 前有连接", alive.length >= 1, alive.length);
  const del = await call(env, "DELETE", `/v1/admin/networks/${net.id}`, { admin: ADMIN_SECRET, body: { confirm: net.id } });
  check("删除网络成功", del.status === 200 && del.body.ok === true, del.body);
  check(
    "purge 后全部以 4410 关闭",
    alive.length > 0 && alive.every((s) => s.closed?.code === 4410),
    alive.map((s) => s.closed),
  );

  console.log("\n13. health 声明了 ws 能力");
  const health = await call(env, "GET", "/v1/health", { admin: ADMIN_SECRET });
  check("features 含 ws", Array.isArray(health.body.features) && health.body.features.includes("ws"), health.body.features);
  check("limits 随 health 下发", health.body.limits?.ws_grace_ms === 75000, health.body.limits);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
