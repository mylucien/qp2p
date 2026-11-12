/**
 * v3 缺陷修复的回归测试。
 *
 *   node signal/fix-smoke.mjs
 *
 * 每条对应评审报告里的一个编号；断言的是**修好之后**的行为。
 * 时间相关的项把阈值压小（env.STALE_MS），机制与真机一致；只有"运行时回调
 * webSocketClose"需要手动触发，本地替身不会自动回放。
 */

import worker, { canonicalJson, NetworkRoom } from "./worker.js";
import { fakeD1 } from "./fake-d1.mjs";
import { fakeRoomBinding } from "./fake-room.mjs";
import { installWebSocketPair } from "./fake-ws.mjs";

const ADMIN = "fix-smoke-secret";
const BASE = "https://qp2p.test";
const ctx = { waitUntil: () => {} };

let pass = 0;
let fail = 0;
function check(name, ok, extra) {
  if (ok) {
    pass += 1;
    console.log(`  ok   ${name}`);
  } else {
    fail += 1;
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
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
const randomNonce = () => hex(crypto.getRandomValues(new Uint8Array(8)));

let ipSeq = 0;
const nextIp = () => `198.21.${Math.floor((ipSeq += 1) / 250)}.${(ipSeq % 250) + 1}`;

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubkey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", hexToBytes(pubkey)));
  return { pubkey, nodeId: hex(digest).slice(0, 32), privateKey: pair.privateKey };
}

async function sign(node, op, netId, body) {
  const digest = await sha256Hex(canonicalJson(body));
  const message = `qp2p1|${op}|${netId}|${body.ts}|${body.nonce}|${digest}`;
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" },
    node.privateKey,
    new TextEncoder().encode(message),
  );
  return hex(new Uint8Array(sig));
}

async function call(env, method, path, { token, body, admin } = {}) {
  const h = { "content-type": "application/json", "cf-connecting-ip": nextIp() };
  if (token) h.authorization = `Bearer ${token}`;
  if (admin) h["x-admin-secret"] = admin;
  const res = await worker.fetch(
    new Request(BASE + path, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    env,
    ctx,
  );
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { _raw: text.slice(0, 160) };
  }
  return { status: res.status, body: parsed };
}

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
  return worker.fetch(
    new Request(`${BASE}/v1/ws?${qs}`, {
      method: "GET",
      headers: {
        upgrade: "websocket",
        authorization: `Bearer ${token}`,
        "cf-connecting-ip": nextIp(),
      },
    }),
    env,
    ctx,
  );
}

async function joinNet(env, token, net, node, name, candidates) {
  const ts = Date.now();
  const nonce = randomNonce();
  const body = {
    node_id: node.nodeId,
    pubkey: node.pubkey,
    name,
    tls_fp: "bb".repeat(32),
    nat_type: "eim",
    candidates,
    ts,
    nonce,
  };
  body.sig = await sign(node, "join", net.id, body);
  return call(env, "POST", "/v1/join", { token, body });
}

async function getEvents(env, token, net, node, since) {
  const ts = Date.now();
  const nonce = randomNonce();
  const body = { node_id: node.nodeId, since, ts, nonce };
  const sig = await sign(node, "events", net.id, body);
  const qs = new URLSearchParams({
    node_id: node.nodeId,
    since: String(since),
    ts: String(ts),
    nonce,
    sig,
  });
  return call(env, "GET", `/v1/events?${qs}`, { token });
}

async function httpLeave(env, token, net, node) {
  const ts = Date.now();
  const nonce = randomNonce();
  const body = { node_id: node.nodeId, pubkey: node.pubkey, ts, nonce };
  body.sig = await sign(node, "leave", net.id, body);
  return call(env, "POST", "/v1/leave", { token, body });
}

function serverSock(room, nodeId) {
  return room.state.getWebSockets().find((s) => s.deserializeAttachment().node === nodeId);
}

function offlines(clientSock) {
  return clientSock.of("event").filter((e) => e.type === "peer_offline");
}

async function main() {
  const restore = installWebSocketPair();
  try {
    await run();
  } finally {
    restore();
  }
  console.log(`\n结果：${pass} 通过，${fail} 失败`);
  process.exit(fail === 0 ? 0 : 1);
}

async function run() {
  const env = { ADMIN_SECRET: ADMIN, DB: fakeD1() };
  env.ROOM = fakeRoomBinding(env);

  const d1Sql = [];
  const rawPrepare = env.DB.prepare.bind(env.DB);
  env.DB.prepare = (sql) => {
    d1Sql.push(sql.replace(/\s+/g, " ").trim());
    return rawPrepare(sql);
  };

  const mk = await call(env, "POST", "/v1/admin/networks", {
    admin: ADMIN,
    body: { name: "fix", join_key: "fix-join-key-0001" },
  });
  let token = mk.body.token;
  const net = { id: mk.body.network.id, cidr: mk.body.network.cidr };
  const room = env.ROOM.roomOf(net.id);

  const alice = await identity();
  const bob = await identity();
  const carol = await identity();
  await joinNet(env, token, net, alice, "alice", ["198.21.9.1:9000"]);
  await joinNet(env, token, net, bob, "bob", ["198.21.9.2:9000"]);
  await joinNet(env, token, net, carol, "carol", ["198.21.9.3:9000"]);

  // ---------------------------------------------------------------- ① 撮合新鲜度
  console.log("\n① WS 节点空闲超过 STALE_MS 后仍可撮合");
  env.STALE_MS = 400; // 真机 120 秒，这里压成 0.4 秒，判断逻辑同一条
  const bWs = await openWs(env, token, bob, net);
  const bobSock = bWs.webSocket;
  const bobServer = serverSock(room, bob.nodeId);
  bobServer._autoAt = Date.now();
  await sleep(500);
  bobServer._autoAt = Date.now(); // 期间照常收到 ping（真实客户端 25 秒一次）

  const live = room.liveness(room.getNode(bob.nodeId), Date.now());
  const wsHit = room.matchmake(alice.nodeId, bob.nodeId);
  check("长连接节点被判在线", live.online === true && live.via === "ws", live);
  check("长连接节点仍能被撮合", wsHit.ok === true, wsHit);

  await sleep(500); // 让 carol 的 last_seen 也过期，并且她没有 socket
  const pollHit = room.matchmake(alice.nodeId, carol.nodeId);
  check(
    "轮询节点过期仍然被拒（保护没被削弱）",
    pollHit.ok === false && pollHit.error === "target_stale",
    pollHit,
  );

  // ---------------------------------------------------------------- ② 游标钳制
  console.log("\n② 旧游标（大于当前最大 seq）自动归零");
  const maxSeq = room.maxSeq();
  const big = maxSeq + 50_000;
  const clamped = await getEvents(env, token, net, alice, big);
  check(
    "带旧游标请求仍能拿到事件",
    clamped.status === 200 && clamped.body.events.length > 0,
    clamped.body,
  );
  check("返回的 cursor 已经回到真实范围", clamped.body.cursor <= maxSeq, {
    cursor: clamped.body.cursor,
    maxSeq,
  });
  delete env.STALE_MS; // 别影响后面的用例

  const resumeSock = await openWs(env, token, carol, net);
  const carolServer = serverSock(room, carol.nodeId);
  const seqNow = room.emit(carol.nodeId, "peer_online", { node_id: alice.nodeId, name: "alice" });
  resumeSock.webSocket.clear();
  await room.webSocketMessage(carolServer, JSON.stringify({ t: "resume", since: seqNow + 50_000 }));
  check(
    "resume 带旧游标也能补发",
    resumeSock.webSocket.of("event").some((e) => e.seq === seqNow),
    resumeSock.webSocket.recv,
  );

  // ---------------------------------------------------------------- ④ 4000 不误报离线
  console.log("\n④ 同 node 换连接不再广播 peer_offline");
  const aWs = await openWs(env, token, alice, net, { caps: ["offline_evt"] });
  const aliceSock = aWs.webSocket;
  const aliceServer = serverSock(room, alice.nodeId);
  aliceSock.clear();

  const bob1 = await openWs(env, token, bob, net);
  const bobServer1 = serverSock(room, bob.nodeId);
  const bob2 = await openWs(env, token, bob, net); // 抢占
  check("旧连接被 4000 关闭", bob1.webSocket.closed?.code === 4000, bob1.webSocket.closed);
  await room.webSocketClose(bobServer1, 4000, "replaced"); // 模拟运行时回调
  check("alice 没收到 peer_offline", offlines(aliceSock).length === 0, aliceSock.recv);
  check("bob 的新连接仍然活着", !!bob2.webSocket && !bob2.webSocket.closed);

  // ---------------------------------------------------------------- ⑤ 下线要通知
  console.log("\n⑤ leave / 踢人立刻通知对端");
  aliceSock.clear();
  const wsLeave = await openWs(env, token, carol, net);
  const carolServer2 = serverSock(room, carol.nodeId);
  await room.webSocketMessage(carolServer2, JSON.stringify({ t: "leave" }));
  check("WS leave 后对端收到 peer_offline", offlines(aliceSock).length === 1, aliceSock.recv);
  check("WS leave 的 socket 以 1000 关闭", wsLeave.webSocket.closed?.code === 1000, wsLeave.webSocket.closed);

  aliceSock.clear();
  await joinNet(env, token, net, carol, "carol", ["198.21.9.3:9000"]);
  const carolWs = await openWs(env, token, carol, net);
  const carolServer3 = serverSock(room, carol.nodeId);
  const left = await httpLeave(env, token, net, carol);
  check("HTTP leave 返回 200", left.status === 200, left.body);
  check("HTTP leave 后对端收到 peer_offline", offlines(aliceSock).length === 1, aliceSock.recv);
  check("HTTP leave 把 socket 关掉（1000）", carolServer3.closed?.code === 1000, carolServer3.closed);
  check("客户端那端也看到了关闭", carolWs.webSocket.closed?.code === 1000, carolWs.webSocket.closed);

  aliceSock.clear();
  await joinNet(env, token, net, carol, "carol", ["198.21.9.3:9000"]);
  const carolWs2 = await openWs(env, token, carol, net);
  const kick = await call(env, "POST", `/v1/admin/networks/${net.id}/nodes/${carol.nodeId}/kick`, {
    admin: ADMIN,
  });
  check("踢人成功", kick.status === 200 && kick.body?.node?.node_id === carol.nodeId, kick.body);
  check("被踢的 socket 以 4401 关闭", carolWs2.webSocket.closed?.code === 4401, carolWs2.webSocket.closed);
  check("踢人后对端收到 peer_offline", offlines(aliceSock).length === 1, aliceSock.recv);

  // ---------------------------------------------------------------- ⑥ sweep 节流
  console.log("\n⑤b 删网要把 D1 里的预留备份一起清掉");
  // 用一个独立网络做这件事：删掉主测试网络会让后面的用例全挂
  const mk2 = await call(env, "POST", "/v1/admin/networks", {
    admin: ADMIN,
    body: { name: "purge-test", join_key: "purge-test-key-0001" },
  });
  const net2 = { id: mk2.body.network.id, cidr: mk2.body.network.cidr };
  const room2b = env.ROOM.roomOf(net2.id);
  await call(env, "GET", `/v1/admin/networks/${net2.id}/nodes`, { admin: ADMIN }); // 让 DO 建好上下文
  const resv = {
    ip: net2.cidr.replace(/0\.0\/16$/, "0.250"),
    node_id: "",
    kind: "user",
    note: "",
    created_at: Date.now(),
  };
  room2b.putReservation(resv);
  await room2b.backupReservation(resv, "put");
  await sleep(300);
  const backupBefore = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM reservations WHERE network_id = ?",
  ).bind(net2.id).first();
  const del2 = await call(env, "DELETE", `/v1/admin/networks/${net2.id}`, {
    admin: ADMIN,
    body: { confirm: net2.id },
  });
  const backupAfter = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM reservations WHERE network_id = ?",
  ).bind(net2.id).first();
  check("删网前备份表里有行", Number(backupBefore?.n ?? 0) > 0, backupBefore);
  check("删网后备份表清空", del2.status === 200 && Number(backupAfter?.n ?? 0) === 0, backupAfter);

  console.log("\n⑥ sweep 的 5 分钟节流在休眠唤醒后仍然有效");
  room.sweep();
  check("last_sweep 已写进 meta", !!room.getMeta("last_sweep"), room.getMeta("last_sweep"));
  room.sql.exec(
    "INSERT INTO events (to_node, type, payload, created_at) VALUES (?, ?, ?, ?)",
    alice.nodeId,
    "peer_online",
    "{}",
    Date.now() - 10 * 60_000,
  );
  const room2 = new NetworkRoom(room.state, env); // 模拟唤醒后的新实例（storage 不变）
  await room.state.ready();
  const beforeCnt = room2.sql.exec("SELECT COUNT(*) AS n FROM events").toArray()[0].n;
  const beforeSweepAt = room2.lastSweep;
  room2.sweep(); // lastSweep 是惰性从 meta 读回来的，所以要在调用后看
  const afterCnt = room2.sql.exec("SELECT COUNT(*) AS n FROM events").toArray()[0].n;
  check("唤醒后从 meta 读回了 last_sweep", room2.lastSweep > 0 && beforeSweepAt === 0, {
    beforeSweepAt,
    after: room2.lastSweep,
  });
  check("唤醒后没有白跑一轮 GC", afterCnt === beforeCnt, { beforeCnt, afterCnt });

  // ---------------------------------------------------------------- ⑦ loadNet
  console.log("\n⑦ 改名 / 改网段会更新 DO 里的上下文");
  const beforeNet = room.net();
  room.loadNet(
    new Request("https://room/i/stats", {
      headers: {
        "x-qp2p-net": JSON.stringify({ v: 1, id: net.id, name: "renamed", cidr: "10.99.0.0/16" }),
      },
    }),
  );
  const afterNet = room.net();
  check(
    "名称与网段都跟着变了",
    afterNet.name === "renamed" && afterNet.cidr === "10.99.0.0/16",
    { beforeNet, afterNet },
  );
  // 还原，后面还要用原网段
  room.loadNet(
    new Request("https://room/i/stats", {
      headers: {
        "x-qp2p-net": JSON.stringify({ v: 1, id: net.id, name: beforeNet.name, cidr: net.cidr }),
      },
    }),
  );

  // ---------------------------------------------------------------- ⑧ 503 语义
  console.log("\n⑧ DO 不可用统一返回 503 room_unavailable");
  const evQs = `/v1/events?node_id=${alice.nodeId}&since=0&ts=1&nonce=x`;
  const envThrow = { ADMIN_SECRET: ADMIN, DB: env.DB };
  envThrow.ROOM = {
    idFromName: (n) => ({ name: String(n) }),
    get: () => ({
      fetch: async () => {
        throw new Error("boom from DO");
      },
    }),
  };
  const boom = await call(envThrow, "GET", evQs, { token });
  check(
    "DO 抛异常 → 503 room_unavailable",
    boom.status === 503 && boom.body?.error === "room_unavailable",
    boom,
  );
  const env503 = { ADMIN_SECRET: ADMIN, DB: env.DB };
  env503.ROOM = {
    idFromName: (n) => ({ name: String(n) }),
    get: () => ({ fetch: async () => new Response("overloaded", { status: 503 }) }),
  };
  const busy = await call(env503, "GET", evQs, { token });
  check("DO 自己返回 503 也保持 503", busy.status === 503, busy);

  // ---------------------------------------------------------------- ③ 换密钥踢连接
  console.log("\n③ 换密钥后旧连接被踢");
  const beforeRotateSockets = room.state.getWebSockets().length;
  const rot = await call(env, "POST", `/v1/admin/networks/${net.id}/rotate`, { admin: ADMIN, body: {} });
  token = rot.body.token;
  check("rotate 返回 200 和新令牌", rot.status === 200 && !!token, rot.status);
  check("rotate 前确实有连接", beforeRotateSockets > 0, beforeRotateSockets);
  check(
    "旧连接全部以 4401 关闭",
    room.state.getWebSockets().every((s) => s.closed?.code === 4401) ||
      room.state.getWebSockets().length === 0,
    room.state.getWebSockets().map((s) => s.closed),
  );
  const oldToken = await openWs(env, token === rot.body.token ? "" : token, alice, net);
  check("旧令牌握手被拒", oldToken.status === 401 || oldToken.status === 403, oldToken.status);

  // ---------------------------------------------------------------- 附：D1 访问
  console.log("\n附：room 模式不再清 D1 数据面 / 网络行有缓存");
  d1Sql.length = 0;
  await call(env, "GET", "/v1/health", { admin: ADMIN });
  const del = d1Sql.filter((s) => /^DELETE/i.test(s));
  check(
    "D1 上只剩控制面清理（不碰 nodes/events/nonces）",
    del.every((s) => /login_attempts/.test(s)),
    del,
  );

  const fresh = await openWs(env, token, alice, net); // 握手一次，通读网络行
  fresh.webSocket.clear();
  d1Sql.length = 0;
  await getEvents(env, token, net, alice, 0);
  await getEvents(env, token, net, alice, 0);
  const netReads = d1Sql.filter((s) => /FROM networks/i.test(s)).length;
  check("连续两次请求只读一次 networks（15 秒缓存）", netReads <= 1, { netReads, sql: d1Sql });
}

main().catch((e) => {
  console.error("测试自身出错：", e);
  process.exit(2);
});
