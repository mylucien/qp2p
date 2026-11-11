/**
 * NetworkRoom 的本地冒烟（P1 骨架）。
 *
 *   node signal/room-smoke.mjs
 *
 * P1 不接业务（join/register/connect 在 P2），这里只验证三件事：
 *   1. `storage.sql.exec(query, ...bindings)` 的参数绑定与 `toArray()` 返回值形状可用
 *   2. 建表幂等、meta 读写、`/i/init` 能写入网络上下文
 *   3. `sweep` 会删过期事件和僵尸节点，但不会误删还挂着 socket 的节点
 */

import { NetworkRoom } from "./worker.js";
import { RoomFakeState, fakeSocket } from "./room-fake.mjs";

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

const req = (method, path, { body, headers } = {}) =>
  new Request(`https://room.test${path}`, {
    method,
    headers: { "content-type": "application/json", ...(headers ?? {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

async function newRoom() {
  const state = new RoomFakeState();
  const room = new NetworkRoom(state, {});
  await state.ready();
  return { room, state };
}

const NODE_A = "a".repeat(32);
const NODE_B = "b".repeat(32);

console.log("\n=== NetworkRoom 骨架（P1） ===");

const { room, state } = await newRoom();

console.log("\n1. 建表与版本");
const ver = room.sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").toArray()[0];
check("schema_version = 1", ver?.v === "1", ver);
check(
  "五张表都在",
  ["nodes", "reservations", "events", "nonces", "meta"].every(
    (t) => room.sql.exec(`SELECT COUNT(*) AS n FROM ${t}`).toArray()[0] !== undefined,
  ),
);
check("没有注册定时器（只有内存字段）", !("alarms" in room.state) || room.state.alarms === undefined);

console.log("\n2. /i/init 与网络上下文");
const initRes = await room.fetch(
  req("POST", "/i/init", {
    body: { net: { v: 1, id: "home", name: "home", cidr: "10.78.0.0/16" } },
  }),
);
const initBody = await initRes.json();
check("/i/init 返回 ok", initRes.status === 200 && initBody.ok === true, initBody);

const dbg = await (await room.fetch(req("GET", "/i/debug"))).json();
check("/i/debug 读到 net", dbg.net?.id === "home" && dbg.net?.cidr === "10.78.0.0/16", dbg.net);
check("/i/debug 带 schema_version", dbg.schema_version === 1, dbg.schema_version);

console.log("\n3. x-qp2p-net 头会更新上下文");
await room.fetch(
  req("GET", "/i/stats", {
    headers: { "x-qp2p-net": JSON.stringify({ v: 1, id: "lab", name: "lab", cidr: "10.99.0.0/16" }) },
  }),
);
const after = room.net();
check("网络上下文已切到 lab", after?.id === "lab", after);
check("未知版本的头被忽略", room.loadNet(req("GET", "/i/stats", {
  headers: { "x-qp2p-net": JSON.stringify({ v: 9, id: "evil" }) },
}))?.id === "lab");

console.log("\n4. /i/stats 计数");
const st0 = await (await room.fetch(req("GET", "/i/stats"))).json();
check("/i/stats 初始全 0", st0.nodes === 0 && st0.reservations === 0 && st0.events === 0, st0);

const now = Date.now();
const insertNode = (id, ip, lastSeen) =>
  room.sql.exec(
    `INSERT INTO nodes (node_id, name, pubkey, tls_fp, virtual_ip, nat_type, advertise,
                        candidates, candidates_at, last_seen, first_seen)
     VALUES (?, ?, ?, ?, ?, '', '', '', ?, ?, ?)`,
    id, `name-${id[0]}`, "c".repeat(64), "d".repeat(64), ip, now, lastSeen, now,
  );
insertNode(NODE_A, "10.78.0.2", now);
insertNode(NODE_B, "10.78.0.3", now - 700_000);

const st1 = await (await room.fetch(req("GET", "/i/stats"))).json();
check("插入两个节点后 nodes = 2", st1.nodes === 2, st1);

console.log("\n5. sweep：过期事件");
room.sql.exec(
  "INSERT INTO events (to_node, type, payload, created_at) VALUES (?, ?, ?, ?)",
  NODE_A, "punch_request", "{}", now - 400_000,
);
room.sql.exec(
  "INSERT INTO events (to_node, type, payload, created_at) VALUES (?, ?, ?, ?)",
  NODE_A, "peer_online", "{}", now,
);
room.sweepNow();
const evLeft = room.sql.exec("SELECT COUNT(*) AS n FROM events").toArray()[0].n;
check("只删过期的那个事件", evLeft === 1, evLeft);
check("last_sweep 已落库", room.getMeta("last_sweep") !== null);

console.log("\n6. sweep：僵尸节点保留有 socket 的");
state.sockets.push(fakeSocket({ node: NODE_A }));
room.sweepNow();
const nodesLeft = room.sql.exec("SELECT node_id FROM nodes").toArray().map((r) => r.node_id);
check("超过 10 分钟但挂着 socket 的节点保留", nodesLeft.includes(NODE_A), nodesLeft);
check("超过 10 分钟且无 socket 的节点被删", !nodesLeft.includes(NODE_B), nodesLeft);

console.log("\n7. 端点状态");
const wsRes = await room.fetch(req("GET", "/i/ws"));
// /i/ws 已在 P3 实现，完整用例在 ws-smoke.mjs；这里只确认参数校验在门口就挡住
check("GET /i/ws 缺 node_id → 400", wsRes.status === 400, wsRes.status);
const unknown = await room.fetch(req("GET", "/i/nope"));
check("未知路径 → 404", unknown.status === 404, unknown.status);

// 业务端点在没注册节点时应给出 404 而不是崩：
// /i/events 与 /i/leave 需要节点身份，这里只验证「没有网络上下文时统一 503」
const bare = new RoomFakeState();
const bareRoom = new NetworkRoom(bare, {});
await bare.ready();
const noNet = await bareRoom.fetch(req("POST", "/i/join", { body: {} }));
check("没有网络上下文 → 503", noNet.status === 503, noNet.status);

console.log("\n8. /i/purge 清空");
await room.fetch(req("POST", "/i/purge", { body: {} }));
const st2 = await (await room.fetch(req("GET", "/i/stats"))).json();
check("purge 后节点与事件归零", st2.nodes === 0 && st2.events === 0 && st2.reservations === 0, st2);
check("purge 后网络上下文已清", room.net() === null);

console.log(`\n结果：${passed} 通过，${failed} 失败\n`);
process.exit(failed === 0 ? 0 : 1);
