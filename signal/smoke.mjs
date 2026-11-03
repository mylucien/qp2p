/**
 * 信令 Worker 的本地冒烟测试。
 *
 *   node signal/smoke.mjs
 *
 * 不连 Cloudflare：内存后端跑一遍，再用 Node 内置 SQLite 冒充 D1 跑一遍，
 * 两条存储路径覆盖同一套断言：建网 → 加入 → 上报 → 撮合 → 拉事件 → 下线 → 地址派生。
 *
 * 节点身份是真正的 Ed25519 密钥，所有写操作都按服务端要求签名。
 */

import { DatabaseSync } from "node:sqlite";

import worker, { deriveVirtualIp } from "./worker.js";

const ADMIN_SECRET = "smoke-secret";
const ctx = { waitUntil: () => {} };
const totals = { passed: 0, failed: 0 };

/** 把 node:sqlite 包成 D1 的 prepare/bind/run/first/all 接口。 */
function fakeD1() {
  const db = new DatabaseSync(":memory:");
  return {
    prepare(sql) {
      const statement = db.prepare(sql);
      let params = [];
      const api = {
        bind: (...args) => {
          params = args.map((a) => (typeof a === "boolean" ? Number(a) : a));
          return api;
        },
        run: () => {
          const result = statement.run(...params);
          return { success: true, meta: { changes: Number(result.changes ?? 0) } };
        },
        first: () => statement.get(...params) ?? null,
        all: () => ({ results: statement.all(...params) }),
      };
      return api;
    },
  };
}

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubkey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", hexToBytes(pubkey)));
  return { pubkey, nodeId: hex(digest).slice(0, 32), privateKey: pair.privateKey };
}

/** 与服务端 signPayload 逐字一致：qp2p1|op|part|part|ts */
async function sign(node, op, parts, ts = Date.now()) {
  const message = ["qp2p1", op, ...parts.map(String), ts].join("|");
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    node.privateKey,
    new TextEncoder().encode(message),
  );
  return { ts, sig: hex(new Uint8Array(signature)) };
}

async function runSuite(label, env, expectedStorage, clientIp) {
  let passed = 0;
  let failed = 0;

  const check = (name, ok, extra) => {
    if (ok) {
      passed += 1;
      console.log(`  ok   ${name}`);
    } else {
      failed += 1;
      console.log(`  FAIL ${name}${extra !== undefined ? ` → ${JSON.stringify(extra)}` : ""}`);
    }
  };

  const call = async (method, path, { token, admin, body, query } = {}) => {
    const url = new URL(`https://qp2p.test${path}`);
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, String(v));
    const headers = { "content-type": "application/json", "cf-connecting-ip": clientIp };
    if (token) headers.authorization = `Bearer ${token}`;
    if (admin) headers["x-admin-secret"] = admin;
    const request = new Request(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const res = await worker.fetch(request, env, ctx);
    return { status: res.status, body: await res.json().catch(() => null) };
  };

  console.log(`\n=== ${label} ===`);

  console.log("\n1. 健康检查");
  const health = await call("GET", "/v1/health");
  check("health ok", health.status === 200 && health.body.ok === true, health.body);
  check(`storage=${expectedStorage}`, health.body.storage === expectedStorage, health.body.storage);

  console.log("\n2. 建网");
  const noSecret = await call("POST", "/v1/admin/networks", { body: { name: "home" } });
  check("缺少 admin secret 被拒", noSecret.status === 401, noSecret.body);

  const created = await call("POST", "/v1/admin/networks", {
    admin: ADMIN_SECRET,
    body: { name: "Home Lab" },
  });
  check("建网成功", created.status === 200 && created.body.ok === true, created.body);
  const net = created.body.network.id;
  check("网络 id 已 slug 化", net === "home-lab", net);
  check(
    "分到 10.x.0.0/16 网段",
    /^10\.\d+\.0\.0\/16$/.test(created.body.network?.cidr ?? ""),
    created.body.network,
  );
  const token = created.body.token;
  check("令牌格式正确", String(token).startsWith("qp2p1_home-lab_"), token);

  const again = await call("POST", "/v1/admin/networks", {
    admin: ADMIN_SECRET,
    body: { name: "home lab" },
  });
  check("重复建网返回同一把密钥", again.body.token === token, again.body.token);
  check("重复建网网段不变", again.body.network.cidr === created.body.network.cidr, again.body.network);

  const otherNet = await call("POST", "/v1/admin/networks", {
    admin: ADMIN_SECRET,
    body: { name: "lab" },
  });
  check("第二个网络网段不与第一个重叠", otherNet.body.network.cidr !== created.body.network.cidr, {
    first: created.body.network.cidr,
    second: otherNet.body.network.cidr,
  });

  console.log("\n3. 加入与上报");
  const alice = await identity();
  const bob = await identity();

  const joinSig = await sign(alice, "join", [net, alice.nodeId]);
  const joined = await call("POST", "/v1/join", {
    token,
    body: { node_id: alice.nodeId, pubkey: alice.pubkey, name: "alice", ...joinSig },
  });
  check("join 成功", joined.status === 200 && joined.body.ok === true, joined.body);
  check("durable 标记与后端一致", joined.body.durable === (expectedStorage === "d1"), joined.body.durable);

  const aliceIp = joined.body.node?.virtual_ip;
  const prefix = created.body.network.cidr.split("/")[0].split(".").slice(0, 2).join(".");
  check("拿到虚拟地址", /^10\.\d+\.\d+\.\d+$/.test(aliceIp ?? ""), aliceIp);
  check("虚拟地址落在网段内", aliceIp?.startsWith(`${prefix}.`), {
    aliceIp,
    cidr: created.body.network.cidr,
  });

  const badId = await call("POST", "/v1/join", {
    token,
    body: { node_id: "0".repeat(32), pubkey: alice.pubkey, ...joinSig },
  });
  check("node_id 与 pubkey 不匹配被拒", badId.status === 403 && badId.body.error === "node_id_mismatch", badId.body);

  const noSig = await call("POST", "/v1/join", { token, body: { node_id: bob.nodeId, pubkey: bob.pubkey } });
  check("缺签名被拒", noSig.status === 403 && noSig.body.error === "bad_signature", noSig.body);

  const staleSig = await sign(bob, "join", [net, bob.nodeId], Date.now() - 10 * 60_000);
  const stale = await call("POST", "/v1/join", {
    token,
    body: { node_id: bob.nodeId, pubkey: bob.pubkey, ...staleSig },
  });
  check("过期时间戳被拒", stale.status === 403 && String(stale.body.detail).includes("120"), stale.body);

  const candidates = ["203.0.113.7:51820", "198.51.100.9:51820"];
  const regSig = await sign(bob, "register", [net, bob.nodeId, candidates.join(",")]);
  const register = await call("POST", "/v1/register", {
    token,
    body: {
      node_id: bob.nodeId,
      pubkey: bob.pubkey,
      name: "bob",
      candidates,
      nat_type: "cone",
      tls_fp: "ab".repeat(32),
      advertise: ["192.168.1.0/24"],
      ...regSig,
    },
  });
  check("register 成功", register.status === 200 && register.body.ok === true, register.body);
  check("对端列表里能看到 alice", register.body.peers?.some((p) => p.node_id === alice.nodeId), register.body.peers);
  check("peers 里带候选与在线标记", register.body.peers?.[0]?.online === true, register.body.peers?.[0]);
  check("两个节点地址不同", register.body.node?.virtual_ip !== aliceIp, {
    bob: register.body.node?.virtual_ip,
    alice: aliceIp,
  });

  const emptySig = await sign(alice, "register", [net, alice.nodeId, ""]);
  const emptyRegister = await call("POST", "/v1/register", {
    token,
    body: { node_id: alice.nodeId, pubkey: alice.pubkey, candidates: [], ...emptySig },
  });
  check(
    "register 缺候选被拒",
    emptyRegister.status === 400 && emptyRegister.body.error === "missing_candidates",
    emptyRegister.body,
  );

  const badCand = ["127.0.0.1:51820"];
  const badCandSig = await sign(bob, "register", [net, bob.nodeId, badCand.join(",")]);
  const badCandidate = await call("POST", "/v1/register", {
    token,
    body: { node_id: bob.nodeId, pubkey: bob.pubkey, candidates: badCand, ...badCandSig },
  });
  check(
    "回环候选被拒",
    badCandidate.status === 400 && badCandidate.body.error === "invalid_candidates",
    badCandidate.body,
  );

  const rejoinSig = await sign(alice, "join", [net, alice.nodeId]);
  const rejoin = await call("POST", "/v1/join", {
    token,
    body: { node_id: alice.nodeId, pubkey: alice.pubkey, ...rejoinSig },
  });
  check("重复加入地址不变", rejoin.body.node?.virtual_ip === aliceIp, {
    before: aliceIp,
    after: rejoin.body.node?.virtual_ip,
  });

  console.log("\n4. 撮合与身份");
  const wrongToken = await call("POST", "/v1/connect", {
    token: "qp2p1_home-lab_deadbeef",
    body: {
      from: alice.nodeId,
      target: bob.nodeId,
      ...(await sign(alice, "connect", [net, alice.nodeId, bob.nodeId])),
    },
  });
  check("错误密钥被拒", wrongToken.status === 403, wrongToken.body);

  // 攻击者持有同一网络的令牌、也知道 bob 的 node_id，但没有 bob 的私钥
  const mallory = await identity();
  const tryMallory = await call("POST", "/v1/connect", {
    token,
    body: {
      from: bob.nodeId,
      target: alice.nodeId,
      ...(await sign(mallory, "connect", [net, bob.nodeId, alice.nodeId])),
    },
  });
  check("冒用他人 node_id 被拒", tryMallory.status === 403 && tryMallory.body.error === "bad_signature", tryMallory.body);

  const crossNet = await call("POST", "/v1/connect", {
    token: otherNet.body.token,
    body: {
      from: alice.nodeId,
      target: bob.nodeId,
      ...(await sign(alice, "connect", ["lab", alice.nodeId, bob.nodeId])),
    },
  });
  check("跨网络看不到别网络的节点", crossNet.status === 404, crossNet.body);

  const selfSig = await sign(alice, "connect", [net, alice.nodeId, alice.nodeId]);
  const selfConnect = await call("POST", "/v1/connect", {
    token,
    body: { from: alice.nodeId, target: alice.nodeId, ...selfSig },
  });
  check("连自己被拒", selfConnect.status === 400 && selfConnect.body.error === "self_connect", selfConnect.body);

  const connectSig = await sign(alice, "connect", [net, alice.nodeId, bob.nodeId]);
  const connected = await call("POST", "/v1/connect", {
    token,
    body: { from: alice.nodeId, target: bob.nodeId, ...connectSig },
  });
  check("撮合成功", connected.status === 200 && connected.body.ok === true, connected.body);
  check(
    "拿到对端候选",
    JSON.stringify(connected.body.target_candidates) === JSON.stringify(candidates),
    connected.body.target_candidates,
  );
  check("拿到对端 TLS 指纹", connected.body.target_tls_fp === "ab".repeat(32), connected.body.target_tls_fp);
  check("带回切换时刻", typeof connected.body.t === "number" && connected.body.t > Date.now(), connected.body.t);

  console.log("\n5. 事件");
  const evSig = await sign(bob, "events", [net, bob.nodeId]);
  const firstPull = await call("GET", "/v1/events", {
    token,
    query: { node_id: bob.nodeId, since: 0, ts: evSig.ts, sig: evSig.sig },
  });
  check("bob 收到一条事件", firstPull.body.events?.length === 1, firstPull.body);
  check("事件类型是 punch_request", firstPull.body.events?.[0]?.type === "punch_request", firstPull.body.events?.[0]);
  check("事件里带发起方的候选", Array.isArray(firstPull.body.events?.[0]?.candidates), firstPull.body.events?.[0]);
  check("返回游标", typeof firstPull.body.cursor === "number" && firstPull.body.cursor > 0, firstPull.body.cursor);

  const pull2Sig = await sign(bob, "events", [net, bob.nodeId]);
  const secondPull = await call("GET", "/v1/events", {
    token,
    query: { node_id: bob.nodeId, since: firstPull.body.cursor, ts: pull2Sig.ts, sig: pull2Sig.sig },
  });
  check("游标之后没有重复事件", secondPull.body.events?.length === 0, secondPull.body);
  check("游标不回退", secondPull.body.cursor === firstPull.body.cursor, secondPull.body.cursor);

  const noSigPull = await call("GET", "/v1/events", { token, query: { node_id: bob.nodeId, since: 0 } });
  check("无签名拉事件被拒", noSigPull.status === 403 && noSigPull.body.error === "bad_signature", noSigPull.body);

  // 攻击者用自己的签名去读 bob 的事件
  const malloryEv = await sign(mallory, "events", [net, bob.nodeId]);
  const steal = await call("GET", "/v1/events", {
    token,
    query: { node_id: bob.nodeId, since: 0, ts: malloryEv.ts, sig: malloryEv.sig },
  });
  check("读取他人事件被拒", steal.status === 403 && steal.body.error === "bad_signature", steal.body);

  const aliceEv = await sign(alice, "events", [net, alice.nodeId]);
  const alicePull = await call("GET", "/v1/events", {
    token,
    query: { node_id: alice.nodeId, since: 0, ts: aliceEv.ts, sig: aliceEv.sig },
  });
  check("alice 没有收到事件", alicePull.body.events?.length === 0, alicePull.body);

  console.log("\n6. 离线");
  const wrongLeaveSig = await sign(alice, "leave", [net, bob.nodeId]);
  const wrongLeave = await call("POST", "/v1/leave", {
    token,
    body: { node_id: bob.nodeId, pubkey: bob.pubkey, ...wrongLeaveSig },
  });
  check("用别人的私钥下线被拒", wrongLeave.status === 403, wrongLeave.body);

  const leaveSig = await sign(bob, "leave", [net, bob.nodeId]);
  const left = await call("POST", "/v1/leave", {
    token,
    body: { node_id: bob.nodeId, pubkey: bob.pubkey, ...leaveSig },
  });
  check("下线成功", left.status === 200 && left.body.ok === true, left.body);

  const afterSig = await sign(alice, "connect", [net, alice.nodeId, bob.nodeId]);
  const afterLeave = await call("POST", "/v1/connect", {
    token,
    body: { from: alice.nodeId, target: bob.nodeId, ...afterSig },
  });
  check("下线后撮合返回 404", afterLeave.status === 404, afterLeave.body);

  console.log("\n7. 地址派生（与 Rust 侧 identity.rs 同一组向量）");
  const vectors = [
    ["0123456789abcdef0123456789abcdef", ["10.64.158.142", "10.64.193.155", "10.64.30.74"]],
    ["ffffffffffffffffffffffffffffffff", ["10.64.159.126", "10.64.129.186", "10.64.197.198"]],
    ["3f9a1b2c3d4e5f60718293a4b5c6d7e8", ["10.64.128.239", "10.64.71.59", "10.64.251.83"]],
  ];
  for (const [id, expected] of vectors) {
    const got = [];
    for (const salt of [0, 1, 7]) got.push(await deriveVirtualIp(id, "10.64.0.0/16", salt));
    check(`派生向量 ${id.slice(0, 8)}`, JSON.stringify(got) === JSON.stringify(expected), { got, expected });
  }

  console.log(`  ${label}：${passed} 通过，${failed} 失败`);
  totals.passed += passed;
  totals.failed += failed;
}

await runSuite("内存后端", { ADMIN_SECRET }, "memory", "198.18.0.1");
await runSuite("D1 后端", { ADMIN_SECRET, DB: fakeD1() }, "d1", "198.18.0.2");

console.log(`\n结果：${totals.passed} 通过，${totals.failed} 失败\n`);
process.exit(totals.failed === 0 ? 0 : 1);
