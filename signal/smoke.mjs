/**
 * 信令 Worker 的本地冒烟测试。
 *
 *   node signal/smoke.mjs                                   # 内存 + SQLite 冒充 D1
 *   ADMIN_SECRET=xxx node signal/smoke.mjs --remote <url>   # 验收线上部署
 *
 * 节点身份是真正的 Ed25519 密钥；签名覆盖整个请求体（去掉 sig），
 * 与服务端 worker.js 的 canonicalJson 逐字节一致。
 */

import { createHmac } from "node:crypto";

import worker, { deriveVirtualIp, canonicalJson as serverCanonicalJson } from "./worker.js";
import { fakeD1 } from "./fake-d1.mjs";

const ADMIN_SECRET = "smoke-secret";
const ctx = { waitUntil: () => {} };
const totals = { passed: 0, failed: 0 };

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

// --- 与服务端 worker.js 完全一致的规范化 JSON ---------------------------------

function canonicalJson(value) {
  if (value === null) return "null";
  const type = typeof value;
  if (type === "number") {
    // 与服务端、Rust 一致：只签 ±(2^53-1) 以内的整数，其余拒绝而不是各自格式化
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`不支持的数字 ${value}`);
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

function compareCodePoints(a, b) {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    const diff = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (diff !== 0) return diff;
  }
  return x.length - y.length;
}

/** 故意"宽松"的序列化：模拟只会 String(number) 的朴素客户端，用来构造"签名合法但数字不规范"的请求。 */
function lenientCanonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return quoteJson(value);
  if (Array.isArray(value)) return `[${value.map(lenientCanonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort(compareCodePoints);
  return `{${keys.map((k) => `${quoteJson(k)}:${lenientCanonicalJson(value[k])}`).join(",")}}`;
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
        out += `\\u${(0xd800 + (rest >> 10)).toString(16).padStart(4, "0")}`;
        out += `\\u${(0xdc00 + (rest & 0x3ff)).toString(16).padStart(4, "0")}`;
      } else {
        out += `\\u${code.toString(16).padStart(4, "0")}`;
      }
    } else out += ch;
  }
  return `${out}"`;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return hex(new Uint8Array(digest));
}

function randomNonce() {
  return hex(crypto.getRandomValues(new Uint8Array(8)));
}

/** 给请求体加上 ts / nonce / sig，返回可直接发送的对象。 */
async function signed(node, op, net, body, opts = {}) {
  const ts = opts.ts ?? Date.now();
  const nonce = opts.nonce ?? randomNonce();
  const payload = { ...body, ts, nonce };
  const digest = await sha256Hex((opts.canonical ?? canonicalJson)(payload));
  const message = `qp2p1|${op}|${net}|${ts}|${nonce}|${digest}`;
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    node.privateKey,
    new TextEncoder().encode(message),
  );
  return { ...payload, sig: hex(new Uint8Array(signature)) };
}

async function runSuite(label, env, expectedStorage, clientIp, opts = {}) {
  let passed = 0;
  let failed = 0;
  const remote = opts.remote ?? null;
  const secret = opts.secret ?? ADMIN_SECRET;
  const base = remote ? remote.replace(/\/+$/, "") : "https://qp2p.test";

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
    const url = new URL(`${base}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, String(v));
    const headers = { "content-type": "application/json", "cf-connecting-ip": clientIp };
    if (token) headers.authorization = `Bearer ${token}`;
    if (admin) headers["x-admin-secret"] = admin;
    const request = new Request(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const res = remote ? await fetch(request) : await worker.fetch(request, env, ctx);
    return { status: res.status, body: await res.json().catch(() => null) };
  };

  console.log(`\n=== ${label} ===`);

  console.log("\n1. 健康检查");
  const health = await call("GET", "/v1/health");
  check("health ok", health.status === 200 && health.body.ok === true, health.body);
  check(`storage=${expectedStorage}`, health.body.storage === expectedStorage, health.body.storage);

  console.log("\n2. 建网与加入密钥");
  const noSecret = await call("POST", "/v1/admin/networks", { body: { name: "home" } });
  check("缺少 admin secret 被拒", noSecret.status === 401, noSecret.body);

  // 预设密钥：管理员自己定，与 ADMIN_SECRET 无关
  const PRESET = "home-lab-preset-key-2024";
  const created = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "Home Lab", join_key: PRESET },
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
  check("令牌里带的就是预设密钥", token === `qp2p1_home-lab_${PRESET}`, token);

  const legacyMac = createHmac("sha256", secret).update("token:home-lab").digest("hex");
  check(
    "加入密钥不再由 ADMIN_SECRET 派生",
    token !== `qp2p1_home-lab_${legacyMac.slice(0, 40)}`,
    token,
  );

  const again = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "home lab", join_key: PRESET },
  });
  check("同一预设密钥重复建网是幂等的", again.body.token === token, again.body);
  check(
    "重复建网网段不变",
    again.body.network?.cidr === created.body.network.cidr,
    again.body.network,
  );

  const collide = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "home lab" },
  });
  check("已存在的网络不会被悄悄换密钥", collide.status === 409, collide.body);

  const shortKey = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "tiny", join_key: "short" },
  });
  check("过短的加入密钥被拒", shortKey.status === 400, shortKey.body);

  const weak = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "weak-key-test", join_key: "abcdefghijklmnopqrst" },
  });
  check("可猜的预设密钥带提醒", weak.status === 200 && Boolean(weak.body.warning), weak.body);

  const otherNet = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "lab" },
  });
  check("第二个网络网段不与第一个重叠", otherNet.body.network.cidr !== created.body.network.cidr);
  check(
    "不填 join_key 时随机生成",
    /^qp2p1_lab_[0-9a-f]{48}$/.test(otherNet.body.token ?? ""),
    otherNet.body.token,
  );

  // 轮换：只作废这一个网络的密钥，ADMIN_SECRET 不动
  const rotNet = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "rotate-test", join_key: "rotate-preset-key-0001" },
  });
  const rotOld = rotNet.body.token;
  const probe = (tk) =>
    call("GET", "/v1/events", { token: tk, query: { node_id: "0".repeat(32), since: 0 } });
  const before = await probe(rotOld);
  check("轮换前令牌可用", before.body.error === "unknown_node", before.body);

  const rotated = await call("POST", "/v1/admin/networks/rotate-test/rotate", {
    admin: secret,
    body: { join_key: "rotate-preset-key-0002" },
  });
  check(
    "轮换返回新令牌",
    rotated.status === 200 && rotated.body.token !== rotOld,
    rotated.body,
  );
  const afterOld = await probe(rotOld);
  const afterNew = await probe(rotated.body.token);
  check("旧令牌立刻失效", afterOld.body.error === "wrong_secret", afterOld.body);
  check("新令牌可用", afterNew.body.error === "unknown_node", afterNew.body);

  // 兼容 2.0：那时没有 join_hash，令牌由 ADMIN_SECRET 派生，服务端仍要认
  const ghostMac = createHmac("sha256", secret).update("token:ghost").digest("hex").slice(0, 40);
  const legacyProbe = await probe(`qp2p1_ghost_${ghostMac}`);
  check("旧版派生令牌仍被接受（兼容老网络）", legacyProbe.body.error === "unknown_node", legacyProbe.body);

  console.log("\n3. 加入与上报");
  const alice = await identity();
  const bob = await identity();

  const joined = await call("POST", "/v1/join", {
    token,
    body: await signed(alice, "join", net, {
      node_id: alice.nodeId,
      pubkey: alice.pubkey,
      name: "alice",
    }),
  });
  check("join 成功", joined.status === 200 && joined.body.ok === true, joined.body);
  check("durable 标记与后端一致", joined.body.durable === (expectedStorage === "d1"), joined.body.durable);

  const aliceIp = joined.body.node?.virtual_ip;
  const prefix = created.body.network.cidr.split("/")[0].split(".").slice(0, 2).join(".");
  check("拿到虚拟地址", /^10\.\d+\.\d+\.\d+$/.test(aliceIp ?? ""), aliceIp);
  check("虚拟地址落在网段内", aliceIp?.startsWith(`${prefix}.`), { aliceIp, cidr: created.body.network.cidr });

  // 用户自定义虚拟地址：加入时自带一个，服务端校验后原样保留
  const customIp = `${prefix}.1.240`;
  const carol = await identity();
  const withCustom = await call("POST", "/v1/join", {
    token,
    body: await signed(carol, "join", net, {
      node_id: carol.nodeId,
      pubkey: carol.pubkey,
      name: "carol",
      virtual_ip: customIp,
    }),
  });
  check(
    "可以指定自己的虚拟地址",
    withCustom.status === 200 && withCustom.body.node?.virtual_ip === customIp,
    withCustom.body,
  );

  const carolAgain = await call("POST", "/v1/join", {
    token,
    body: await signed(carol, "join", net, { node_id: carol.nodeId, pubkey: carol.pubkey }),
  });
  check(
    "不指定时沿用上次的地址",
    carolAgain.body.node?.virtual_ip === customIp,
    carolAgain.body.node,
  );

  const dave = await identity();
  const takenIp = await call("POST", "/v1/join", {
    token,
    body: await signed(dave, "join", net, {
      node_id: dave.nodeId,
      pubkey: dave.pubkey,
      virtual_ip: customIp,
    }),
  });
  check(
    "地址被占用时拒绝",
    takenIp.status === 409 && takenIp.body.error === "virtual_ip_taken",
    takenIp.body,
  );

  const outside = await call("POST", "/v1/join", {
    token,
    body: await signed(dave, "join", net, {
      node_id: dave.nodeId,
      pubkey: dave.pubkey,
      virtual_ip: "10.250.0.5",
    }),
  });
  check("网段外的地址被拒", outside.status === 400, outside.body);

  const netBase = created.body.network.cidr.split("/")[0];
  const netAddr = await call("POST", "/v1/join", {
    token,
    body: await signed(dave, "join", net, {
      node_id: dave.nodeId,
      pubkey: dave.pubkey,
      virtual_ip: netBase,
    }),
  });
  check("网段地址不能给节点", netAddr.status === 400, netAddr.body);

  const broadcast = await call("POST", "/v1/join", {
    token,
    body: await signed(dave, "join", net, {
      node_id: dave.nodeId,
      pubkey: dave.pubkey,
      virtual_ip: `${prefix}.255.255`,
    }),
  });
  check("广播地址不能给节点", broadcast.status === 400, broadcast.body);

  const badId = await call("POST", "/v1/join", {
    token,
    body: await signed(alice, "join", net, { node_id: "0".repeat(32), pubkey: alice.pubkey }),
  });
  check("node_id 与 pubkey 不匹配被拒", badId.status === 403 && badId.body.error === "node_id_mismatch", badId.body);

  const noSig = await call("POST", "/v1/join", {
    token,
    body: { node_id: bob.nodeId, pubkey: bob.pubkey },
  });
  check("缺签名被拒", noSig.status === 403 && noSig.body.error === "bad_signature", noSig.body);

  const stale = await call("POST", "/v1/join", {
    token,
    body: await signed(
      bob,
      "join",
      net,
      { node_id: bob.nodeId, pubkey: bob.pubkey },
      { ts: Date.now() - 10 * 60_000 },
    ),
  });
  check("过期时间戳被拒", stale.status === 403 && String(stale.body.detail).includes("120"), stale.body);

  // 关键回归：拿一份合法签名，改字段后重发
  const tamperBase = await signed(bob, "join", net, {
    node_id: bob.nodeId,
    pubkey: bob.pubkey,
    name: "bob",
  });
  const tamperedCandidates = await call("POST", "/v1/join", {
    token,
    body: { ...tamperBase, candidates: ["198.51.100.66:4444"] },
  });
  check("改 candidates 后签名失效", tamperedCandidates.status === 403, tamperedCandidates.body);

  const tamperedFp = await call("POST", "/v1/join", {
    token,
    body: { ...tamperBase, tls_fp: "attacker-fp" },
  });
  check("改 tls_fp 后签名失效", tamperedFp.status === 403, tamperedFp.body);

  const firstUse = await call("POST", "/v1/join", { token, body: tamperBase });
  check("首次提交合法", firstUse.status === 200, firstUse.body);
  const replayJoin = await call("POST", "/v1/join", { token, body: tamperBase });
  check(
    "同报文重放被拒",
    replayJoin.status === 403 && String(replayJoin.body.detail).includes("重放"),
    replayJoin.body,
  );

  const candidates = ["203.0.113.7:51820", "198.51.100.9:51820"];
  const register = await call("POST", "/v1/register", {
    token,
    body: await signed(bob, "register", net, {
      node_id: bob.nodeId,
      pubkey: bob.pubkey,
      name: "bob",
      candidates,
      nat_type: "cone",
      tls_fp: "ab".repeat(32),
      advertise: ["192.168.1.0/24"],
    }),
  });
  check("register 成功", register.status === 200 && register.body.ok === true, register.body);
  check("对端列表里能看到 alice", register.body.peers?.some((p) => p.node_id === alice.nodeId), register.body.peers);
  check("peers 里带候选与在线标记", register.body.peers?.[0]?.online === true, register.body.peers?.[0]);
  check("两个节点地址不同", register.body.node?.virtual_ip !== aliceIp, {
    bob: register.body.node?.virtual_ip,
    alice: aliceIp,
  });

  const emptyRegister = await call("POST", "/v1/register", {
    token,
    body: await signed(alice, "register", net, {
      node_id: alice.nodeId,
      pubkey: alice.pubkey,
      candidates: [],
    }),
  });
  check(
    "register 缺候选被拒",
    emptyRegister.status === 400 && emptyRegister.body.error === "missing_candidates",
    emptyRegister.body,
  );

  const badCandidate = await call("POST", "/v1/register", {
    token,
    body: await signed(bob, "register", net, {
      node_id: bob.nodeId,
      pubkey: bob.pubkey,
      candidates: ["127.0.0.1:51820"],
    }),
  });
  check(
    "回环候选被拒",
    badCandidate.status === 400 && badCandidate.body.error === "invalid_candidates",
    badCandidate.body,
  );

  const rejoin = await call("POST", "/v1/join", {
    token,
    body: await signed(alice, "join", net, { node_id: alice.nodeId, pubkey: alice.pubkey }),
  });
  check("重复加入地址不变", rejoin.body.node?.virtual_ip === aliceIp, {
    before: aliceIp,
    after: rejoin.body.node?.virtual_ip,
  });

  console.log("\n4. 撮合与身份");
  const wrongToken = await call("POST", "/v1/connect", {
    token: "qp2p1_home-lab_deadbeef",
    body: await signed(alice, "connect", net, { from: alice.nodeId, target: bob.nodeId }),
  });
  check("错误密钥被拒", wrongToken.status === 403, wrongToken.body);

  const mallory = await identity();
  const tryMallory = await call("POST", "/v1/connect", {
    token,
    body: await signed(mallory, "connect", net, { from: bob.nodeId, target: alice.nodeId }),
  });
  check("冒用他人 node_id 被拒", tryMallory.status === 403 && tryMallory.body.error === "bad_signature", tryMallory.body);

  const crossNet = await call("POST", "/v1/connect", {
    token: otherNet.body.token,
    body: await signed(alice, "connect", "lab", { from: alice.nodeId, target: bob.nodeId }),
  });
  check("跨网络看不到别网络的节点", crossNet.status === 404, crossNet.body);

  const selfConnect = await call("POST", "/v1/connect", {
    token,
    body: await signed(alice, "connect", net, { from: alice.nodeId, target: alice.nodeId }),
  });
  check("连自己被拒", selfConnect.status === 400 && selfConnect.body.error === "self_connect", selfConnect.body);

  const connectBody = await signed(alice, "connect", net, { from: alice.nodeId, target: bob.nodeId });
  const connected = await call("POST", "/v1/connect", { token, body: connectBody });
  check("撮合成功", connected.status === 200 && connected.body.ok === true, connected.body);
  check(
    "撮合返回对端心跳时间",
    Number(connected.body.target_last_seen) > 0,
    connected.body.target_last_seen,
  );

  if (!remote) {
    // STALE_MS 可覆盖是为了这里能测：压到 1 毫秒，立刻判定"可能刚换网"
    env.STALE_MS = 1;
    const staleRes = await call("POST", "/v1/connect", {
      token,
      body: await signed(alice, "connect", net, { from: alice.nodeId, target: bob.nodeId }),
    });
    delete env.STALE_MS;
    check(
      "对端心跳过期时拒绝撮合",
      staleRes.status === 409 && staleRes.body.error === "target_stale",
      staleRes.body,
    );
  }

  check(
    "拿到对端候选",
    JSON.stringify(connected.body.target_candidates) === JSON.stringify(candidates),
    connected.body.target_candidates,
  );
  check("拿到对端 TLS 指纹", connected.body.target_tls_fp === "ab".repeat(32), connected.body.target_tls_fp);

  const replayConnect = await call("POST", "/v1/connect", { token, body: connectBody });
  check(
    "connect 重放被拒",
    replayConnect.status === 403 && String(replayConnect.body.detail).includes("重放"),
    replayConnect.body,
  );

  console.log("\n5. 事件");
  const evBody = await signed(bob, "events", net, { node_id: bob.nodeId, since: 0 });
  const { sig: evSig, ...evQuery } = evBody;
  const firstPull = await call("GET", "/v1/events", { token, query: { ...evQuery, sig: evSig } });
  check("bob 收到一条事件", firstPull.body.events?.length === 1, firstPull.body);
  check("事件类型是 punch_request", firstPull.body.events?.[0]?.type === "punch_request", firstPull.body.events?.[0]);
  check("事件里带发起方的候选", Array.isArray(firstPull.body.events?.[0]?.candidates), firstPull.body.events?.[0]);
  check("返回游标", typeof firstPull.body.cursor === "number" && firstPull.body.cursor > 0, firstPull.body.cursor);

  const pull2 = await signed(bob, "events", net, { node_id: bob.nodeId, since: firstPull.body.cursor });
  const { sig: p2Sig, ...p2Query } = pull2;
  const secondPull = await call("GET", "/v1/events", { token, query: { ...p2Query, sig: p2Sig } });
  check("游标之后没有重复事件", secondPull.body.events?.length === 0, secondPull.body);
  check("游标不回退", secondPull.body.cursor === firstPull.body.cursor, secondPull.body.cursor);

  const noSigPull = await call("GET", "/v1/events", { token, query: { node_id: bob.nodeId, since: 0 } });
  check("无签名拉事件被拒", noSigPull.status === 403 && noSigPull.body.error === "bad_signature", noSigPull.body);

  const malloryEv = await signed(mallory, "events", net, { node_id: bob.nodeId, since: 0 });
  const { sig: mSig, ...mQuery } = malloryEv;
  const steal = await call("GET", "/v1/events", { token, query: { ...mQuery, sig: mSig } });
  check("读取他人事件被拒", steal.status === 403 && steal.body.error === "bad_signature", steal.body);

  const aliceEv = await signed(alice, "events", net, { node_id: alice.nodeId, since: 0 });
  const { sig: aSig, ...aQuery } = aliceEv;
  const alicePull = await call("GET", "/v1/events", { token, query: { ...aQuery, sig: aSig } });
  check("alice 没有收到事件", alicePull.body.events?.length === 0, alicePull.body);

  console.log("\n6. 离线");
  const wrongLeave = await call("POST", "/v1/leave", {
    token,
    body: await signed(alice, "leave", net, { node_id: bob.nodeId, pubkey: bob.pubkey }),
  });
  check("用别人的私钥下线被拒", wrongLeave.status === 403, wrongLeave.body);

  if (remote) {
    const dropAlice = await call("POST", "/v1/leave", {
      token,
      body: await signed(alice, "leave", net, { node_id: alice.nodeId, pubkey: alice.pubkey }),
    });
    check("远端清理 alice", dropAlice.status === 200, dropAlice.body);
  }

  const left = await call("POST", "/v1/leave", {
    token,
    body: await signed(bob, "leave", net, { node_id: bob.nodeId, pubkey: bob.pubkey }),
  });
  check("下线成功", left.status === 200 && left.body.ok === true, left.body);

  const afterLeave = await call("POST", "/v1/connect", {
    token,
    body: await signed(alice, "connect", net, { from: alice.nodeId, target: bob.nodeId }),
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

  console.log("\n8. 规范 JSON 边界（与 Rust 侧 canonical.rs 同一组规则）");
  const outcome = (fn) => {
    try {
      return fn();
    } catch {
      return "REJECT";
    }
  };
  for (const [name, impl] of [
    ["服务端", serverCanonicalJson],
    ["客户端副本", canonicalJson],
  ]) {
    check(`${name}：整数原样输出`, outcome(() => impl({ a: 1, b: -7 })) === '{"a":1,"b":-7}');
    check(
      `${name}：2^53-1 可签`,
      outcome(() => impl({ a: Number.MAX_SAFE_INTEGER })) === '{"a":9007199254740991}',
    );
    for (const [label, value] of [
      ["浮点 1.5", 1.5],
      ["2^53（超出安全范围）", 2 ** 53],
      ["1e21", 1e21],
      ["-0", -0],
      ["NaN", Number.NaN],
    ]) {
      check(`${name}：拒绝 ${label}`, outcome(() => impl({ a: value })) === "REJECT");
    }
    check(`${name}：嵌套里的浮点也拒绝`, outcome(() => impl({ a: [1, { b: 2.5 }] })) === "REJECT");
    // U+FFFD 的码点小于 U+1F600；按 UTF-16 码元排序会得到相反的顺序
    check(
      `${name}：键按码点排序`,
      outcome(() => impl({ "\u{1F600}": 1, "\uFFFD": 2, a: 3 })) ===
        '{"a":3,"\\ufffd":2,"\\ud83d\\ude00":1}',
    );
  }

  // 签名合法、但数字不规范：必须是 4xx 且有明确原因，不能变成 500
  for (const [label, extra] of [
    ["浮点数", 1.5],
    ["超出 2^53 的整数", 2 ** 53],
    ["1e21", 1e21],
  ]) {
    const body = await signed(
      alice,
      "register",
      net,
      { node_id: alice.nodeId, pubkey: alice.pubkey, candidates: ["203.0.113.5:51820"], extra },
      { canonical: lenientCanonicalJson },
    );
    const res = await call("POST", "/v1/register", { token, body });
    check(
      `请求体含${label}被拒（403，说明原因）`,
      res.status === 403 && String(res.body?.detail).includes("规范化"),
      res,
    );
  }

  console.log("\nN. 管理面：列网络与删网络");
  const listed = await call("GET", "/v1/admin/networks", { admin: secret });
  check(
    "列出网络",
    listed.status === 200 && (listed.body.networks ?? []).some((n) => n.id === net),
    listed.status,
  );
  check(
    "列表带成员数",
    typeof (listed.body.networks ?? []).find((n) => n.id === net)?.nodes === "number",
    listed.body.networks,
  );
  const noAuth = await call("GET", "/v1/admin/networks");
  check("列网络需要管理密钥", noAuth.status === 401, noAuth.body);

  const delNoConfirm = await call("DELETE", `/v1/admin/networks/${net}`, {
    admin: secret,
    body: {},
  });
  check(
    "删除必须带 confirm",
    delNoConfirm.status === 400 && delNoConfirm.body.error === "confirm_required",
    delNoConfirm.body,
  );

  // 用一次性网络验证删除，别把 net 删掉影响别的用例
  const tmp = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "delete-me" },
  });
  const tmpId = tmp.body.network.id;
  const del = await call("DELETE", `/v1/admin/networks/${tmpId}`, {
    admin: secret,
    body: { confirm: tmpId },
  });
  check("删除网络成功", del.status === 200 && del.body.ok === true, del.body);

  const afterDel = await call("GET", "/v1/admin/networks", { admin: secret });
  check(
    "删除后列表里不再出现",
    !(afterDel.body.networks ?? []).some((n) => n.id === tmpId),
    afterDel.body.networks,
  );

  const goneToken = await call("POST", "/v1/join", {
    token: tmp.body.token,
    body: await signed(alice, "join", tmpId, {
      node_id: alice.nodeId,
      pubkey: alice.pubkey,
    }),
  });
  check("已删网络的令牌立即失效", [401, 403].includes(goneToken.status), goneToken.body);

  console.log("\nO. IP 预留与管理面");
  const resvNet = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "resv-test", cidr: "10.99.0.0/16" },
  });
  check("可以指定网段建网", resvNet.body.network?.cidr === "10.99.0.0/16", resvNet.body.network);
  const rNet = resvNet.body.network.id;
  const rToken = resvNet.body.token;

  const pinnedIp = "10.99.0.50";
  const nick = await identity();
  const nickJoin = await call("POST", "/v1/join", {
    token: rToken,
    body: await signed(nick, "join", rNet, {
      node_id: nick.nodeId,
      pubkey: nick.pubkey,
      name: "nick",
      virtual_ip: pinnedIp,
    }),
  });
  check("加入时指定 IP 生效", nickJoin.body.node?.virtual_ip === pinnedIp, nickJoin.body.node);

  const resvList = await call("GET", `/v1/admin/networks/${rNet}/reservations`, { admin: secret });
  const nickResv = (resvList.body.reservations ?? []).find((r) => r.ip === pinnedIp);
  check("手填 IP 生成 user 预留", nickResv?.kind === "user" && nickResv?.node_id === nick.nodeId, nickResv);

  const nickLeave = await call("POST", "/v1/leave", {
    token: rToken,
    body: await signed(nick, "leave", rNet, { node_id: nick.nodeId, pubkey: nick.pubkey }),
  });
  check("nick 下线", nickLeave.status === 200, nickLeave.body);

  const resvAfterLeave = await call("GET", `/v1/admin/networks/${rNet}/reservations`, { admin: secret });
  check(
    "下线后 user 预留还在",
    (resvAfterLeave.body.reservations ?? []).some((r) => r.ip === pinnedIp),
    resvAfterLeave.body.reservations,
  );

  const eve = await identity();
  const stealResv = await call("POST", "/v1/join", {
    token: rToken,
    body: await signed(eve, "join", rNet, {
      node_id: eve.nodeId,
      pubkey: eve.pubkey,
      name: "eve",
      virtual_ip: pinnedIp,
    }),
  });
  check(
    "预留地址不能被别人抢",
    stealResv.status === 409 && stealResv.body.error === "virtual_ip_reserved",
    stealResv.body,
  );

  const eveJoin = await call("POST", "/v1/join", {
    token: rToken,
    body: await signed(eve, "join", rNet, { node_id: eve.nodeId, pubkey: eve.pubkey, name: "eve" }),
  });
  check("自动分配跳过预留地址", eveJoin.body.node?.virtual_ip !== pinnedIp, eveJoin.body.node);
  const eveIp = eveJoin.body.node?.virtual_ip;

  const autoResv =
    (await call("GET", `/v1/admin/networks/${rNet}/reservations`, { admin: secret })).body
      .reservations ?? [];
  check(
    "自动分配的地址登记为 auto",
    autoResv.some((r) => r.ip === eveIp && r.kind === "auto"),
    autoResv,
  );

  const nodeList = await call("GET", `/v1/admin/networks/${rNet}/nodes`, { admin: secret });
  const eveRow = (nodeList.body.nodes ?? []).find((n) => n.node_id === eve.nodeId);
  check("节点列表带在线状态", eveRow?.online === true, eveRow);
  check("节点列表带预留标记", eveRow?.reserved === true, eveRow);

  const nickBack = await call("POST", "/v1/join", {
    token: rToken,
    body: await signed(nick, "join", rNet, { node_id: nick.nodeId, pubkey: nick.pubkey, name: "nick" }),
  });
  check("重连拿回预留地址", nickBack.body.node?.virtual_ip === pinnedIp, nickBack.body.node);

  const manualIp = "10.99.0.77";
  const manual = await call("POST", `/v1/admin/networks/${rNet}/reservations`, {
    admin: secret,
    body: { ip: manualIp, note: "打印机" },
  });
  check("管理员可以预留 IP", manual.status === 200, manual.body);

  const outsideResv = await call("POST", `/v1/admin/networks/${rNet}/reservations`, {
    admin: secret,
    body: { ip: "10.250.1.1" },
  });
  check("预留必须在网段内", outsideResv.status === 400, outsideResv.body);

  const releaseManual = await call("DELETE", `/v1/admin/networks/${rNet}/reservations/${manualIp}`, {
    admin: secret,
  });
  check("可以释放预留", releaseManual.status === 200, releaseManual.body);

  const patch = await call("PATCH", `/v1/admin/networks/${rNet}`, {
    admin: secret,
    body: { cidr: "10.100.0.0/16" },
  });
  check("改网段成功", patch.status === 200 && patch.body.network?.cidr === "10.100.0.0/16", patch.body);
  check("网段外的节点重新分配", patch.body.reassigned === 2, patch.body);

  const movedNodes = await call("GET", `/v1/admin/networks/${rNet}/nodes`, { admin: secret });
  check(
    "重分配后地址都在新网段",
    (movedNodes.body.nodes ?? []).every((n) => String(n.virtual_ip).startsWith("10.100.")),
    movedNodes.body.nodes,
  );

  const clashPatch = await call("PATCH", `/v1/admin/networks/${rNet}`, {
    admin: secret,
    body: { cidr: created.body.network.cidr },
  });
  check("网段冲突被拒", clashPatch.status === 409 && clashPatch.body.error === "cidr_in_use", clashPatch.body);

  const kick = await call("POST", `/v1/admin/networks/${rNet}/nodes/${eve.nodeId}/kick`, {
    admin: secret,
  });
  check("踢下线成功", kick.status === 200, kick.body);
  const afterKick = await call("GET", `/v1/admin/networks/${rNet}/nodes`, { admin: secret });
  check(
    "踢下线后节点消失",
    !(afterKick.body.nodes ?? []).some((n) => n.node_id === eve.nodeId),
    afterKick.body.nodes,
  );

  const auditRows = await call("GET", "/v1/admin/audit?limit=50", { admin: secret });
  const actions = (auditRows.body.actions ?? []).map((a) => a.action);
  check("审计记录改网段", actions.includes("network.update"), actions);
  check("审计记录踢下线", actions.includes("node.kick"), actions);
  check("审计记录预留", actions.includes("reservation.put"), actions);

  const badLogin = await call("POST", "/v1/admin/login", { body: { secret: "wrong-secret" } });
  check("错误密钥登录被拒", badLogin.status === 401, badLogin.body);
  const goodLogin = await call("POST", "/v1/admin/login", { body: { secret } });
  check("正确密钥登录成功", goodLogin.status === 200 && goodLogin.body.ok === true, goodLogin.body);

  const rawLogin = new Request(`${base}/v1/admin/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret }),
  });
  const loginRes = remote ? await fetch(rawLogin) : await worker.fetch(rawLogin, env, ctx);
  const setCookie = loginRes.headers.get("set-cookie") ?? "";
  check(
    "登录下发 HttpOnly cookie",
    /qp2p_admin=/.test(setCookie) && /HttpOnly/.test(setCookie),
    setCookie,
  );

  const cookieHeader = setCookie.split(";")[0];
  const cookieReq = new Request(`${base}/v1/admin/networks`, { headers: { cookie: cookieHeader } });
  const cookieRes = remote ? await fetch(cookieReq) : await worker.fetch(cookieReq, env, ctx);
  check("cookie 可以访问管理接口", cookieRes.status === 200, cookieRes.status);

  const forgedReq = new Request(`${base}/v1/admin/networks`, {
    headers: { cookie: "qp2p_admin=9999999999999.deadbeef" },
  });
  const forgedRes = remote ? await fetch(forgedReq) : await worker.fetch(forgedReq, env, ctx);
  check("伪造 cookie 被拒", forgedRes.status === 401, forgedRes.status);

  const page = remote
    ? await fetch(`${base}/admin`)
    : await worker.fetch(new Request(`${base}/admin`), env, ctx);
  const pageText = await page.text();
  check("管理页面可访问", page.status === 200 && pageText.includes("qp2p 管理台"), page.status);

  const delResvNet = await call("DELETE", `/v1/admin/networks/${rNet}`, {
    admin: secret,
    body: { confirm: rNet },
  });
  check("删网一并清预留", delResvNet.status === 200, delResvNet.body);
  const goneResv = await call("GET", `/v1/admin/networks/${rNet}/reservations`, { admin: secret });
  check("删网后预留查询 404", goneResv.status === 404, goneResv.body);

  console.log(`  ${label}：${passed} 通过，${failed} 失败`);
  totals.passed += passed;
  totals.failed += failed;
}

const remoteFlag = process.argv.indexOf("--remote");
const remoteUrl = remoteFlag > 0 ? process.argv[remoteFlag + 1] : null;

if (remoteUrl) {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) {
    console.error("远端模式需要 ADMIN_SECRET 环境变量");
    process.exit(2);
  }
  await runSuite(`远端 ${remoteUrl}`, { ADMIN_SECRET: secret }, "d1", "198.18.0.3", {
    remote: remoteUrl,
    secret,
  });
} else {
  await runSuite("内存后端", { ADMIN_SECRET }, "memory", "198.18.0.1");
  await runSuite("D1 后端", { ADMIN_SECRET, DB: fakeD1() }, "d1", "198.18.0.2");
}

console.log(`\n结果：${totals.passed} 通过，${totals.failed} 失败\n`);
process.exit(totals.failed === 0 ? 0 : 1);
