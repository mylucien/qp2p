/**
 * 真机压测：N 个节点同时挂长连接。
 *
 *   ADMIN_SECRET=xxx node signal/load-live.mjs https://你的地址 [节点数=100] [保持秒数=300]
 *
 * 为什么慢速铺开：Worker 的限流是「每 IP 每分钟 240 次」，而压测机只有一个出口 IP。
 * 一秒一个的速度下，join 与握手各占一分钟 100 次，滚动窗口不会超限。
 * 如果还是撞到 429，脚本会立刻停下并报出是在哪一步撞的。
 */

const BASE = (process.argv[2] ?? "").replace(/\/+$/, "");
const NODES = Number(process.argv[3] ?? 100);
const HOLD_SEC = Number(process.argv[4] ?? 300);
const ADMIN = process.env.ADMIN_SECRET ?? "";
const PACE_MS = Number(process.env.PACE_MS ?? 1100);

if (!BASE || !ADMIN) {
  console.error("用法：ADMIN_SECRET=xxx node signal/load-live.mjs <地址> [节点数] [保持秒数]");
  process.exit(2);
}

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
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
const nonce = () => hex(crypto.getRandomValues(new Uint8Array(8)));

async function identity() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const pubkey = hex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", hexToBytes(pubkey)));
  return { pubkey, nodeId: hex(digest).slice(0, 32), privateKey: pair.privateKey };
}

const { canonicalJson } = await import("./worker.js");

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

async function api(method, path, { token, body, admin } = {}) {
  const h = { "content-type": "application/json" };
  if (token) h.authorization = `Bearer ${token}`;
  if (admin) h["x-admin-secret"] = admin;
  const res = await fetch(BASE + path, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = { _raw: text.slice(0, 200) };
  }
  return { status: res.status, body: parsed };
}

async function main() {
  const name = `load-${Date.now().toString(36)}`;
  const startedAt = Date.now();
  console.log(`压测：${NODES} 个节点，保持 ${HOLD_SEC} 秒，地址 ${BASE}`);

  console.log("\n1. 建网");
  const mk = await api("POST", "/v1/admin/networks", {
    admin: ADMIN,
    body: { name, join_key: `jk-${name}` },
  });
  if (mk.status !== 200 && mk.status !== 201) {
    console.log("  建网失败，退出：", mk.status, mk.body);
    process.exit(1);
  }
  const token = mk.body.token;
  const netId = mk.body.network.id;
  console.log(`  网络 ${netId}`);

  console.log(`\n2. 登记 ${NODES} 个节点（每 ${PACE_MS}ms 一个）`);
  const nodes = [];
  let joinFail = 0;
  let rateLimited = 0;
  for (let i = 0; i < NODES; i += 1) {
    const id = await identity();
    const ts = Date.now();
    const n = nonce();
    const body = {
      node_id: id.nodeId,
      pubkey: id.pubkey,
      name: `n${i}`,
      tls_fp: "cc".repeat(32),
      nat_type: "eim",
      candidates: [`203.0.113.${(i % 200) + 20}:${9000 + i}`],
      ts,
      nonce: n,
    };
    body.sig = await sign(id, "join", netId, body);
    const r = await api("POST", "/v1/join", { token, body });
    if (r.status === 429) rateLimited += 1;
    if (r.status !== 200) joinFail += 1;
    else nodes.push(id);
    if ((i + 1) % 20 === 0) console.log(`   已登记 ${i + 1}/${NODES}（失败 ${joinFail}，429 ${rateLimited}）`);
    await sleep(PACE_MS);
  }
  check("全部节点登记成功", joinFail === 0 && nodes.length === NODES, {
    ok: nodes.length,
    joinFail,
    rateLimited,
  });
  if (nodes.length < 2) {
    console.log("  可用节点太少，退出");
    await api("DELETE", `/v1/admin/networks/${netId}`, { admin: ADMIN, body: { confirm: netId } });
    process.exit(1);
  }

  console.log(`\n3. 建立 ${nodes.length} 条长连接`);
  const conns = [];
  let wsFail = 0;
  for (let i = 0; i < nodes.length; i += 1) {
    const node = nodes[i];
    const ts = Date.now();
    const n = nonce();
    const payload = { node_id: node.nodeId, since: 0, ts, nonce: n, caps: "" };
    const sig = await sign(node, "ws", netId, payload);
    const qs = new URLSearchParams({
      node_id: node.nodeId,
      since: "0",
      ts: String(ts),
      nonce: n,
      caps: "",
      sig,
      token,
    });
    try {
      const ws = new WebSocket(`${BASE.replace(/^http/, "ws")}/v1/ws?${qs}`);
      const hello = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("等 hello 超时")), 15_000);
        ws.addEventListener("message", (ev) => {
          const raw = String(ev.data);
          if (raw === "pong") return;
          try {
            const m = JSON.parse(raw);
            if (m.t === "hello") {
              clearTimeout(timer);
              resolve(m);
            }
          } catch {
            /* 忽略 */
          }
        });
        ws.addEventListener("close", (ev) => {
          clearTimeout(timer);
          reject(new Error(`关闭 ${ev.code}`));
        });
        ws.addEventListener("error", () => {
          clearTimeout(timer);
          reject(new Error("握手失败"));
        });
      });
      conns.push({ node, ws, hello, inbox: [] });
      ws.addEventListener("message", (ev) => {
        const raw = String(ev.data);
        if (raw === "pong") return;
        try {
          const m = JSON.parse(raw);
          if (m.t !== "hello") conns[i]?.inbox.push(m);
        } catch {
          /* 忽略 */
        }
      });
    } catch (e) {
      wsFail += 1;
      if (wsFail <= 3) console.log(`   握手失败：${e.message}`);
    }
    if ((i + 1) % 20 === 0) console.log(`   已连接 ${i + 1}/${nodes.length}（失败 ${wsFail}）`);
    await sleep(PACE_MS);
  }
  check("全部节点握手成功", wsFail === 0 && conns.length === nodes.length, {
    ok: conns.length,
    wsFail,
  });

  console.log("\n4. 管理面看到的在线数");
  const list = await api("GET", `/v1/admin/networks/${netId}/nodes`, { admin: ADMIN });
  const rows = list.body.nodes ?? [];
  const online = rows.filter((r) => r.online).length;
  const viaWs = rows.filter((r) => r.via === "ws").length;
  check(`${NODES} 个节点都在线`, online === rows.length && rows.length === NODES, {
    rows: rows.length,
    online,
  });
  check("全部按 ws 判定", viaWs === rows.length, { viaWs, rows: rows.length });

  console.log(`\n5. 保持 ${HOLD_SEC} 秒：每 25 秒发一次 ping，中途做撮合`);
  const holdUntil = Date.now() + HOLD_SEC * 1000;
  let round = 0;
  let connectOk = 0;
  let connectErr = 0;
  while (Date.now() < holdUntil) {
    await sleep(Math.min(25_000, Math.max(0, holdUntil - Date.now())));
    for (const c of conns) {
      try {
        c.ws.send("ping");
      } catch {
        /* 已关 */
      }
    }
    round += 1;
    if (round % 2 === 0 && conns.length >= 4) {
      // 随机挑 10 对撮合，覆盖"两个节点都在长连接上"的真实路径
      for (let k = 0; k < Math.min(10, conns.length); k += 1) {
        const a = conns[Math.floor(Math.random() * conns.length)];
        const b = conns[Math.floor(Math.random() * conns.length)];
        if (a === b) continue;
        a.inbox.length = 0;
        a.ws.send(JSON.stringify({ t: "connect", req: k + 1, target: b.node.nodeId }));
        const deadline = Date.now() + 6_000;
        while (Date.now() < deadline && !a.inbox.some((m) => m.req === k + 1)) {
          await sleep(120);
        }
        const reply = a.inbox.find((m) => m.req === k + 1);
        if (reply?.t === "connect_ok") connectOk += 1;
        else connectErr += 1;
      }
      console.log(
        `   ${Math.round((Date.now() - startedAt) / 1000)}s：在线连接 ${conns.filter((c) => c.ws.readyState === 1).length}，撮合 ok=${connectOk} 失败=${connectErr}`,
      );
    }
  }
  check("保持期间撮合正常", connectErr === 0 && connectOk > 0, { connectOk, connectErr });

  const aliveNow = conns.filter((c) => c.ws.readyState === 1).length;
  check("保持结束时全部连接仍活着", aliveNow === conns.length, { alive: aliveNow, total: conns.length });

  const list2 = await api("GET", `/v1/admin/networks/${netId}/nodes`, { admin: ADMIN });
  const online2 = (list2.body.nodes ?? []).filter((r) => r.online).length;
  check("保持结束后管理面仍显示全部在线", online2 === NODES, { online2 });

  console.log("\n6. 清理");
  for (const c of conns) {
    try {
      c.ws.close(1000, "done");
    } catch {
      /* 已关 */
    }
  }
  await sleep(1_500);
  const del = await api("DELETE", `/v1/admin/networks/${netId}`, { admin: ADMIN, body: { confirm: netId } });
  check("删除压测网络", del.status === 200 && del.body.ok === true, del.body);

  const total = Math.round((Date.now() - startedAt) / 1000);
  console.log(`\n结果：${passed} 通过，${failed} 失败（耗时 ${total} 秒，${NODES} 节点）`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\n中断：", e?.message ?? e);
  process.exit(1);
});
