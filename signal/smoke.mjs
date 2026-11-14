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
import { fakeRoomBinding } from "./fake-room.mjs";

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

  /**
   * `impl` 用来指定"哪个 isolate"：本地用 `import("./worker.js?x=1")` 拿到另一个
   * 模块实例，各自持有独立的网络行缓存，DO 与 D1 仍然共用——这正是多 isolate 的模型。
   */
  const call = async (method, path, { token, admin, body, query, impl, upgrade } = {}) => {
    const url = new URL(`${base}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, String(v));
    // 本地跑时用伪造的 cf-connecting-ip 隔离限流桶；打真机时不能带——
    // Cloudflare 边缘会把它当成伪造请求直接 403。
    const headers = { "content-type": "application/json" };
    if (!remote) headers["cf-connecting-ip"] = clientIp;
    if (upgrade) headers.upgrade = "websocket";
    if (token) headers.authorization = `Bearer ${token}`;
    if (admin) headers["x-admin-secret"] = admin;
    const request = new Request(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const res = remote ? await fetch(request) : await (impl ?? worker).fetch(request, env, ctx);
    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      // 边缘返回 HTML（403 挑战页、5xx）时保留一小段原文，断言失败但不中断整轮
      parsed = { _raw: text.slice(0, 200), _status: res.status };
    }
    return { status: res.status, body: parsed };
  };

  console.log(`\n=== ${label} ===`);

  // 远端模式：先把上一轮可能残留的测试网络删掉，保证每轮都从干净状态开始。
  // 本地模式不需要——每次都是新的内存/D1 替身。
  if (remote) {
    for (const name of ["home-lab", "lab", "weak-key-test", "rotate-test", "resv-test", "tiny"]) {
      try {
        await fetch(`${base}/v1/admin/networks/${name}`, {
          method: "DELETE",
          headers: { "x-admin-secret": secret, "content-type": "application/json" },
          body: JSON.stringify({ confirm: name }),
        });
      } catch {
        // 不存在就是最好情况
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  console.log("\n1. 健康检查");
  const anon = await call("GET", "/v1/health");
  check("匿名可达", anon.status === 200 && anon.body.ok === true, anon.body);
  check(
    "匿名看不到版本/存储",
    anon.body.version === undefined && anon.body.storage === undefined,
    anon.body,
  );
  const health = await call("GET", "/v1/health", { admin: secret });
  check("带管理密钥看到详情", health.status === 200 && health.body.ok === true, health.body);
  check(`storage=${expectedStorage}`, health.body.storage === expectedStorage, health.body.storage);

  const root = await call("GET", "/");
  check("根路径不暴露接口清单", root.status === 404, root.body);

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

  // 网络名允许中文（只有 id 强制 ASCII）。名字要经 x-qp2p-net 头传给 DO，而 HTTP 头
  // 只能是 Latin-1——原样塞中文会让这个网络的每个业务请求都 500。
  const zhNet = await call("POST", "/v1/admin/networks", {
    admin: secret,
    body: { name: "我的家庭网络", join_key: "chinese-key-000001" },
  });
  check("可以用中文给网络起名", zhNet.status === 200 && zhNet.body.network?.name === "我的家庭网络", zhNet.body);
  const zhProbe = await probe(zhNet.body.token);
  check("中文名网络的业务请求不 500", zhProbe.status === 404 && zhProbe.body.error === "unknown_node", zhProbe.body);

  /**
   * 第二个 isolate：独立的网络行缓存（15 秒），D1 与 DO 仍与主 isolate 共用。
   * 远端模式只有一个 Worker，造不出第二个 isolate，这几条只在本机跑。
   */
  const workerB = remote ? null : (await import("./worker.js?isolate=stale")).default;
  if (workerB) {
    const warm = await call("GET", "/v1/events", {
      token: rotOld,
      query: { node_id: "0".repeat(32), since: 0 },
      impl: workerB,
    });
    check("另一个 isolate 先缓存了旧网络行", warm.body.error === "unknown_node", warm.body);
  }

  const rotated = await call("POST", "/v1/admin/networks/rotate-test/rotate", {
    admin: secret,
    body: { join_key: "rotate-preset-key-0002" },
  });
  check(
    "轮换返回新令牌",
    rotated.status === 200 && rotated.body.token !== rotOld,
    rotated.body,
  );
  check("轮换成功时标明已断开旧连接", rotated.body.kicked === true, rotated.body);
  const afterOld = await probe(rotOld);
  const afterNew = await probe(rotated.body.token);
  check("旧令牌立刻失效", afterOld.body.error === "wrong_secret", afterOld.body);
  check("新令牌可用", afterNew.body.error === "unknown_node", afterNew.body);

  if (workerB) {
    // 要点：这个 isolate 的缓存里还是旧 join_hash，它自己"验得过"旧令牌。
    // 拦住它的是 DO 手里的 rev（换密钥时前进），不是缓存新鲜度。
    const staleEvents = await call("GET", "/v1/events", {
      token: rotOld,
      query: { node_id: "0".repeat(32), since: 0 },
      impl: workerB,
    });
    check(
      "换密钥后旧缓存 isolate 的请求被拒",
      staleEvents.status === 403 && staleEvents.body.error === "stale_net_rev",
      staleEvents.body,
    );

    // 最初复现的就是这条：旧令牌在旧缓存 isolate 里握手拿到 101，之后再也不被踢
    const staleWs = await call("GET", `/v1/ws?node_id=${"0".repeat(32)}&since=0`, {
      token: rotOld,
      impl: workerB,
      upgrade: true,
    });
    check(
      "换密钥后旧缓存 isolate 的握手被拒（不是 101）",
      staleWs.status === 403 && staleWs.body.error === "stale_net_rev",
      staleWs.body,
    );

    // 反方向：这个 isolate 缓存里还是旧 join_hash，拿**新**令牌来反而"对不上"。
    // 鉴权失败时读一次主库即可消掉这 15 秒窗口；否则客户端会因为 403 直接停止。
    const newOnStale = await call("GET", "/v1/events", {
      token: rotated.body.token,
      query: { node_id: "0".repeat(32), since: 0 },
      impl: workerB,
      clientIp: "198.18.0.5",
    });
    check(
      "换密钥后新令牌在旧缓存 isolate 里也能用（不是 403 wrong_secret）",
      newOnStale.status === 404 && newOnStale.body.error === "unknown_node",
      newOnStale.body,
    );
  }

  if (workerB) {
    // 改名不 bump rev：别的 isolate 缓存里的旧名字不能被判成"令牌失效"，
    // 否则改一次名字等于把全网在每个 isolate 的缓存过期前都踢掉。
    const renNet = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: "rename-test", join_key: "rename-preset-key-0001" },
    });
    const renWarm = await call("GET", "/v1/events", {
      token: renNet.body.token,
      query: { node_id: "0".repeat(32), since: 0 },
      impl: workerB,
    });
    check("改名测试：旧 isolate 已缓存", renWarm.body.error === "unknown_node", renWarm.body);
    const renamed = await call("PATCH", "/v1/admin/networks/rename-test", {
      admin: secret,
      body: { name: "rename-test-2" },
    });
    check("改名成功", renamed.status === 200 && renamed.body.changed === true, renamed.body);
    const renAfter = await call("GET", "/v1/events", {
      token: renNet.body.token,
      query: { node_id: "0".repeat(32), since: 0 },
      impl: workerB,
    });
    check("改名后旧缓存 isolate 不被误判为过期", renAfter.body.error === "unknown_node", renAfter.body);
  }

  if (workerB) {
    // 删网后另一个 isolate 的缓存还能往里写数据（孤儿网络）：墓碑必须拦住
    const orphanId = "orphan-test";
    const orphan = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: orphanId, join_key: "orphan-preset-key-0001" },
    });
    const orphanToken = orphan.body.token;
    const orphanWarm = await call("GET", "/v1/events", {
      token: orphanToken,
      query: { node_id: "0".repeat(32), since: 0 },
      impl: workerB,
    });
    check("删网前旧 isolate 已缓存网络行", orphanWarm.body.error === "unknown_node", orphanWarm.body);

    const orphanDel = await call("DELETE", `/v1/admin/networks/${orphanId}`, {
      admin: secret,
      body: { confirm: orphanId },
    });
    check("删网成功", orphanDel.status === 200, orphanDel.body);

    const ghost = await identity();
    const ghostJoin = await call("POST", "/v1/join", {
      token: orphanToken,
      impl: workerB,
      body: await signed(ghost, "join", orphanId, {
        node_id: ghost.nodeId,
        pubkey: ghost.pubkey,
        name: "orphan",
      }),
    });
    check(
      "删网后旧缓存 isolate 不能再 join（报网络已删除）",
      ghostJoin.status === 403 && ghostJoin.body.error === "network_deleted",
      ghostJoin.body,
    );

    // 重建同名网络要拿得到新 rev，不能被自己上一次的墓碑永久拒绝
    const rebuilt = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: orphanId, join_key: "orphan-preset-key-0002" },
    });
    check("删网后可以用同名重建", rebuilt.status === 200, rebuilt.body);
    const rebuiltProbe = await probe(rebuilt.body.token);
    check("重建后的新令牌可用", rebuiltProbe.body.error === "unknown_node", rebuiltProbe.body);
  }

  if (!remote) {
    // 换密钥的原子性：D1 已经改了、通知 DO 失败，绝不能把新令牌留在 500 里
    const downId = "rotate-down";
    const downNet = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: downId, join_key: "rotate-down-key-0001" },
    });
    const realRoom = env.ROOM;
    env.ROOM = {
      idFromName: (n) => ({ name: String(n) }),
      get: () => ({
        fetch: async () => {
          throw new Error("DO down (simulated)");
        },
      }),
    };
    let downRes;
    try {
      downRes = await call("POST", `/v1/admin/networks/${downId}/rotate`, {
        admin: secret,
        body: { join_key: "rotate-down-key-0002" },
      });
    } finally {
      env.ROOM = realRoom;
    }
    check(
      "DO 故障时换密钥仍返回新令牌",
      downRes.status === 200 && typeof downRes.body.token === "string" && downNet.body.token !== downRes.body.token,
      downRes.body,
    );
    check(
      "DO 故障时标明 kicked=false 并说明原因",
      downRes.body.kicked === false && Boolean(downRes.body.warning),
      downRes.body,
    );
    const downAfter = await probe(downRes.body.token);
    check("DO 恢复后新令牌可用", downAfter.body.error === "unknown_node", downAfter.body);
  }

  if (!remote) {
    /**
     * 回归：改网段时通知 DO 失败，DO 原先会永久停在旧网段。
     *
     * 成因：改动只写 D1（rev 不前进），DO 只在 rev 前进时覆盖上下文；管理员重试时
     * D1 里已是新值，`changes.length === 0` 直接返回，永远不再推给 DO。
     * 现在两条路都能收尾：cfg_rev（普通请求即可自愈）与幂等重推（管理员重试）。
     */
    console.log("\n2.5 改网段：通知失败后可自愈");

    const breakRoom = () => {
      const real = env.ROOM;
      env.ROOM = {
        idFromName: (n) => ({ name: String(n) }),
        get: () => ({
          fetch: async () => {
            throw new Error("DO down (simulated)");
          },
        }),
      };
      return () => {
        env.ROOM = real;
        return real;
      };
    };

    // A. 管理员重试路径：第二次 PATCH（同网段）只为重推上下文
    const cfgId = "cidr-down";
    const cfgNet = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: cfgId, join_key: "cidr-down-key-0001" },
    });
    const cfgToken = cfgNet.body.token;
    const cfgOld = cfgNet.body.network.cidr;
    await probe(cfgToken); // 让 DO 先拿到旧网段（创建网络本身不碰 DO）
    const roomOf = env.ROOM.roomOf(cfgId);
    check("DO 已记下旧网段", roomOf.net()?.cidr === cfgOld, roomOf.net());

    const restore = breakRoom();
    let cfgDown;
    try {
      cfgDown = await call("PATCH", `/v1/admin/networks/${cfgId}`, {
        admin: secret,
        body: { cidr: "10.201.0.0/16" },
      });
    } finally {
      restore();
    }
    check(
      "改网段通知失败时返回 200（不是 500）",
      cfgDown.status === 200 && cfgDown.body.changed === true,
      cfgDown.body,
    );
    check(
      "改网段通知失败时标明 synced=false 并给出提示",
      cfgDown.body.synced === false && Boolean(cfgDown.body.warning),
      cfgDown.body,
    );
    check("DO 确实停在旧网段（复现前提）", roomOf.net()?.cidr === cfgOld, roomOf.net());

    const retried = await call("PATCH", `/v1/admin/networks/${cfgId}`, {
      admin: secret,
      body: { cidr: "10.201.0.0/16" },
    });
    check(
      "重试同样的修改：changed=false 但仍然重推",
      retried.status === 200 && retried.body.changed === false && retried.body.synced === true,
      retried.body,
    );
    check(
      "重试后 DO 跟上新网段",
      roomOf.net()?.cidr === "10.201.0.0/16",
      roomOf.net(),
    );

    // B. cfg_rev 路径：不靠管理员重试，普通业务请求也能把新网段推过去
    const cfg2 = "cidr-cfg";
    const cfg2Net = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: cfg2, join_key: "cidr-cfg-key-00001" },
    });
    const cfg2Old = cfg2Net.body.network.cidr;
    await probe(cfg2Net.body.token);
    const room2 = env.ROOM.roomOf(cfg2);
    const restore2 = breakRoom();
    try {
      await call("PATCH", `/v1/admin/networks/${cfg2}`, {
        admin: secret,
        body: { cidr: "10.202.0.0/16" },
      });
    } finally {
      restore2();
    }
    check("cfg 路径：DO 仍在旧网段", room2.net()?.cidr === cfg2Old, room2.net());
    const healed = await probe(cfg2Net.body.token);
    check("cfg 路径：普通请求不被当成过期", healed.body.error === "unknown_node", healed.body);
    check(
      "cfg 路径：普通请求把新网段推给了 DO",
      room2.net()?.cidr === "10.202.0.0/16",
      room2.net(),
    );
    check(
      "cfg_rev 前进但 rev 不变（改名/改网段不踢人）",
      Number(room2.net()?.rev ?? 0) > 0 && Number(room2.net()?.cfg_rev ?? 0) > 0,
      room2.net(),
    );
  }

  if (!remote) {
    /**
     * 删网中途失败：DO 已打墓碑、D1 行还在。此时请求应当报"网络已删除"，
     * 而不是误导人的"上下文已过期"；管理员再删一次能收尾。
     */
    console.log("\n2.6 删网中途失败");

    const delId = "del-half";
    const delNet = await call("POST", "/v1/admin/networks", {
      admin: secret,
      body: { name: delId, join_key: "del-half-key-00001" },
    });
    const delToken = delNet.body.token;
    await probe(delToken);

    const realDB = env.DB;
    // 两次（首次 + 内部重试）都失败，才走到"请再执行一次删除"这条分支
    let failsLeft = 2;
    env.DB = {
      prepare(sql) {
        if (/^\s*DELETE\s+FROM\s+networks/i.test(sql) && failsLeft > 0) {
          failsLeft -= 1;
          return {
            bind: () => ({
              run: () => {
                throw new Error("D1 write failed (simulated)");
              },
            }),
          };
        }
        return realDB.prepare(sql);
      },
    };
    let delRes;
    try {
      delRes = await call("DELETE", `/v1/admin/networks/${delId}`, {
        admin: secret,
        body: { confirm: delId },
      });
    } finally {
      env.DB = realDB;
    }
    check(
      "删网记录失败时给出明确错误码与收尾提示",
      delRes.status === 500 &&
        delRes.body.error === "delete_record_failed" &&
        String(delRes.body.detail).includes("再执行一次"),
      delRes.body,
    );
    const halfProbe = await probe(delToken);
    check(
      "中间态报网络已删除（不是上下文过期）",
      halfProbe.status === 403 && halfProbe.body.error === "network_deleted",
      halfProbe.body,
    );
    const delAgain = await call("DELETE", `/v1/admin/networks/${delId}`, {
      admin: secret,
      body: { confirm: delId },
    });
    check("再删一次收尾", delAgain.status === 200, delAgain.body);
    const goneRow = await call("GET", `/v1/admin/networks/${delId}`, { admin: secret });
    check("收尾后网络行已删除", goneRow.status === 404, goneRow.body);
  }

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
  // join / register 是幂等的，不再占 nonce（省两行写入）：重放同一报文只会写入同样的内容。
  // 破坏性的 leave 和有副作用的 connect 仍然防重放，见下面对应的测试。
  const replayJoin = await call("POST", "/v1/join", { token, body: tamperBase });
  check(
    "join 同报文重放是幂等的（结果与首次一致）",
    replayJoin.status === 200 &&
      replayJoin.body.node?.virtual_ip === firstUse.body.node?.virtual_ip,
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
  // 事件流里除了发给 bob 的 punch_request，还有全网广播的 peer_online：按类型分开断言
  const punches = (firstPull.body.events ?? []).filter((e) => e.type === "punch_request");
  const presence = (firstPull.body.events ?? []).filter((e) => e.type === "peer_online");
  check("bob 收到一条 punch_request", punches.length === 1, firstPull.body);
  check("事件里带发起方的候选", Array.isArray(punches[0]?.candidates), punches[0]);
  check(
    "bob 能读到自己注册时的上线广播",
    presence.some((e) => e.node_id === bob.nodeId && e.candidates?.length > 0),
    presence,
  );
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
  const alicePunches = (alicePull.body.events ?? []).filter((e) => e.type === "punch_request");
  check("alice 没有收到撮合请求", alicePunches.length === 0, alicePull.body);
  check(
    "alice 通过广播得知 bob 上线",
    (alicePull.body.events ?? []).some((e) => e.type === "peer_online" && e.node_id === bob.nodeId),
    alicePull.body,
  );

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

  const leaveBody = await signed(bob, "leave", net, { node_id: bob.nodeId, pubkey: bob.pubkey });
  const left = await call("POST", "/v1/leave", { token, body: leaveBody });
  check("下线成功", left.status === 200 && left.body.ok === true, left.body);
  const replayLeave = await call("POST", "/v1/leave", { token, body: leaveBody });
  check(
    "leave 重放被拒（破坏性操作仍然防重放）",
    replayLeave.status === 403 && String(replayLeave.body.detail).includes("重放"),
    replayLeave.body,
  );

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
  check("节点列表带首次上线时间", Number(eveRow?.first_seen) > 0, eveRow?.first_seen);

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

  const batchKick = await call("POST", `/v1/admin/networks/${rNet}/nodes/kick`, {
    admin: secret,
    body: { node_ids: [nick.nodeId] },
  });
  check("批量踢下线成功", batchKick.status === 200 && batchKick.body.removed === 1, batchKick.body);

  const batchBad = await call("POST", `/v1/admin/networks/${rNet}/nodes/kick`, {
    admin: secret,
    body: { node_ids: ["not-a-node-id"] },
  });
  check("批量踢下线校验 node_id", batchBad.status === 400, batchBad.body);

  const auditRows = await call("GET", "/v1/admin/audit?limit=50", { admin: secret });
  const actions = (auditRows.body.actions ?? []).map((a) => a.action);
  check("审计记录改网段", actions.includes("network.update"), actions);
  check("审计记录踢下线", actions.includes("node.kick"), actions);
  check("审计记录预留", actions.includes("reservation.put"), actions);

  // 审计分页：服务端筛选 + 总数 + 页码钳制，旧 limit 参数保持兼容
  const auditP1 = await call("GET", "/v1/admin/audit?page=1&page_size=3", { admin: secret });
  const auditP2 = await call("GET", "/v1/admin/audit?page=2&page_size=3", { admin: secret });
  check(
    "审计分页返回总数与页数",
    auditP1.status === 200 && typeof auditP1.body.total === "number" &&
      auditP1.body.pages >= 1 && auditP1.body.page === 1,
    auditP1.body,
  );
  check("审计每页不超过 3 条", (auditP1.body.actions ?? []).length <= 3, auditP1.body.actions?.length);
  const auditKey = (a) => `${a.at}|${a.action}|${a.target}|${a.detail}`;
  const p1Keys = (auditP1.body.actions ?? []).map(auditKey);
  const p2Keys = (auditP2.body.actions ?? []).map(auditKey);
  check("审计两页不重叠", p1Keys.every((k) => !p2Keys.includes(k)), p2Keys);
  const auditKind = await call("GET", "/v1/admin/audit?page=1&page_size=20&kind=login.", { admin: secret });
  check(
    "审计按类别筛选",
    (auditKind.body.actions ?? []).every((a) => String(a.action).startsWith("login.")),
    auditKind.body.actions,
  );
  const auditQ = await call("GET", "/v1/admin/audit?page=1&page_size=20&q=admin", { admin: secret });
  check("审计搜索不越页", (auditQ.body.actions ?? []).length <= 20, auditQ.body.actions?.length);
  const auditFar = await call("GET", "/v1/admin/audit?page=9999&page_size=3", { admin: secret });
  check("审计越界页码钳到最后一页", auditFar.body.page === auditFar.body.pages, auditFar.body);
  const auditLegacy = await call("GET", "/v1/admin/audit?limit=50", { admin: secret });
  check("审计旧 limit 参数仍可用", Array.isArray(auditLegacy.body.actions), auditLegacy.body);

  const status1 = await call("GET", "/v1/admin/status");
  check("管理状态可查", status1.status === 200, status1.body);

  if (!remote) {
    // 账号流程只在本地跑：远端可能已经初始化过，重复 bootstrap 会 409
    check("初始状态需要创建账号", status1.body.needs_bootstrap === true, status1.body);

    const bootWrong = await call("POST", "/v1/admin/bootstrap", {
      body: { secret: "wrong", username: "admin", password: "password123" },
    });
    check("初始化密钥错误被拒", bootWrong.status === 401, bootWrong.body);

    const bootShort = await call("POST", "/v1/admin/bootstrap", {
      body: { secret, username: "admin", password: "short" },
    });
    check("过短密码被拒", bootShort.status === 400 && bootShort.body.error === "weak_password", bootShort.body);

    const bootBadName = await call("POST", "/v1/admin/bootstrap", {
      body: { secret, username: "A", password: "password123" },
    });
    check("用户名不合规被拒", bootBadName.status === 400, bootBadName.body);

    const bootReq = new Request(`${base}/v1/admin/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret, username: "admin", password: "password123" }),
    });
    const bootRes = await worker.fetch(bootReq, env, ctx);
    const bootBody = await bootRes.json();
    check("初始化账号成功", bootRes.status === 200 && bootBody.ok === true, bootBody);
    const setCookie = bootRes.headers.get("set-cookie") ?? "";
    check(
      "初始化后下发 HttpOnly 会话",
      /qp2p_admin=/.test(setCookie) && /HttpOnly/.test(setCookie),
      setCookie,
    );

    const status2 = await call("GET", "/v1/admin/status");
    check("初始化后不再需要创建", status2.body.needs_bootstrap === false, status2.body);

    const bootAgain = await call("POST", "/v1/admin/bootstrap", {
      body: { secret, username: "admin2", password: "password123" },
    });
    check("重复初始化被拒", bootAgain.status === 409, bootAgain.body);

    const badLogin = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "wrong-password" },
    });
    check("密码错误被拒", badLogin.status === 401 && badLogin.body.error === "bad_credentials", badLogin.body);

    const noUser = await call("POST", "/v1/admin/login", {
      body: { username: "nobody", password: "password123" },
    });
    check("不存在的账号同样报凭据错误", noUser.status === 401, noUser.body);

    const loginReq = new Request(`${base}/v1/admin/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "password123" }),
    });
    const loginRes = await worker.fetch(loginReq, env, ctx);
    check("账号密码登录成功", loginRes.status === 200, loginRes.status);
    const loginCookie = loginRes.headers.get("set-cookie") ?? "";
    check("登录下发会话", /qp2p_admin=/.test(loginCookie), loginCookie);

    const cookieHeader = loginCookie.split(";")[0];
    const cookieReq = new Request(`${base}/v1/admin/networks`, { headers: { cookie: cookieHeader } });
    const cookieRes = await worker.fetch(cookieReq, env, ctx);
    check("cookie 可以访问管理接口", cookieRes.status === 200, cookieRes.status);

    const forgedReq = new Request(`${base}/v1/admin/networks`, {
      headers: { cookie: "qp2p_admin=9999999999999.admin.deadbeefdeadbeefdeadbeefdeadbeef" },
    });
    const forgedRes = await worker.fetch(forgedReq, env, ctx);
    check("伪造 cookie 被拒", forgedRes.status === 401, forgedRes.status);

    const pwdWrong = await call("POST", "/v1/admin/password", {
      body: { old_password: "nope", new_password: "newpassword1" },
    });
    check("未登录不能改密码", pwdWrong.status === 401, pwdWrong.body);

    const pwdReq = new Request(`${base}/v1/admin/password`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: cookieHeader },
      body: JSON.stringify({ old_password: "password123", new_password: "newpassword1" }),
    });
    const pwdRes = await worker.fetch(pwdReq, env, ctx);
    check("登录后可以改密码", pwdRes.status === 200, pwdRes.status);

    // 改密码的首要目的是"把可能被偷走的那份会话踢掉"。原来 cookie 的 MAC 只绑
    // username + 过期时间，改完密码旧 cookie 照样能用满 2 小时。
    const staleCookieRes = await worker.fetch(
      new Request(`${base}/v1/admin/networks`, { headers: { cookie: cookieHeader } }),
      env,
      ctx,
    );
    check("改密码后旧 cookie 立刻失效", staleCookieRes.status === 401, staleCookieRes.status);

    const freshCookie = (pwdRes.headers.get("set-cookie") ?? "").split(";")[0];
    const freshCookieRes = await worker.fetch(
      new Request(`${base}/v1/admin/networks`, { headers: { cookie: freshCookie } }),
      env,
      ctx,
    );
    check(
      "改密码发的新 cookie 直接可用（不会把自己踢下线）",
      freshCookieRes.status === 200,
      freshCookieRes.status,
    );

    const oldPwdLogin = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "password123" },
    });
    check("改完密码旧密码失效", oldPwdLogin.status === 401, oldPwdLogin.body);

    const reset = await call("POST", "/v1/admin/password/reset", {
      admin: secret,
      body: { username: "admin", new_password: "resetpassword1" },
    });
    check("命令行密钥可重置密码", reset.status === 200, reset.body);

    const afterResetRes = await worker.fetch(
      new Request(`${base}/v1/admin/networks`, { headers: { cookie: freshCookie } }),
      env,
      ctx,
    );
    check("命令行重置密码后旧 cookie 失效", afterResetRes.status === 401, afterResetRes.status);

    const resetLogin = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "resetpassword1" },
    });
    check("重置后新密码可登录", resetLogin.status === 200, resetLogin.body);

    // 登出只清浏览器 cookie 是不够的：泄漏出去的副本会一直用到过期（最长 2 小时），
    // 管理员点"登出"等于没做。这里验服务端真的把会话作废了。
    const logoutLoginRes = await worker.fetch(
      new Request(`${base}/v1/admin/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "admin", password: "resetpassword1" }),
      }),
      env,
      ctx,
    );
    const logoutCookie = (logoutLoginRes.headers.get("set-cookie") ?? "").split(";")[0];
    const logoutRes = await worker.fetch(
      new Request(`${base}/v1/admin/logout`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie: logoutCookie },
      }),
      env,
      ctx,
    );
    const logoutBody = await logoutRes.json().catch(() => null);
    check(
      "带会话登出返回 revoked:true",
      logoutRes.status === 200 && logoutBody?.revoked === true,
      logoutBody,
    );

    const afterLogoutRes = await worker.fetch(
      new Request(`${base}/v1/admin/networks`, { headers: { cookie: logoutCookie } }),
      env,
      ctx,
    );
    check("登出后旧 cookie 立刻失效", afterLogoutRes.status === 401, afterLogoutRes.status);

    // 未登录也要能调登出（清掉自己浏览器里的死 cookie），但绝不能推动别人的代次，
    // 否则任何人都能凭一个用户名把管理员踢下线。
    const anonLogoutRes = await worker.fetch(
      new Request(`${base}/v1/admin/logout`, {
        method: "POST",
        headers: { "content-type": "application/json" },
      }),
      env,
      ctx,
    );
    const anonLogoutBody = await anonLogoutRes.json().catch(() => null);
    check(
      "未登录调登出不撤销任何会话",
      anonLogoutRes.status === 200 && anonLogoutBody?.revoked === false,
      anonLogoutBody,
    );

    // 爆破防护：3 次失败后成功登录应清零计数
    for (let i = 0; i < 3; i += 1) {
      await call("POST", "/v1/admin/login", {
        body: { username: "admin", password: "definitely-wrong" },
      });
    }
    const afterThree = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "resetpassword1" },
    });
    check("失败几次后仍可正常登录", afterThree.status === 200, afterThree.body);

    const stillOpen = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "definitely-wrong" },
    });
    check("成功登录会清零失败计数", stillOpen.status === 401, stillOpen.body);

    // 再连续失败 4 次（累计 5 次）应触发 60 秒锁定
    for (let i = 0; i < 3; i += 1) {
      await call("POST", "/v1/admin/login", {
        body: { username: "admin", password: "definitely-wrong" },
      });
    }
    const locked = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "definitely-wrong" },
    });
    check(
      "连续失败 5 次触发锁定",
      locked.status === 429 && locked.body.error === "too_many_attempts",
      locked.body,
    );

    const lockedEvenCorrect = await call("POST", "/v1/admin/login", {
      body: { username: "admin", password: "resetpassword1" },
    });
    check("锁定期间密码正确也拒绝", lockedEvenCorrect.status === 429, lockedEvenCorrect.body);

    const otherUser = await call("POST", "/v1/admin/login", {
      body: { username: "someone-else", password: "whatever-123" },
    });
    check("锁定只影响该账号", otherUser.status === 401, otherUser.body);

    const auditAfter = await call("GET", "/v1/admin/audit?limit=50", { admin: secret });
    const loginActions = (auditAfter.body.actions ?? []).map((a) => a.action);
    check("审计记录登录与账号操作", loginActions.includes("login.ok") && loginActions.includes("admin.password"), loginActions);
    const withActor = (auditAfter.body.actions ?? []).some((a) => a.actor === "admin");
    check("审计记录操作人", withActor, auditAfter.body.actions?.[0]);
  }

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
  // 只有一种引擎了：控制面在 D1 替身，数据面在 DO 替身。
  // ROOM 与 Worker 共用同一个 env 对象，这样用例临时改的 env 变量也能传进 DO。
  const roomEnv = { ADMIN_SECRET, DB: fakeD1() };
  roomEnv.ROOM = fakeRoomBinding(roomEnv);
  await runSuite("端到端", roomEnv, "d1", "198.18.0.4");
}

console.log(`\n结果：${totals.passed} 通过，${totals.failed} 失败\n`);
process.exit(totals.failed === 0 ? 0 : 1);
