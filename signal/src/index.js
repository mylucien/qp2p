import { NetworkRoom } from "./room.js";

export { NetworkRoom };

const TOKEN_PREFIX = "qp2p1_";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/v1/health") {
      return json({ ok: true, ts: Date.now() });
    }

    if (url.pathname === "/v1/admin/networks" && request.method === "POST") {
      return createNetwork(request, env);
    }

    const auth = await authenticate(request, env);
    if (!auth.ok) return auth.response;

    const { network } = auth;
    const roomUrl = `https://room.local${url.pathname}?network_id=${encodeURIComponent(
      network.network_id,
    )}&cidr=${encodeURIComponent(network.cidr)}`;
    const forwarded = new Request(roomUrl, request);
    const stub = env.ROOMS.get(env.ROOMS.idFromName(network.network_id));

    if (url.pathname === "/v1/join") {
      return json({
        ok: true,
        network: {
          id: network.network_id,
          name: network.name,
          cidr: network.cidr,
        },
        server_ms: Date.now(),
      });
    }

    if (
      url.pathname === "/v1/register" ||
      url.pathname === "/v1/connect" ||
      url.pathname === "/v1/leave" ||
      url.pathname === "/v1/ws"
    ) {
      return stub.fetch(forwarded);
    }

    return err(404, "not_found");
  },
};

async function createNetwork(request, env) {
  const provided = request.headers.get("x-admin-secret") ?? "";
  if (!env.ADMIN_SECRET || provided !== env.ADMIN_SECRET) {
    return err(401, "invalid_admin_secret");
  }

  const body = await request.json().catch(() => ({}));
  const name = (body.name ?? "").trim() || "network";
  const networkId = randomHex(6);
  const secret = randomHex(24);
  const token = `${TOKEN_PREFIX}${networkId}_${secret}`;

  const existing = await env.DB.prepare("SELECT COUNT(*) AS n FROM networks").first();
  const index = Number(existing?.n ?? 0);
  if (index >= 64) {
    return err(507, "network_quota_exhausted", "10.64.0.0/10 已分满");
  }
  const cidr = `10.${64 + index}.0.0/16`;

  await env.DB.prepare(
    "INSERT INTO networks (network_id, name, token_hash, cidr, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(networkId, name, await sha256Hex(secret), cidr, Date.now())
    .run();

  return json({
    ok: true,
    network: { id: networkId, name, cidr },
    token,
    note: "密钥只显示这一次",
  });
}

async function authenticate(request, env) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const parsed = parseToken(token);
  if (!parsed) return { ok: false, response: err(401, "invalid_token") };

  const row = await env.DB.prepare(
    "SELECT network_id, name, cidr, token_hash FROM networks WHERE network_id = ?",
  )
    .bind(parsed.networkId)
    .first();
  if (!row) return { ok: false, response: err(403, "unknown_network") };

  if ((await sha256Hex(parsed.secret)) !== row.token_hash) {
    return { ok: false, response: err(403, "wrong_secret") };
  }

  return { ok: true, network: row };
}

export function parseToken(token) {
  if (!token.startsWith(TOKEN_PREFIX)) return null;
  const rest = token.slice(TOKEN_PREFIX.length);
  const index = rest.indexOf("_");
  if (index <= 0 || index === rest.length - 1) return null;
  return { networkId: rest.slice(0, index), secret: rest.slice(index + 1) };
}

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function err(status, code, detail) {
  return json({ ok: false, error: code, ...(detail ? { detail } : {}) }, status);
}
