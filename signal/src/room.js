import { err, json, sha256Hex } from "./index.js";

const OFFLINE_MS = 120_000;
const FLUSH_INTERVAL_MS = 60_000;

/**
 * 每个网络一个实例：在线节点表、长连接、撮合。
 * 候选地址只存在这里的内存/存储里，D1 只放冷数据。
 */
export class NetworkRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.nodes = null;
    this.networkId = null;
  }

  async load() {
    if (!this.nodes) {
      this.nodes = (await this.state.storage.get("nodes")) ?? {};
    }
    return this.nodes;
  }

  async persist() {
    await this.state.storage.put("nodes", this.nodes);
    const current = await this.state.storage.getAlarm();
    if (current === null) {
      await this.state.storage.setAlarm(Date.now() + FLUSH_INTERVAL_MS);
    }
  }

  async fetch(request) {
    const url = new URL(request.url);
    this.networkId = url.searchParams.get("network_id") ?? this.networkId;
    this.cidr = url.searchParams.get("cidr") ?? this.cidr ?? "10.64.0.0/16";
    await this.load();

    if (url.pathname === "/v1/ws") {
      return this.handleWebSocket(request, url);
    }

    const body = await request.json().catch(() => ({}));

    switch (url.pathname) {
      case "/v1/register":
        return this.register(body);
      case "/v1/connect":
        return this.connect(body);
      case "/v1/leave":
        return this.leave(body);
      default:
        return err(404, "not_found");
    }
  }

  async register(body) {
    const { node_id, name, pubkey, tls_fp, candidates, nat_type, advertise } = body;
    if (!node_id || !Array.isArray(candidates) || candidates.length === 0) {
      return err(400, "invalid_register", "node_id 与 candidates 必填");
    }

    const nodes = this.nodes ?? {};
    const previous = nodes[node_id];
    const virtualIp = previous?.virtual_ip ?? (await this.assignIp(node_id, nodes));

    nodes[node_id] = {
      node_id,
      name: name ?? node_id.slice(0, 8),
      pubkey: pubkey ?? "",
      tls_fp: tls_fp ?? "",
      candidates,
      nat_type: nat_type ?? "unknown",
      advertise: advertise ?? [],
      virtual_ip: virtualIp,
      last_seen: Date.now(),
    };
    await this.persist();
    await this.upsertD1(nodes[node_id]);

    return json({
      ok: true,
      virtual_ip: virtualIp,
      peers: Object.values(nodes).map(publicNode),
      server_ms: Date.now(),
    });
  }

  async connect(body) {
    const { from, target, candidates } = body;
    if (!from || !target) return err(400, "missing_field", "from 与 target 必填");

    const peer = this.nodes?.[target];
    if (!peer) return err(404, "target_not_found");
    if (Date.now() - peer.last_seen > OFFLINE_MS) return err(410, "target_offline");

    const t = Date.now() + 500;

    if (Array.isArray(candidates) && candidates.length > 0) {
      const self = this.nodes[from];
      if (self) {
        self.candidates = candidates;
        self.last_seen = Date.now();
        await this.persist();
      }
    }

    let delivered = 0;
    for (const socket of this.state.getWebSockets(target)) {
      try {
        socket.send(
          JSON.stringify({
            type: "punch_request",
            from,
            candidates: this.nodes?.[from]?.candidates ?? candidates ?? [],
            t,
            server_ms: Date.now(),
          }),
        );
        delivered += 1;
      } catch {
        // 连接已断，忽略
      }
    }

    return json({
      ok: true,
      t,
      delivered,
      target_candidates: peer.candidates,
      target_virtual_ip: peer.virtual_ip,
      target_tls_fp: peer.tls_fp,
      server_ms: Date.now(),
    });
  }

  async leave(body) {
    const { node_id } = body;
    if (node_id && this.nodes?.[node_id]) {
      delete this.nodes[node_id];
      await this.persist();
      await this.env.DB.prepare("DELETE FROM nodes WHERE network_id = ? AND node_id = ?")
        .bind(this.networkId, node_id)
        .run();
    }
    return json({ ok: true });
  }

  async handleWebSocket(request, url) {
    if (request.headers.get("upgrade") !== "websocket") {
      return err(426, "upgrade_required");
    }
    const nodeId = url.searchParams.get("node_id");
    if (!nodeId) return err(400, "missing_node_id", "node_id 必填");

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server, [nodeId]);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    let payload;
    try {
      payload = JSON.parse(message);
    } catch {
      return;
    }
    if (payload.type === "pong" && Array.isArray(payload.candidates)) {
      const node = this.nodes?.[payload.node_id];
      if (node) {
        node.candidates = payload.candidates;
        node.last_seen = Date.now();
        await this.persist();
      }
    }
  }

  async webSocketClose() {
    for (const node of Object.values(this.nodes ?? {})) {
      node.last_seen = Date.now();
    }
    await this.persist();
  }

  async alarm() {
    const nodes = this.nodes ?? {};
    const statements = [];
    for (const node of Object.values(nodes)) {
      statements.push(
        this.env.DB.prepare(
          "UPDATE nodes SET last_seen = ?, candidates = ? WHERE network_id = ? AND node_id = ?",
        ).bind(node.last_seen, JSON.stringify(node.candidates), this.networkId, node.node_id),
      );
    }
    if (statements.length > 0) {
      await this.env.DB.batch(statements);
    }
    await this.state.storage.setAlarm(Date.now() + FLUSH_INTERVAL_MS);
  }

  async upsertD1(node) {
    await this.env.DB.prepare(
      `INSERT INTO nodes (network_id, node_id, name, pubkey, tls_fp, virtual_ip, nat_type, advertise, candidates, last_seen, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(network_id, node_id) DO UPDATE SET
         name = excluded.name,
         pubkey = excluded.pubkey,
         tls_fp = excluded.tls_fp,
         virtual_ip = excluded.virtual_ip,
         nat_type = excluded.nat_type,
         advertise = excluded.advertise,
         candidates = excluded.candidates,
         last_seen = excluded.last_seen`,
    )
      .bind(
        this.networkId,
        node.node_id,
        node.name,
        node.pubkey,
        node.tls_fp,
        node.virtual_ip,
        node.nat_type,
        JSON.stringify(node.advertise),
        JSON.stringify(node.candidates),
        node.last_seen,
        Date.now(),
      )
      .run();
  }

  async assignIp(nodeId, nodes) {
    const [first, second] = (this.cidr ?? "10.64.0.0/16").split(".");
    const used = new Set(Object.values(nodes).map((n) => n.virtual_ip));
    for (let salt = 0; salt < 32; salt += 1) {
      const digest = await sha256Hex(`${nodeId}:${salt}`);
      const third = parseInt(digest.slice(0, 2), 16);
      const fourth = (parseInt(digest.slice(2, 4), 16) % 254) + 1;
      const ip = `${first ?? 10}.${second ?? 64}.${third}.${fourth}`;
      if (!used.has(ip)) return ip;
    }
    return `${first ?? 10}.${second ?? 64}.255.${(Object.keys(nodes).length % 254) + 1}`;
  }
}

function publicNode(node) {
  return {
    node_id: node.node_id,
    name: node.name,
    virtual_ip: node.virtual_ip,
    nat_type: node.nat_type,
    last_seen: node.last_seen,
    online: Date.now() - node.last_seen <= OFFLINE_MS,
    candidates: node.candidates,
  };
}
