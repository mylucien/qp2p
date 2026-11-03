/**
 * 本地跑信令 Worker：把 worker.js 的 fetch handler 挂到一个真 HTTP 服务上。
 *
 *   ADMIN_SECRET=dev node signal/dev-server.mjs        # 默认 127.0.0.1:8787
 *   ADMIN_SECRET=dev node signal/dev-server.mjs 9000
 *
 * 之后就可以用 curl 或 `node signal/smoke.mjs --remote http://127.0.0.1:8787` 打它。
 * 存储用 Node 内置 SQLite 冒充 D1，重启即清空。
 */

import { createServer } from "node:http";

import worker from "./worker.js";
import { fakeD1 } from "./fake-d1.mjs";

const port = Number(process.argv[2] ?? 8787);
const env = { ADMIN_SECRET: process.env.ADMIN_SECRET ?? "dev", DB: fakeD1() };
const ctx = { waitUntil: () => {} };

if (!process.env.ADMIN_SECRET) {
  console.warn("未设置 ADMIN_SECRET，使用默认值 dev");
}

const server = createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);

  const url = `http://${req.headers.host ?? `127.0.0.1:${port}`}${req.url}`;
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(",") : value);
  }
  headers.set("cf-connecting-ip", req.socket.remoteAddress ?? "127.0.0.1");

  const request = new Request(url, {
    method: req.method,
    headers,
    body: chunks.length > 0 ? Buffer.concat(chunks) : undefined,
  });

  try {
    const response = await worker.fetch(request, env, ctx);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (e) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: String(e) }));
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`qp2p signal 本地服务：http://127.0.0.1:${port}`);
});
