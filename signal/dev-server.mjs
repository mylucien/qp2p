/**
 * 本地跑信令 Worker：把 worker.js 的 fetch handler 挂到一个真 HTTP 服务上。
 *
 *   ADMIN_SECRET=dev node signal/dev-server.mjs        # 默认 127.0.0.1:8787
 *   ADMIN_SECRET=dev node signal/dev-server.mjs 9000
 *
 * 之后就可以用 curl 或 `node signal/smoke.mjs --remote http://127.0.0.1:8787` 打它。
 * 存储：D1 与 Durable Object 都用 Node 内置 SQLite 冒充，重启即清空。
 * 注意：WebSocket 升级在这条 Node HTTP 链路上不可用（要用 wrangler dev 验），
 * 这里只适合验 HTTP 接口与管理面。
 */

import { createServer } from "node:http";

import worker from "./worker.js";
import { fakeD1 } from "./fake-d1.mjs";
import { fakeRoomBinding } from "./fake-room.mjs";

const port = Number(process.argv[2] ?? 8787);
// 数据面在 Durable Object 里：本地用 SQLite 替身顶替 ROOM，
// 这样 dev-server 跑的是和线上同一套代码路径（legacy 引擎已退役）。
const env = { ADMIN_SECRET: process.env.ADMIN_SECRET ?? "dev", DB: fakeD1() };
env.ROOM = fakeRoomBinding(env);
const ctx = { waitUntil: () => {} };

if (!process.env.ADMIN_SECRET) {
  console.warn("未设置 ADMIN_SECRET，使用默认值 dev");
}

const server = createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);

  // 有些客户端在走代理时会用绝对形式（http://host/path）发请求，
  // 直连时则是 /path。两种都接住，别让调试服务自己 500。
  const raw = req.url ?? "/";
  const url = raw.startsWith("http")
    ? raw
    : `http://${req.headers.host ?? `127.0.0.1:${port}`}${raw}`;
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
