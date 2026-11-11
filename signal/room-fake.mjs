/**
 * NetworkRoom 的本地替身：用 node:sqlite 冒充 Durable Object 的 storage.sql。
 *
 * 真机上的 SqlStorage 形状是 `exec(query, ...bindings)`，返回带 `toArray()` /
 * `one()` 的游标；node:sqlite 是 `prepare().all()/run()`。这里只做最小适配，
 * 目的是让 NetworkRoom 的 SQL 在本地能跑，不追求覆盖 SqlStorage 的全部行为。
 */

import { DatabaseSync } from "node:sqlite";

class SqlFake {
  constructor() {
    this.db = new DatabaseSync(":memory:");
  }

  exec(query, ...bindings) {
    const head = query.trimStart().slice(0, 16).toUpperCase();
    const stmt = this.db.prepare(query);

    if (head.startsWith("SELECT") || head.startsWith("PRAGMA") || head.startsWith("WITH")) {
      const rows = stmt.all(...bindings);
      return { toArray: () => rows, one: () => rows[0] ?? null };
    }
    stmt.run(...bindings);
    return { toArray: () => [], one: () => null };
  }
}

/** 假 socket：只需要 NetworkRoom 用到的那几个方法。 */
export function fakeSocket(attachment = {}) {
  return {
    attachment,
    sent: [],
    closeCode: null,
    closeReason: null,
    deserializeAttachment() {
      return this.attachment;
    },
    serializeAttachment(next) {
      this.attachment = next;
    },
    send(data) {
      this.sent.push(data);
    },
    close(code, reason) {
      this.closeCode = code;
      this.closeReason = reason;
    },
  };
}

/** DurableObjectState 的替身。 */
export class RoomFakeState {
  constructor() {
    this.storage = { sql: new SqlFake() };
    this.sockets = [];
    this.autoResponse = null;
    this._pending = [];
  }

  /** 真机上这段会阻塞后续请求；测试里只要等 Promise 完成即可。 */
  blockConcurrencyWhile(fn) {
    const p = Promise.resolve().then(fn);
    this._pending.push(p);
    return p;
  }

  async ready() {
    while (this._pending.length) {
      const batch = this._pending;
      this._pending = [];
      await Promise.all(batch);
    }
  }

  getWebSockets() {
    return this.sockets;
  }

  setWebSocketAutoResponse(pair) {
    this.autoResponse = pair;
  }

  /** 真机的 Hibernation API：登记 socket（可选 tags）。 */
  acceptWebSocket(ws, tags = []) {
    ws._state = this;
    ws._tags = tags;
    ws.accept?.();
    if (!this.sockets.includes(ws)) this.sockets.push(ws);
  }

  /**
   * 自动应答时间戳。真机上由运行时在收到 ping 时刷新；本地没有运行时，
   * 直接读 `socket._autoAt`，由测试自己改它来模拟"时间戳在推进"。
   */
  getWebSocketAutoResponseTimestamp(ws) {
    return ws?._autoAt ? new Date(ws._autoAt) : null;
  }

  /** 连接关闭后要从列表里摘掉，否则 liveness 会一直看到已经断掉的 socket。 */
  dropSocket(ws) {
    this.sockets = this.sockets.filter((s) => s !== ws);
  }
}
