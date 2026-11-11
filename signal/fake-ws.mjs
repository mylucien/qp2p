// 本地的 WebSocketPair 替身：让 NetworkRoom 的握手/消息/关闭逻辑能在 node 里跑。
//
// 真机语义：pair[0] 交给客户端，pair[1] 留在 DO。服务端往 pair[1] 发，客户端收；
// 客户端往 pair[0] 发，服务端收。这里用互相指向的 peer 复现这一对。
//
// 自动应答（ping→pong）本地不真跑：`RoomFakeState.getWebSocketAutoResponseTimestamp`
// 直接返回 `socket._autoAt`，测试自己改这个值来模拟"时间戳在推进"。
// 真机是否真的推进属于 V9，只能上真机验。

export class FakeSocket {
  constructor() {
    this.recv = []; // 我收到的消息（字符串）
    this.sent = []; // 我发出的消息（字符串）
    this.closed = null;
    this.accepted = false;
    this.attachment = null;
    this.peer = null;
    this._autoAt = null;
    this._state = null;
    this._tags = [];
  }

  send(data) {
    const text = typeof data === "string" ? data : String(data);
    this.sent.push(text);
    if (this.peer) this.peer.recv.push(text);
  }

  close(code, reason = "") {
    // 已经关过的连接再关一次，真机会抛异常；这里同样不覆盖第一次的结果
    if (this.closed) return;
    this.closed = { code, reason };
    // 真机上服务端 close 会让另一端收到关闭帧；替身里同步一份，测试才能从 client 侧断言
    if (this.peer && !this.peer.closed) this.peer.closed = { code, reason, fromPeer: true };
    this._state?.dropSocket(this);
  }

  accept() {
    this.accepted = true;
  }

  serializeAttachment(value) {
    this.attachment = value;
  }

  deserializeAttachment() {
    return this.attachment;
  }

  /** 测试用：读走我收到的最新一条并解析。 */
  last() {
    const raw = this.recv[this.recv.length - 1];
    return raw ? JSON.parse(raw) : null;
  }

  /** 测试用：取出所有收到的、按 t 过滤过的消息体。 */
  of(type) {
    return this.recv
      .map((raw) => {
        try {
          return JSON.parse(raw);
        } catch {
          return null;
        }
      })
      .filter((m) => m && m.t === type);
  }

  /** 测试用：清空收件箱，方便断言"这一步之后又多收到了什么"。 */
  clear() {
    this.recv.length = 0;
  }
}

/** 一对互相连通的 socket。 */
export function makePair() {
  const client = new FakeSocket();
  const server = new FakeSocket();
  client.peer = server;
  server.peer = client;
  return { client, server };
}

/**
 * 安装全局 WebSocketPair。
 *
 * 只影响本地进程，真机的 pair 由运行时提供。返回卸载函数，测试结束可以还原。
 */
export function installWebSocketPair() {
  const prev = globalThis.WebSocketPair;
  globalThis.WebSocketPair = class WebSocketPair {
    constructor() {
      const { client, server } = makePair();
      this[0] = client;
      this[1] = server;
    }
  };
  return () => {
    if (prev === undefined) delete globalThis.WebSocketPair;
    else globalThis.WebSocketPair = prev;
  };
}

