/**
 * 把 NetworkRoom 包装成 `env.ROOM`，让 smoke.mjs 的整套协议用例能跑在 room 引擎上。
 *
 * 目的：同一套断言对 legacy（D1）与 room（DO）各跑一遍，验证两个引擎的响应形状
 * 和行为一致（设计文档 §14「兼容性矩阵」）。
 */

import { NetworkRoom } from "./worker.js";
import { RoomFakeState } from "./room-fake.mjs";

/**
 * @param sharedEnv 与 Worker 共用的 env 对象。真机上 DO 和 Worker 拿到的是同一份
 *                  绑定配置，测试里也必须共用，否则用例临时改的 env 变量
 *                  （比如 env.STALE_MS）传不进 DO。
 */
export function fakeRoomBinding(sharedEnv = {}) {
  const rooms = new Map();

  const entryOf = (name) => {
    let entry = rooms.get(name);
    if (!entry) {
      const state = new RoomFakeState();
      entry = { state, room: new NetworkRoom(state, sharedEnv) };
      rooms.set(name, entry);
    }
    return entry;
  };

  return {
    idFromName: (name) => ({ name: String(name) }),
    get: (handle) => ({
      fetch: async (request) => {
        const { state, room } = entryOf(handle.name);
        await state.ready();
        return room.fetch(request);
      },
    }),

    /** 测试辅助：直接拿到某个网络对应的 room 实例 */
    roomOf: (name) => entryOf(name).room,
    /** 测试辅助：当前已创建的网络 id 列表 */
    names: () => [...rooms.keys()],
  };
}
