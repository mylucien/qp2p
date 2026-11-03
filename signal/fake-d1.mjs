/**
 * 用 Node 内置 SQLite 冒充 Cloudflare D1，接口对齐 prepare/bind/run/first/all。
 * 只用于本地跑通 worker.js，不参与部署。
 */

import { DatabaseSync } from "node:sqlite";

export function fakeD1() {
  const db = new DatabaseSync(":memory:");
  return {
    prepare(sql) {
      const statement = db.prepare(sql);
      let params = [];
      const api = {
        bind: (...args) => {
          params = args.map((a) => (typeof a === "boolean" ? Number(a) : a));
          return api;
        },
        run: () => {
          const result = statement.run(...params);
          return { success: true, meta: { changes: Number(result.changes ?? 0) } };
        },
        first: () => statement.get(...params) ?? null,
        all: () => ({ results: statement.all(...params) }),
      };
      return api;
    },
  };
}
