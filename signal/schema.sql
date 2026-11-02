-- qp2p 信令面：只存冷数据。在线状态与候选地址在 Durable Object 里。
CREATE TABLE IF NOT EXISTS networks (
  network_id TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  cidr       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  network_id TEXT NOT NULL,
  node_id    TEXT NOT NULL,
  name       TEXT NOT NULL,
  pubkey     TEXT NOT NULL DEFAULT '',
  tls_fp     TEXT NOT NULL DEFAULT '',
  virtual_ip TEXT NOT NULL,
  nat_type   TEXT NOT NULL DEFAULT 'unknown',
  advertise  TEXT NOT NULL DEFAULT '[]',
  candidates TEXT NOT NULL DEFAULT '[]',
  last_seen  INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (network_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes (network_id, last_seen);
