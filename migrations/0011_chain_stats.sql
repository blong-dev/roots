-- roots migration 0011 — the public chain-pulse cache (share-and-verify §3).
-- One row, pushed OUTBOUND from m3 on a timer; the /chain page reads it.
-- No inbound path to m3, no chain RPC exposure, ever.
CREATE TABLE chain_stats (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  stats      TEXT NOT NULL,                -- JSON blob as pushed
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
