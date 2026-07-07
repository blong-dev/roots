-- roots migration 0003 — the read path: grants + api keys + access outcome.
--
-- The consent model (owner's explicit decision 2026-07-06): per-read ENFORCEMENT
-- against standing, scoped, REVOCABLE grants — not session-scoped implicit trust.
-- A consumer never "captures a session and grinds everything out": every read is
-- authorized against a live grant and logged, so revocation lands on the very
-- next read and every access (allowed OR denied) is visible to the owner.

-- ------------------------------------------------------------------ grants
-- One row = one standing permission the OWNER issued to a consumer. Append-only:
-- a grant is revoked by stamping revoked_at, never deleted (audit trail intact).
-- data_type NULL = all-types (discouraged; the read still names a type + logs it).
CREATE TABLE grants (
  id          TEXT PRIMARY KEY,
  wallet_id   TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  reader      TEXT NOT NULL,                          -- consuming service (api-key identity)
  data_type   TEXT,                                   -- dt.* scope; NULL = all types
  purpose     TEXT NOT NULL,                          -- declared purpose, matched on every read
  granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at  TEXT,                                   -- NULL = live; set = revoked
  granted_by  TEXT                                    -- who authorized (the holder / interim operator)
);
CREATE INDEX idx_grants_lookup ON grants(wallet_id, reader, revoked_at);

-- ------------------------------------------------------------------ access_log outcome
-- access_log (migration 0001) logs every read; record whether it was allowed or
-- DENIED so the owner sees attempted access, not just successful reads.
ALTER TABLE access_log ADD COLUMN outcome TEXT NOT NULL DEFAULT 'allowed'
  CHECK (outcome IN ('allowed','denied'));

-- ------------------------------------------------------------------ api_keys
-- Consumer auth. Lifted verbatim from Telekora 0022 (FK to tenants dropped —
-- roots has none). tenant_id is kept as the opaque consumer/reader identity;
-- the semantic rename lands in the routes-remap migration.
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,              -- opaque consumer/reader id (-> `reader` on grants)
  name TEXT,
  key_prefix TEXT NOT NULL,            -- display id, e.g. tk_ALoq1rk (never secret)
  key_hash TEXT NOT NULL UNIQUE,       -- SHA-256 hex of the full key; plaintext never stored
  scopes TEXT NOT NULL DEFAULT '',     -- CSV: credentials:verify,credentials:read,…
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
