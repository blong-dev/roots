-- roots migration 0005 — unify grants into a read/write capability model.
--
-- A wallet has MANY contributors (Telekora, a KYC provider, HometownWire, …), not
-- one owner. So write authorization uses the SAME consent primitive as reads: a
-- grant now carries a `capability` (read | write). The holder authorizes which
-- parties may CONTRIBUTE to their wallet exactly as they authorize who may READ;
-- every contributor is an independently-revocable, audited grant row. The
-- creating consumer gets an automatic write-grant at wallet creation.
--
-- `reader` → `grantee` (a grant is for a party, not just a reader). `purpose` is
-- now nullable (required for reads, unused for writes). grants is empty (roots
-- undeployed) so a drop + recreate is safe.
DROP INDEX IF EXISTS idx_grants_lookup;
DROP TABLE grants;
CREATE TABLE grants (
  id          TEXT PRIMARY KEY,
  wallet_id   TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  grantee     TEXT NOT NULL,                              -- the party granted the capability (consumer identity)
  capability  TEXT NOT NULL DEFAULT 'read' CHECK (capability IN ('read','write')),
  data_type   TEXT,                                       -- scope; NULL = all types
  purpose     TEXT,                                       -- required for reads; NULL for writes
  granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at  TEXT,                                       -- NULL = live; set = revoked
  granted_by  TEXT                                        -- the holder (or 'system:creation')
);
CREATE INDEX idx_grants_lookup ON grants(wallet_id, grantee, capability, revoked_at);
