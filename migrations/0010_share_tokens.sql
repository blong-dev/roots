-- roots migration 0010 — share tokens (share-and-verify S1, docs/share-and-verify.md).
--
-- A share token is a holder-minted, revocable, expiring capability to view ONE
-- record either as a validity verdict (never the content) or, later (S2), as a
-- grant-gated read. Consumption is public (the /s/{token} page) and every open
-- is written to the wallet's access log.
CREATE TABLE share_tokens (
  token       TEXT PRIMARY KEY,                 -- 128-bit random, base58/hex — the URL segment
  wallet_id   TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  mode        TEXT NOT NULL DEFAULT 'validity'
                CHECK (mode IN ('validity','read')),
  created_by  TEXT NOT NULL,                    -- holder id from the minting delegation (audit)
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL,                    -- required; default 7d, max 90d (enforced in code)
  max_uses    INTEGER,                          -- NULL = unlimited while unexpired
  use_count   INTEGER NOT NULL DEFAULT 0,
  revoked_at  TEXT                              -- holder-revocable; lands on next open
);
CREATE INDEX idx_share_tokens_wallet ON share_tokens(wallet_id, created_at);
