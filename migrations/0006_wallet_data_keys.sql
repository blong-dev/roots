-- roots migration 0006 — per-wallet data keys for encryption at rest.
--
-- Each wallet gets a random AES-256 data key, wrapped under ROOTS_KEK (which
-- lives in Secrets Store, NOT in D1). Record payloads are AES-GCM sealed under
-- the wallet's data key, so a D1 dump alone (without the KEK) reveals nothing.
-- Reads/exports unwrap the data key and decrypt for authorized parties — this is
-- hosted custody (server-readable during a session), so it defends the database
-- at rest, not the authorized-consumer path (that is what grants are for).
CREATE TABLE wallet_data_keys (
  wallet_id  TEXT PRIMARY KEY REFERENCES wallets(id) ON DELETE CASCADE,
  enc_key    TEXT NOT NULL,   -- base64 AES-GCM ciphertext of the base64 data key, under ROOTS_KEK
  iv         TEXT NOT NULL,   -- base64 IV for the wrap
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
