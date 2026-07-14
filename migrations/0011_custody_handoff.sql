-- roots migration 0011 — custody handoff (the holder takes their own key).
--
-- V0 wallets are fully server-custodied: the receiver Ed25519 private key is
-- KEK-wrapped server-side and roots signs the did.jsonl inception with it. The
-- handoff moves signing authority to a key the HOLDER generated client-side:
-- roots appends a chained did:webvh log entry that rotates the DID's updateKeys
-- to the holder key, marks the wallet self-custodied, and disables (but retains)
-- the server key. Append-only throughout — nothing is hard-deleted, so a botched
-- handoff can be reasoned about and, if ever needed, rolled forward.

-- server = roots holds the signing key; self = the holder's key is authoritative.
ALTER TABLE wallets ADD COLUMN custody_state TEXT NOT NULL DEFAULT 'server'
  CHECK (custody_state IN ('server','self'));

-- The holder's own public key (Multikey), captured at handoff so BOTH resolution
-- surfaces agree: the did:webvh log rotates authority to it, and the did:web
-- document (did.json) also serves it once custody is self (never the retired
-- server key).
ALTER TABLE wallets ADD COLUMN holder_multikey TEXT;

-- The server-custodied receiver key is RETAINED (append-only) but disabled once
-- handed off: after handoff the server must not sign NEW material for the wallet.
-- retired_at set = disabled. The historical inception signature stays valid.
ALTER TABLE receiver_keys ADD COLUMN retired_at TEXT;

-- Appended did:webvh log entries (version >= 2). The inception (version 1) is
-- regenerated deterministically from the wallet's receiver key + created_at; every
-- later entry (e.g. the custody rotation) is a holder-key-dependent, non-
-- deterministic entry and so is PERSISTED here, chained by versionId.
CREATE TABLE did_log (
  wallet_id   TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  version     INTEGER NOT NULL,          -- 2, 3, … (1 is the regenerated inception)
  entry_json  TEXT NOT NULL,             -- the full signed did:webvh JSONL entry
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (wallet_id, version)
);
