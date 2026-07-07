-- roots migration 0002 — key management + credential status
-- Lifted from Telekora migrations 0010 (issuer_keys/receiver_keys) and 0019
-- (status_counters/credential_status) to back the keystore.ts + status.ts engine.
--
-- MECHANICAL LIFT NOTE: column names are kept verbatim from Telekora so the
-- lifted engine compiles and runs unchanged. The FK REFERENCES to tenants(id)/
-- users(id) are DROPPED — roots has no tenants/users tables. The semantic remap
-- (tenant_id -> issuer scope, user_id -> wallets.id) happens in the routes
-- adaptation migration, not here. keystore.ts/status.ts treat these as opaque
-- string keys, so nothing in the engine changes.

-- ------------------------------------------------------------------ issuer_keys
-- roots-as-issuer signing keys (e.g. signing its own did:webvh history, or
-- wallet-native attestations). Encrypted JWK stored under ROOTS_KEK.
CREATE TABLE issuer_keys (
  tenant_id TEXT PRIMARY KEY,              -- opaque issuer scope key
  did TEXT NOT NULL UNIQUE,                -- did:key:z6Mk…
  public_key_multibase TEXT NOT NULL,
  encrypted_private_jwk TEXT NOT NULL,     -- base64 AES-GCM ciphertext of JSON.stringify(JWK)
  encryption_iv TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------------ receiver_keys
-- per-holder receiver keypair (receiver proof + custody handoff). user_id here
-- maps to wallets.id in the routes remap.
CREATE TABLE receiver_keys (
  user_id TEXT PRIMARY KEY,                -- opaque holder key -> wallets.id
  did TEXT NOT NULL UNIQUE,
  public_key_multibase TEXT NOT NULL,
  encrypted_private_jwk TEXT NOT NULL,
  encryption_iv TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'server',   -- 'server' | 'dtw'
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------------ status_counters
-- next free slot per issuer scope in the Bitstring status lists.
CREATE TABLE status_counters (
  tenant_id TEXT PRIMARY KEY,              -- opaque issuer scope key
  next_index INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------ credential_status
-- One row per issued credential: its slot in the status lists and the two
-- status bits. Lists are generated from these rows on demand.
CREATE TABLE credential_status (
  credential_id TEXT PRIMARY KEY,          -- urn:uuid:<id>
  tenant_id TEXT NOT NULL,                 -- opaque issuer scope key
  status_index INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  suspended INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_credential_status_tenant ON credential_status(tenant_id);
CREATE UNIQUE INDEX idx_credential_status_slot ON credential_status(tenant_id, status_index);
