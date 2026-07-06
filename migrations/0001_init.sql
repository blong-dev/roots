-- 0001_init — roots wallet core schema.
-- Generalizes Telekora's credential-only wallet store into a full typed-record wallet.
-- See docs/roots.md §3. Names/brand lowercase: dreamtree (network), roots (wallet).

-- The wallet anchor. `id` is the durable internal id; `did` is the portable did:webvh identity.
CREATE TABLE wallets (
  id                TEXT PRIMARY KEY,                       -- wallet_id (nanoid)
  did               TEXT UNIQUE,                            -- did:webvh:dreamtree.org:w:<id> (nullable until minted)
  verification_tier TEXT NOT NULL DEFAULT 'unverified'      -- DERIVED from a valid proof_of_personhood record
                      CHECK (verification_tier IN ('unverified','verified_human')),
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- IdP attachments (Google now; more later). The human is the identity; IdPs are attachments.
CREATE TABLE wallet_identities (
  wallet_id     TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  provider      TEXT NOT NULL,
  provider_uid  TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (provider, provider_uid)
);

-- THE core store. One typed record = one thing the wallet holds. Subsumes creds + self-data.
CREATE TABLE records (
  id             TEXT PRIMARY KEY,
  wallet_id      TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  data_type      TEXT NOT NULL,                             -- dt.* key (data-types.md); validated at write
  payload        TEXT NOT NULL,                             -- JSON, or {v,iv,ciphertext} envelope if encrypted
  encrypted      INTEGER NOT NULL DEFAULT 0,                -- derived from the data_type's PII class
  source_type    TEXT NOT NULL                              -- provenance class
                   CHECK (source_type IN ('self','tool','issued','imported')),
  source_ref     TEXT,                                      -- tool_id / import id / issuer op
  issuer_id      TEXT REFERENCES issuers(id),               -- set for issued/imported credentials
  signature      TEXT,                                      -- issuer proofValue (parsed out for indexing)
  alignment_json TEXT,                                      -- issuer-asserted framework alignment (taxonomy seed)
  state          TEXT NOT NULL DEFAULT 'active'             -- active | retracted (append-only correction)
                   CHECK (state IN ('active','retracted')),
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_records_wallet_type ON records(wallet_id, data_type);
CREATE INDEX idx_records_state ON records(wallet_id, state);

-- The immutable audit chain: every issue / import / retract / reinstate is a row here.
CREATE TABLE record_events (
  id          TEXT PRIMARY KEY,
  record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  event       TEXT NOT NULL CHECK (event IN ('issued','imported','retracted','reinstated')),
  reason      TEXT,
  actor       TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_record_events_record ON record_events(record_id, created_at);

-- Trust registry (= Telekora wallet_issuers). Seeded only with issuers that resolve.
CREATE TABLE issuers (
  id          TEXT PRIMARY KEY,
  did_or_iss  TEXT NOT NULL UNIQUE,
  name        TEXT,
  method      TEXT,                                         -- did:web | did:webvh | did:key | jwks
  status      TEXT NOT NULL DEFAULT 'known'
                CHECK (status IN ('trusted','known','revoked')),
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Consent / audit: every consumer read of wallet contents.
CREATE TABLE access_log (
  id         TEXT PRIMARY KEY,
  wallet_id  TEXT NOT NULL,
  reader     TEXT NOT NULL,                                 -- the consuming service/tenant
  data_type  TEXT,
  purpose    TEXT NOT NULL,                                 -- declared purpose
  at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_access_log_wallet ON access_log(wallet_id, at);

-- NOTE: keys (issuer/receiver, did:webvh), status_counters/credential_status, and api_keys
-- lift over from Telekora in later migrations (roots P1). The data_type registry loads from
-- data-types.json at boot, not the DB.
