# roots — the wallet (build sketch)

*Sketch started 2026-07-06. The buildable shape of **roots**, the standalone user-owned
wallet on the **dreamtree** protocol. Supersedes the framing in [`wallet-v0.md`](./wallet-v0.md)
with today's reality: the credential engine roots needs **already exists** — it was built inside
Telekora over 2026-07-06 (VC Phases 0–3, GNS-837/839/841/845/847/851). roots is mostly a
**lift-and-generalize**, not a greenfield build.*

*Names are lowercase: **dreamtree** (chain/protocol/network), **roots** (the wallet). Reads with
`wallet-v0.md`, `wallet-spec.md`, `data-types.md`, `credential-profile.md`, `data-model.md`.*

---

## 1. What roots is

A standalone **Cloudflare Workers + a dedicated D1** service — the user-owned wallet — consumed
over HTTP. Telekora is its first and (for v0) only consumer; dreamtree.org, Cosmo, and
HometownWire slot in later on equal terms. roots holds **typed records** (skills, stories,
values) and **credentials** (issued + imported), anchored to a **did:webvh** identity, with
**hosted custody by default**, an append-only correction model, and a full **export** for
sovereignty. It is a *view* of the `data-model.md` atom substrate; the chain (**dreamtree**) is a
later serialization it does not need at v0 (`protocol-spec.md`: v0 = "over-engineered database").

## Repos & sequencing (decided 2026-07-06)

**Two repos under `quorum/dreamtree/`** — which becomes a plain container, *not* itself a repo:
- `quorum/dreamtree/roots/` — **roots**, the wallet service. **NEW repo** (`blong-dev/roots`). Where the
  lifted credential engine + the identity/records/export layer lives.
- `quorum/dreamtree/dreamtree/` — **dreamtree**, the protocol/chain + substrate + brand. The **existing**
  `blong-dev/dreamtree` repo, relocated one level down so it sits beside roots.

**Sequencing: dual-run, then staged extract** (protects the live paying product):
1. **Dual-run** — stand roots up *alongside* Telekora; Telekora's working credential system is untouched.
   roots proves the moved engine + the new identity/records/export layer against acceptance, zero revenue risk.
2. **Staged extract** — cut Telekora over progressively, behind a flag, migration reversible: reads first,
   then writes (completion → credential issued into roots), then retire Telekora's local store. Each stage
   independently revertible; the **custody handoff is the last stage.**

## 2. The lift-out map — most of this is already built

The hard part (the cryptographic credential engine) is done and battle-tested in Telekora. roots
is where it belongs. What moves, what generalizes, what's genuinely new:

| Capability | Where it is now (Telekora) | roots disposition |
|---|---|---|
| eddsa-jcs-2022 Data Integrity proofs | `credentials/di.ts` | **move** verbatim |
| External issuer resolution (did:web/webvh/jwks) + SSRF guard | `credentials/resolve.ts` | **move** verbatim |
| 4-format verifier + honest tiers + OB alignment capture | `credentials/verify-external.ts` | **move** verbatim |
| Bitstring status list (revocation + suspension) | `credentials/status.ts` | **move** verbatim |
| OB 3.0 AchievementCredential issuance | `credentials/achievement.ts` | **move** (becomes an *issuer* calling roots) |
| Ed25519 keys, did:web, issuer/receiver keystore | `credentials/{keys,keystore}.ts` | **move** + extend to did:webvh |
| `wallet_records` (imported creds, tiers, state, alignment) | migrations 0021/0023/0024 | **generalize** → `records` (all data_types) |
| `wallet_issuers` trust registry | migration 0021 | **move** → `issuers` |
| Append-only retract/reinstate/history | migration 0023, `routes/wallet.ts` | **move** verbatim |
| Scoped API keys + operator token + MCP | `apikeys.ts`, `routes/{keys,mcp}.ts` | **move** (roots' programmatic surface) |
| Public trust surfaces (did.json, status, contexts) | `routes/wellknown.ts` | **move** + add did:webvh |
| **Typed record ontology (skills/stories/values/…)** | — (Telekora only has creds) | **NEW** — the `data_type` registry (`data-types.md`) |
| **did:webvh identity anchor + verification tier** | — | **NEW** — the human-as-key layer |
| **Hosted-custody encryption (PBKDF2→wrap→AES-GCM)** | — (Telekora has KEK for issuer keys) | **NEW** — per-wallet PII encryption |
| **Export API** | — | **NEW** — the sovereignty payoff |
| **Receiver-key custody handoff** | `receiver_keys.source` exists, stub | **NEW** — the "truly held" moment (`dtw-handoff.md`) |

So: ~60% is a repo move; the new work is **identity + typed records + encryption + export + handoff**.

## 3. Schema (D1)

Generalizes Telekora's credential-only `wallet_records` into a full typed-record store.

```sql
-- The wallet anchor. wallet_id is the durable id; did:webvh is the portable identity.
CREATE TABLE wallets (
  id                TEXT PRIMARY KEY,          -- wallet_id (nanoid) — durable anchor
  did               TEXT UNIQUE,               -- did:webvh:dreamtree.org:w:<id> (nullable until minted)
  verification_tier TEXT NOT NULL DEFAULT 'unverified',  -- DERIVED from a valid proof_of_personhood record
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE wallet_identities (               -- IdP attachments (Google now, more later)
  wallet_id    TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  provider     TEXT NOT NULL, provider_uid TEXT NOT NULL,
  PRIMARY KEY (provider, provider_uid)
);

-- THE core store. One typed record = one thing the wallet holds. Subsumes creds + self-data.
CREATE TABLE records (
  id           TEXT PRIMARY KEY,
  wallet_id    TEXT NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  data_type    TEXT NOT NULL,                  -- dt.* key (data-types.md); validated at write
  payload      TEXT NOT NULL,                  -- JSON, or {v,iv,ciphertext} envelope if encrypted
  encrypted    INTEGER NOT NULL DEFAULT 0,     -- derived from the data_type's PII class
  source_type  TEXT NOT NULL,                  -- 'self' | 'tool' | 'issued' | 'imported'
  source_ref   TEXT,                           -- provenance (tool_id / import id / issuer op)
  issuer_id    TEXT REFERENCES issuers(id),    -- set for issued/imported credentials
  signature    TEXT,                           -- issuer proofValue (parsed out for indexing)
  alignment_json TEXT,                          -- issuer-asserted framework alignment (taxonomy seed)
  state        TEXT NOT NULL DEFAULT 'active',  -- active | retracted (append-only correction)
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_records_wallet_type ON records(wallet_id, data_type);

CREATE TABLE record_events (                   -- the immutable audit chain (imported|retracted|reinstated|issued)
  id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
  event TEXT NOT NULL, reason TEXT, actor TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE issuers (                          -- trust registry (= Telekora wallet_issuers)
  id TEXT PRIMARY KEY, did_or_iss TEXT UNIQUE NOT NULL, name TEXT, method TEXT,
  status TEXT NOT NULL DEFAULT 'known',         -- trusted | known | revoked
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE access_log (                        -- consent/audit: every consumer read
  id TEXT PRIMARY KEY, wallet_id TEXT NOT NULL, reader TEXT NOT NULL,
  data_type TEXT, purpose TEXT NOT NULL, at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- plus (moved from Telekora): keys (issuer/receiver, did:webvh), status_counters/credential_status,
-- api_keys. data_type registry loads from data-types.json at boot.
```

**Verification tier is a reading, not a column** (data-model principle): for credential records,
the tier (verified / valid-signature / self-reported) is computed on read over the stored VC +
`issuers`, via the moved `verify-external.ts`. Telekora cached it for query; roots may cache too,
but the source of truth is the recomputation.

## 4. Identity & custody

- **did:webvh** (`wallet-spec.md` L1 Q1). roots hosts the DID document + append-only *signed
  history log* under dreamtree.org — tamper-evidence without a chain, and **portable** (export the
  log + keys, re-host anywhere, DID unchanged). Served at `/w/:id/did.jsonl`.
- **human-as-key** (`wallet-v0.md` §1). The human is the identity; the key is a replaceable
  attachment. `verification_tier` is **derived** from holding a valid `dt.identity.proof_of_personhood@1`
  record signed by a registered KYC-provider issuer. No new machinery — a KYC provider is just a
  high-trust issuer.
- **Hosted custody, forever, opt-out to self/third-party** (`wallet-spec.md` L2 Q5). PBKDF2/Argon2 →
  wrapping key → AES-GCM per-wallet data key; server-decryptable *during an active session* only,
  blind when logged out. **No invented recovery** (no seed phrases, no social recovery — soft-tyranny
  failure mode). Recovery = re-prove you're the same human (KYC re-attestation).

## 5. API surface

Grounded in `wallet-v0.md` §4–5; the credential routes already exist in Telekora and move over.

- **Identity:** `POST /wallets` (create + bind IdP; the silent-wallet entry) · `GET /w/:id/did.jsonl`
  (did:webvh history) · `GET /w/:id/did.json`.
- **Records:** `POST /w/:id/records` (self/tool data, typed, validated) · `GET /w/:id/records`
  (consent-gated read, logs to `access_log`) · retract / reinstate / history (moved verbatim).
- **Credentials:** `POST /w/:id/credentials` (an issuer writes a VC into the wallet) ·
  `GET /credentials/:id/verify` (the moved verifier) · import (moved).
- **Export (sovereignty):** `GET /w/:id/export` — full decrypt + signed bundle; the user leaves with
  everything intact.
- **Issuers:** `GET/POST /issuers` (registry, moved).
- **Auth:** scoped API keys + operator token + MCP (moved); plus per-wallet *holder* auth (the human
  reads/exports their own wallet).

## 6. How Telekora becomes a client (the extraction)

The move that makes roots the moat rather than a feature trapped in one app:

1. Telekora stops storing `wallet_records`/`learner_data` locally; it calls roots over HTTP.
2. **Silent wallet:** every Telekora signup → `POST /wallets` (bind Google). The learner is a roots
   instance from day zero, whether they know it or not.
3. Course completion → `POST /w/:id/credentials` with Telekora's tenant as the signing **issuer**
   (Telekora becomes an issuer *to* roots, not a wallet itself). `achievement.ts` runs Telekora-side.
4. Verify / import / hold / retract all resolve against roots.
5. **Custody handoff** (`dtw-handoff.md`): when a wallet is claimed, Telekora flips
   `receiver_keys.source` `server → roots`, deletes its copy; roots signs receiver proofs thereafter;
   past credentials verify under the archived old key. **This is the visible payoff — "your credentials
   are truly yours."**

## 7. Build order

1. **Stand up the service** — new Workers project + dedicated D1; move `credentials/*`, `apikeys.ts`,
   the wallet/keys/mcp routes; tables `wallets`/`records`/`issuers`/`record_events`/`access_log`. Prove
   the moved verifier passes its acceptance in the new home.
2. **Generalize the record model** — `records` + the `data_type` registry (`data-types.json`); accept
   self/tool records, not just credentials; derive `encrypted` from PII class.
3. **Identity + custody** — did:webvh mint + history log; verification tier from proof-of-personhood;
   per-wallet PBKDF2→AES-GCM encryption; export API.
4. **Point Telekora at roots** — silent wallet on signup; completion → credential to roots; migrate
   Telekora's existing wallet data over; Telekora becomes a client + issuer.
5. **Custody handoff** — the receiver-key migration; the "truly held" moment.

## 8. Deferred / open

- **The dreamtree chain** — network, photons/seeds, marketplace, attestation-as-work consensus. A
  later serialization; roots needs none of it at v0 (settled: chain is downstream of the substrate).
- **Selective disclosure** (SD-JWT VC / BBS+), **OID4VCI/VP** exchange rails — reserved, not precluded.
- **did:webvh full history-chain verification** — v0 resolves latest + flags history-unverified.
- **dreamtree-app (workbook) migration onto roots** — v0 leaves it dual-running; Telekora is the only
  consumer.
- **Open decisions** carried from `wallet-spec.md`: cross-IdP merging (L1 Q4), smart-content read
  surface / encryption boundary (L2 Q6/Q7), PDS sync, the public SDK shape.

---

*Bottom line: roots is closer than it looks. The cryptographic core is written and proven; the build
is a repo lift + the identity/records/export/handoff layer on top. That's the moat, and it's weeks of
work, not a rebuild.*
