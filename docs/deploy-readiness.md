# roots — deploy readiness

Status as of the pre-deploy security audit. roots is **not yet deployed**
(`wrangler.toml` still has `database_id = TODO`). This is the checklist + the
known-posture record for when we go live.

## Pre-deploy prerequisites (blocking)

1. **Create the D1 database** and paste its id into `wrangler.toml`:
   `wrangler d1 create roots` → copy `database_id`.
2. **Apply all migrations** to the remote DB (0001–0007), in order.
3. **Provision secrets:**
   - `ROOTS_KEK` — 32 random bytes, base64, in **Secrets Store** (not a plain
     var). Wraps every private key AND every per-wallet data key. *If this is
     ever lost, all encrypted payloads and signing keys are unrecoverable.* Back
     it up out-of-band.
   - `ROOTS_OPS_TOKEN` — `wrangler secret put` (≥24 chars, random). Owner
     break-glass for holder routes; not per-user.
   - `ROOTS_DELEGATION_ISSUERS` — CSV of DIDs allowed to vouch for holders
     (Telekora's issuer DID). **Unset = deny-all delegation** (fail-closed).
4. **DID resolution routing — easy to miss.** Wallet + issuer DIDs are
   `did:web:dreamtree.org:...`. For them to resolve *externally* (so exported
   proofs and issued credentials verify off-box), `https://dreamtree.org/w/<id>/did.json`
   and `https://dreamtree.org/tenants/<t>/did.json` must reach this worker. Either
   deploy/route the worker under `dreamtree.org`, or change `DID_WEB_DOMAIN`
   (`src/credentials/keys.ts`) to the actual served domain. Until then, external
   resolution fails (internal verification via the DB still works).

## Audit outcome (fixed before deploy)

Full pass on 2026-07-06. Cryptography is real (AES-GCM w/ random IV, Ed25519,
SHA-256, real eddsa-jcs-2022 — proofs re-verified with an independent verifier).
Every route is auth-gated; DID docs are intentionally public. SSRF-guarded egress;
no secret leakage; parameterized SQL. Fixed in the audit:

- **Write authorization** — writes now require a read/write **grant capability**
  (was: any import-scoped key could write any wallet). Contributors scale as
  revocable grant rows; creating consumer auto-granted at wallet creation.
- **Encryption at rest** — record payloads AES-GCM sealed under a per-wallet data
  key wrapped by `ROOTS_KEK`; a D1 dump without the KEK is opaque.
- **Delegation replay** — delegations are single-use (`jti` consumed in D1).
- `POST /wallets` concurrency race (orphan wallet); stale `TELEKORA_KEK` wording;
  export's stale `grants.reader` column.

## Known v0 posture (deferred, non-blocking — revisit as noted)

- **No app-level rate limiting.** Add Cloudflare WAF / rate-limit rules before
  meaningful traffic, especially: `verify_credential` and credential import (they
  make outbound `safeFetch` calls), and `POST /wallets` (creates rows + keys).
- **No explicit request-body size caps** — relies on the Workers platform limit.
  Add caps on record payload size if abuse appears.
- **DNS-rebinding SSRF** is mitigated only by Workers egress (can't reach the
  origin's private network). The app-layer guard blocks literal private IPs +
  known metadata hosts, not a hostname that resolves to a private IP. Fine on
  Workers; would need resolve-then-check if ever run elsewhere.
- ~~Encryption is all-or-nothing~~ **RESOLVED (P2 / DT-3):** encryption is now
  selective by the registry's PII class — non-PII types clear + queryable at rest,
  PII/credential types sealed. Field-level encryption inside partial-PII payloads
  is the remaining v1 refinement.
- **did:webvh is v0** — DIDs resolve as `did:web` now; `did.jsonl` is a single
  signed inception entry. Full webvh SCID / entry-hash chain verification is later
  hardening.
- **`status.ts` is unwired** (status-list *issuance*). Kept as foundation for when
  roots issues revocable credentials; roots already *consumes* external status
  lists. Not dead-on-purpose — decided to keep.
- **Delegation trust is transitive to the allowlisted issuer.** roots trusts
  `ROOTS_DELEGATION_ISSUERS` to vouch for holders (Telekora during dual-run). This
  is the intended model; scope it tightly.
