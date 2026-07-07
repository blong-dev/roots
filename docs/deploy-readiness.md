# roots — deploy readiness

Status as of the pre-deploy security audit. roots is **not yet deployed**
(`wrangler.toml` still has `database_id = TODO`). This is the checklist + the
known-posture record for when we go live.

## Deploy runbook

Order matters. Steps marked **[dashboard]** need Cloudflare account/DNS actions;
the rest are CLI.

1. **DNS / zone [dashboard].** `dreamtree.org` must be a zone on this Cloudflare
   account, with an `id` record. The worker binds `id.dreamtree.org` as a custom
   domain (`wrangler.toml`); DIDs are `did:web:id.dreamtree.org:...` and resolve
   here (`/w/:id/did.json`, `/tenants/:t/did.json`). This is the permanent DID
   anchor — every minted DID carries it forever.
2. **Create D1:** `wrangler d1 create roots` → paste `database_id` into
   `wrangler.toml`.
3. **Provision the KEK [dashboard/CLI]:** create `ROOTS_KEK` (32 random bytes,
   base64) in the account **Secrets Store** (store id already in `wrangler.toml`).
   **BACK IT UP out-of-band before anything writes** — losing it makes all keys +
   encrypted payloads unrecoverable. (Compromise, not loss, is handled by
   `POST /admin/kek/rotate` + `ROOTS_KEK_NEXT`.)
4. **Provision plain secrets:** `wrangler secret put ROOTS_OPS_TOKEN` (≥24 random
   chars) and `ROOTS_DELEGATION_ISSUERS` (Telekora's issuer DID; unset =
   deny-all delegation, fail-closed).
5. **Apply migrations** to the remote DB (0001–0008), in order.
6. **mTLS second factor [dashboard]:** configure Cloudflare **API Shield mTLS** on
   `id.dreamtree.org` — upload the client-cert CA (or Telekora's cert), enforce
   client certs. Then `wrangler secret put ROOTS_REQUIRE_MTLS` (any non-empty) and,
   optionally, `ROOTS_MTLS_FINGERPRINTS` to pin specific consumers. This makes a
   leaked API key useless on its own. Public routes (DID docs, health, data-types)
   stay open; only authenticated routes require the cert.
7. **Rate limiting [dashboard]:** add Cloudflare WAF / rate-limit rules —
   especially credential-verify + import (outbound `safeFetch`) and `POST /wallets`.
8. **Deploy:** `wrangler deploy`. Smoke-test `GET /health`, a DID doc, `/data-types`.

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
