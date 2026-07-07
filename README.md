# roots

the user-owned wallet on the **dreamtree** network. A standalone service that holds your
credentials and the typed record of what you've done, anchored to a portable identity,
with the whole thing exportable the day you want it.

lowercase, always: **dreamtree** (the network) · **roots** (the wallet).

**status: live.** roots runs in production at [`id.dreamtree.org`](https://id.dreamtree.org),
holding real wallets with real learning history. [Telekora](https://telekora.com) is the first
consumer: every signup silently receives a wallet, every credential Telekora issues lands in it,
and Telekora reads it back through the same consent gate any third party would use.

## what makes it a wallet and not a database

- **Every wallet has a public identity.** `did:web:id.dreamtree.org:w:<id>` resolves for anyone,
  so credentials issued into a wallet verify without asking us.
- **Reads are consent-gated, per read.** A consumer holds a scoped, revocable grant from the
  wallet's owner. Revocation lands on the very next read. Every access, allowed or denied, is
  logged where the owner can see it.
- **A contributor sees only what it contributed.** Cross-party reads take an explicit grant from
  the holder. Write access is a grant too.
- **Verification is a reading, never a stored fact.** Tiers (verified / valid-signature /
  self-reported) are recomputed cryptographically at read time against the live trust registry.
- **Nothing is deleted.** Corrections are append-only retractions with the reason in the audit
  chain. An attester can withdraw its own attestation; only the holder can touch the rest.
- **Sensitive payloads are encrypted at rest**, per-wallet keys wrapped under a master key that
  never lives in the database. PII classification comes from the type registry, not per-record
  judgment calls.
- **You can leave.** `GET /w/:id/export` returns the entire wallet as a signed bundle that
  verifies offline with the key embedded in it.

## stack

Cloudflare Workers + a dedicated D1 database, Hono, Ed25519 (WebCrypto), W3C Verifiable
Credentials 2.0 with `eddsa-jcs-2022` data-integrity proofs. AGPL-3.0.

## layout

- `src/credentials/` — the cryptographic engine (data-integrity proofs, DID resolution,
  the four-format external verifier, key custody)
- `src/routes/` — the HTTP surface (identity, records, credentials, grants, contributions,
  export, MCP for agents)
- `src/data-types.ts` — the `dt.*` type registry (authoritative, fail-closed)
- `migrations/` — D1 schema
- `docs/` — the build sketch, deploy runbook, and the Telekora integration record

## the bigger picture

roots is one layer of the dreamtree design: a data-sovereign wallet whose records are portable
by construction, so nothing you earn is born trapped in the platform that issued it. The design
docs live in the public [dreamtree repo](https://github.com/blong-dev/dreamtree).
