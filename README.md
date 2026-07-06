# roots

the user-owned wallet on the **dreamtree** protocol — a standalone Cloudflare Workers + D1
service that holds your credentials and the record of who you are, anchored to a portable
`did:webvh` identity, and lets you take all of it with you.

lowercase, always: **dreamtree** (the network) · **roots** (the wallet).

**status: scaffolding.** the design sketch is in [`docs/roots.md`](docs/roots.md). Much of the
cryptographic credential engine is being lifted from Telekora (VC Phases 0–3, already built and
proven) — see the sketch's lift-out map. Sequencing is dual-run → staged extract: roots stands up
*alongside* Telekora with zero risk to the paying product, then Telekora is cut over behind a flag.

## stack

Cloudflare Workers + a dedicated D1 database, Hono, Ed25519 (WebCrypto). AGPL-3.0.

## layout

- `src/credentials/` — the cryptographic engine (di, resolve, verify-external, status, keys) — lifted from Telekora
- `src/routes/` — the HTTP surface (wallets, records, credentials, issuers, export, mcp)
- `migrations/` — D1 schema (`0001_init.sql` = wallets / records / issuers / record_events / access_log)
- `docs/roots.md` — the build sketch
