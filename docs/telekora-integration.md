# DT-5 — wiring Telekora to roots (the staged extract)

**Status: scope, 2026-07-06.** roots' P1 surface + P2 registry are built and audited.
This scopes how Telekora stops being the de-facto wallet and becomes a *client +
issuer* of roots — in reversible stages that never break the live telekora.com
demo. The DTW handoff stub (`telekora/docs/specs/dtw-handoff.md`) is the
predecessor; its "when this gets real" trigger is now met, and this resolves its
TBDs against what roots actually does.

## The one hard constraint

**Never break the live demo.** telekora.com has a running Drake demo. Every stage
is behind a flag, dual-runs (local stays authoritative until proven), and is
reversible by flipping the flag back. Local Telekora storage is the safety net
until the very last stage. (Cf. the union-manifest rule: frontier changes must not
strip the live local path.)

## Prerequisites (before any Telekora code changes)

1. **A running roots.** Telekora's Worker calls roots over HTTP, so roots must be
   deployed — at least to a staging URL (e.g. `roots-staging.<domain>`). Full prod
   deploy prereqs are in `deploy-readiness.md`. *Integration can be built + tested
   Telekora-side against a local roots first (`wrangler dev`), but dual-run needs a
   reachable roots.*
2. **A roots consumer API key for Telekora** (`tk_…`) with scopes
   `wallets:create, credentials:import, credentials:read`. Stored as a Telekora
   secret (`ROOTS_API_KEY`), plus `ROOTS_BASE_URL`.
3. **Delegation trust.** roots verifies holder actions via Telekora-signed
   assertions. Add Telekora's issuer DID to roots' `ROOTS_DELEGATION_ISSUERS`.
   Telekora already serves its did:web doc (`wellknown.ts`), so roots resolves it
   over the network — no new Telekora trust surface.
4. **A Telekora-side delegation signer** — a small helper that mints the
   `{iss, sub=userId, wallet, exp, jti}` JWS with Telekora's issuer key when
   Telekora acts on a user's behalf (grant/retract/export/read-as-holder). This is
   the only genuinely new crypto on the Telekora side, and it reuses the issuer key
   Telekora already has.

## The seams (exact Telekora integration points)

| Telekora today | roots call | roots type |
|---|---|---|
| `routes/auth.ts:115/179` — `INSERT INTO users` at Google login | `POST /wallets {provider:'google', provider_uid}` → store `roots_wallet_id` on the user | wallet create (idempotent) |
| `routes/learn.ts:572` — `INSERT INTO learner_data` (responses) | `POST /w/:id/records` | `dt.response.{quiz,text,poll,assessment}@1` |
| `credentials/achievement.ts` + `learn.ts` — Telekora issues a completion VC | `POST /w/:id/credentials` | `dt.credential.course_completion@1` / `learner_response@1` |
| `routes/wallet.ts:151` — imported external creds (`wallet_records`) | `POST /w/:id/credentials` (imported) | issuer-signed VC |
| `routes/wallet.ts` holdings + smart-content reads | `GET /w/:id/records?data_type=&purpose=` (+ read grant) | consent-gated read |

Telekora stays the **issuer** (its tenant key signs completion VCs; `achievement.ts`
runs Telekora-side). roots stores + serves. Telekora becomes an issuer *to* roots,
not a wallet.

## Staged sequence (each stage flagged + reversible)

- **Stage 0 — silent wallets, no reads.** At signup, `POST /wallets`; persist
  `users.roots_wallet_id`. No behavior change for the user. Reversible: stop
  calling; the column is inert. *(Flag: `ROOTS_CREATE_WALLETS`.)*
- **Stage 1 — shadow write.** On every `learner_data` / credential write, ALSO
  write to roots (best-effort, non-blocking; a roots failure never fails the
  Telekora write). Local stays authoritative. This proves the write path + fills
  roots with live data. Reversible: stop shadowing. *(Flag: `ROOTS_SHADOW_WRITE`.)*
- **Stage 2 — backfill.** One-time idempotent job: for each existing user, create
  their wallet + replay their `learner_data` + `wallet_records` into roots. Safe to
  re-run (roots writes are id-keyed; `POST /wallets` is idempotent per identity).
- **Stage 3 — read flip.** Point holdings + smart-content reads at roots (with the
  first-party read grant, below). Keep local as fallback on a roots error.
  Reversible: flip reads back to local. *(Flag: `ROOTS_READ_THROUGH`.)*
- **Stage 4 — local off.** Stop writing `learner_data`/`wallet_records` locally;
  roots is authoritative. Local tables kept (not dropped) as a cold backup for a
  release. *(Flag: `ROOTS_AUTHORITATIVE`.)*
- **Stage 5 — DT-6 custody handoff.** Separate epic: `receiver_keys.source`
  `server → dtw`, Telekora deletes its private key, roots' wallet key signs
  thereafter. This is the sovereignty moment (`dtw-handoff.md` §4). NOT part of
  DT-5 — DT-5 makes roots the store; DT-6 makes the user the key-holder.

## Open decisions (need a call)

1. **First-party read grant (the important one).** roots' silent-wallet bootstrap
   auto-grants the creating consumer a *write* grant. Reads are consent-gated. Does
   wallet creation ALSO auto-issue Telekora a *read* grant scoped to
   `purpose = personalize_telekora` (revocable, logged)? **Recommend yes:** signing
   up for Telekora *is* consent for Telekora to read your learning data to
   personalize your experience — and it stays revocable + fully in the access log.
   Without it, every smart-content read would need an explicit prompt. (This is the
   one place DT-5 slightly widens the default; call it explicitly.)
2. **Delegation signing key.** Telekora signs holder delegations with its existing
   tenant issuer key, or a dedicated platform delegation key? Recommend the
   existing issuer key (already resolvable via did:web; one fewer key to manage).
3. **Backfill scope.** All historical users, or only active ones? Recommend active
   first (bounded), then a sweep.
4. **Credential re-issue vs rotation marker** (DT-6, noted for continuity):
   accept W3C key-rotation on handoff (no re-issue). Recommend accept.

## Recommended first increment

**Stage 0 + the delegation signer**, built Telekora-side behind
`ROOTS_CREATE_WALLETS` (default off), tested against a local roots. It's the
smallest reversible step, exercises wallet-create + the delegation trust end to
end, and de-risks everything downstream — with zero user-visible change and no
dependency on a prod deploy yet.
