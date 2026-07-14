# Custody handoff — the holder takes their own key

Status: MVP (conservative). Shipped with `feat/roots-dormant-features`.

roots wallets are created **server-custodied**: roots generates the wallet's
Ed25519 receiver key, KEK-wraps the private half, and signs the wallet's DID
history with it. That is hosted custody — convenient, but roots can sign as the
wallet. **Custody handoff** moves signing authority to a key the *holder*
generated on their own device, so roots can no longer produce a valid signature
as the wallet going forward.

This is a security-sensitive design fork; read the trust model below before
relying on it.

## What the handoff does

`POST /w/:id/custody/handoff` (holder-authed via `delegatedHolderAuth`; operator
break-glass allowed), body `{ "public_key_multibase": "z6Mk…" }` where the value
is an Ed25519 **Multikey** the holder generated **client-side** (roots never sees
the private key). On success roots, atomically:

1. **Appends a chained `did:webvh` log entry** (version 2) to the wallet's
   `did.jsonl`. The entry:
   - adds the holder key as a verification method (`#key-2`),
   - moves `authentication` and `assertionMethod` to the holder key,
   - rotates `parameters.updateKeys` to `[holderKey]` — so every *future* log
     entry must be signed by the holder key,
   - is itself signed by the **server key** (`#key-1`), which is still the
     authorized updater *as of the previous entry*. This is the standard
     did:webvh rotation: the current controller authorizes the successor.
2. **Marks the wallet self-custodied** (`wallets.custody_state = 'self'`) and
   records the holder key (`wallets.holder_multikey`).
3. **Retires the server key** (`receiver_keys.retired_at` set). The row is
   **retained, not deleted** (append-only philosophy / rollback safety), but it
   is removed from every verification relationship and from `updateKeys`.
4. **Rotates both resolution surfaces** to the holder key:
   - `did.jsonl` (the verifiable did:webvh history) — authority is the holder key.
   - `did.json` (the did:web quick-resolution mirror) — now serves the holder
     key, never the retired server key.

The append-only did:webvh log is verifiable end-to-end by
`credentials/webvh.ts` `verifyWebvhLog` (SCID self-certification + entry-hash
chain + per-entry authorized proof).

## Trust model — before vs. after

| | Before (server custody) | After (self custody) |
|---|---|---|
| Who holds the private signing key | roots (KEK-wrapped in D1) | the holder (on their device) |
| Who can sign as the wallet | roots | the holder only |
| `updateKeys` (who can extend the history) | server key | holder key |
| did.jsonl authority (`authentication`) | server key `#key-1` | holder key `#key-2` |
| did.json (`verificationMethod`) | server key | holder key |
| Data at rest (record payloads) | roots-encrypted, server-readable during a session | **unchanged** — still hosted (see below) |

### What the server CAN still do after handoff

- Serve the wallet's records and export bundle (encryption at rest is a
  *separate* concern from DID signing authority — see the caveat below).
- Regenerate the historical **inception** entry (version 1), which the server key
  *legitimately* signed at genesis. This reproduces a past signature; it is not
  new authority.
- Retain (but not use) the old KEK-wrapped server key for audit/rollback.

### What the server CANNOT do after handoff

- Produce a **new** valid did:webvh log entry. Future entries require a signature
  from the holder key (per `updateKeys`); a server-signed entry is rejected by
  `verifyWebvhLog` (`signer not authorized`).
- Present the server key as authoritative on either resolution surface — the
  handoff route refuses a second handoff (409), and both did.json and did.jsonl
  serve the holder key.

## Recovery story

- **Holder loses their key.** There is **no server-side recovery of signing
  authority** by design — that is the point of self-custody. Recovery would be a
  future social-recovery / rotation flow: the holder signs a new rotation entry
  with a pre-registered recovery key. Not implemented in this MVP.
- **Botched handoff / rollback.** Nothing is hard-deleted. The server key row and
  its KEK-wrapped secret are retained (`retired_at` marks it disabled). A rollback
  would clear `custody_state`, `holder_multikey`, and `retired_at`, and drop the
  version-2 `did_log` row — an operator DB action, deliberately not a public
  route.

## Known limitations / things to verify (flagged honestly)

- **Encryption at rest is unchanged.** Handoff rotates *DID signing authority*,
  not *data custody*. Record payloads are still encrypted under a roots-held KEK
  and are server-readable for authorized reads/exports. True end-to-end
  confidentiality (client-side encryption to the holder key) is a separate,
  larger change and is **not** part of this handoff.
- **Dual DID identity.** A wallet has a `did:web` identity (primary, in
  `wallets.did`) and a `did:webvh` identity (the verifiable history, whose DID
  embeds the log SCID). The handoff rotates the key material on both surfaces, but
  they remain distinct DIDs. Consumers should treat the did:webvh log as the
  authoritative history.
- **Naive verifiers.** The retired server key remains *listed* in the did:webvh
  entry's `verificationMethod` array (append-only) but is absent from every
  verification relationship and from `updateKeys`. A spec-compliant verifier will
  not honor it; a naive verifier that trusts any listed method could. This is the
  cost of append-only retention over hard deletion.
- **`versionTime` uses the request clock** for the handoff entry (the inception
  uses the deterministic wallet `created_at`). This is persisted, not
  regenerated, so it does not affect determinism.
