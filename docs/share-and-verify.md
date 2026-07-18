# roots.dreamtree.org — the human surface (share-and-verify first)

Status: SPEC v0 (owner-approved direction + order, 2026-07-18; card DT-24)
Owner rulings baked in: Telekora is the demo corpus ("still technically testing,
all active users are free, my sandbox"); wallet UI home = **roots.dreamtree.org**
(id.dreamtree.org never moves — it is baked into every DID); build everything
**except user management** first; custody/identity questions are settled canon
(`wallet-spec.md` L2 Q5, `wallet-v0.md` §1) — the remaining auth decisions are
listed at the bottom and stay open until the owner rules.

## Why this order

The chain holds commitments, never content — so "an employer checks validity
without the owner exposing information" is already a live primitive
(verify.dreamtree.org). What's missing is the presentation layer. We build the
share button before the wallet dashboard because a share link is the product
thesis made tangible, and every other surface (badges, wallet UI, docs) grows
outward from it. The legal ladder the owner named — "start with secure sharing,
push legal towards just validation" — is a technical ladder too:

1. **Grant-gated read** (live backend): purpose-scoped, revocable grants.
2. **Validity-only** (live primitive): anchored / when / issuer / standing —
   zero content exposure.
3. **Per-field selective disclosure** (future): salted per-field commitments;
   no exotic crypto required.
4. ZK-style proofs (someday, if ever warranted).

## 1. Share-and-verify

### The flow

- **Mint** (holder side): the holder, in a Telekora session, taps "Share" on a
  credential → Telekora calls roots with its existing **delegatedHolderAuth**
  (60s single-use EdDSA assertion — the live mechanism, no new user
  management) → roots mints a **share token** → link + QR.
- **Consume** (public side): anyone opening `roots.dreamtree.org/s/{token}`
  sees a rendered verdict page. No login, no account.

### Share modes (chosen at mint)

| mode | what the consumer sees | backend |
|---|---|---|
| `validity` | credential EXISTS, anchored at height H, issued by DID X (standing S), issued/valid dates, revocation status. **Never the content.** | verify primitive + roots record status |
| `read` | the above PLUS the credential content (rendered VC) | a purpose-bound revocable grant (`purpose=share:{token}`), decrypt-at-read |

### Share token design (roots D1, new table `share_tokens`)

- `token` — 128-bit random, base58; the URL path segment. Unguessable.
- `wallet_id`, `record_id` — what is shared.
- `mode` — `validity` | `read`.
- `created_by` — the holder assertion that minted it (audit chain).
- `expires_at` — REQUIRED, default 7 days, max 90.
- `max_uses` — default unlimited while unexpired; optional 1 for one-shot.
- `revoked_at` — holder-revocable any time; revocation lands on next open
  (same semantics as roots grants).
- Every consumption logged to the wallet's access log (`actor=share:{token}`)
  — the holder can see who-opened-what-when on their wallet surface later.

### Privacy properties (stated honestly on the page)

- `validity` mode: the consumer learns the credential type, issuer, dates,
  anchor, and revocation status — NOT the content, NOT the holder's other
  records. The page says exactly this.
- `read` mode: content is shown; the page states it was shared deliberately
  and is revocable.
- Both: opening a share writes an access-log entry the holder can see.

### Routes (roots worker; UI pages on roots.dreamtree.org)

- `POST /shares` (delegatedHolderAuth) — mint. Body: record_id, mode,
  expires_in, max_uses.
- `DELETE /shares/{token}` (delegatedHolderAuth) — revoke.
- `GET /s/{token}` — the public verdict page (HTML; `?format=json` for
  machines — same graded-verdict discipline as verify.dreamtree.org).
- Telekora side: a "Share" button on the existing credential views, calling
  its own backend which relays via delegation (pattern proven by Stage 3b
  plumbing).

## 2. Holder dashboard (moved up — owner 2026-07-18)

Owner rulings: no Telekora-side Share button (S3 dropped — these are dreamtree
upgrades); each wallet holder gets a dashboard at roots.dreamtree.org to
**view, add, verify, remove, and share** their documents and credentials.
User management REMAINS DEFERRED: the dashboard mounts behind the existing
delegatedHolderAuth seam (delegation or operator break-glass), and holder
login is a pluggable front door to be wired when the owner rules on it.
Nothing in the dashboard presumes a login mechanism.

**Sensitive documents live on the holder's device, never in our storage
(owner ruling 2026-07-18).** The add flow:

1. Holder picks a file → encrypted CLIENT-SIDE (WebCrypto, AES-GCM, key held
   client-side) → blob stored in the browser's Origin Private File System.
2. roots receives ONLY: sha256 commitment + a metadata record
   (`dt.document.*`, filename, size, mime) → anchored on-chain like any record.
3. **Verify** = rehash the local file, compare to the anchored commitment:
   "this exact file, unaltered, anchored at height N" — provable without our
   infrastructure ever holding a byte of content.
4. **Share** (validity mode) works unchanged — it is commitment-based.
   Read-mode sharing of device-held documents is a future, explicit,
   holder-initiated transfer — never a server-side copy.

The honest trade, stated in the UI: lose the device, lose the blob; the
record + anchor survive, and re-adding the original file re-verifies.
Records/credentials issued by tools (the existing corpus) stay hosted as
today — this ruling covers sensitive document BLOBS.

Verbs → rails: view (holder read path), add (device vault + record write),
verify (local rehash + record verify + anchor), remove (retract/reinstate,
append-only, honest), share (S1 tokens).

## 3. Chain dashboard (public pulse)

`roots.dreamtree.org/chain` (or dreamtree.org embed): supply vs peg, batch
cadence, convergence rate, latest anchors, governance state. Data via the
no-inbound-door pattern: an m3 job PUSHES a stats JSON outward on a cadence
(the verify-resolver already holds the outbound seam; a `/stats/push` Bearer
route on the worker + KV/D1 storage). No chain RPC exposure, ever.

## 4. Docs

- **Agents/developers**: verify API + MCP tools + share JSON format — served
  at verify.dreamtree.org (extend the landing) + a docs page.
- **Humans**: what a wallet is, what sharing does, what the verifier sees —
  plain language, on roots.dreamtree.org. The honesty framings (hosted
  custody, not zero-knowledge; what each share mode exposes) are copy
  requirements, not footnotes.

## 5. Badges (after shares exist)

An embeddable badge is a share link wearing a pixel:
`GET /s/{token}/badge.svg` renders current status (valid/revoked/expired)
from the same token machinery. Tools that hold a dt credential can embed it;
clicking lands on the share page. No new trust surface.

## Explicitly deferred: user management

Settled canon (do not re-open in build): hosted custody as default forever
(user-derived wrapping key; opt-in self-custody exit; NO seed phrases, NO
social recovery, NO passkey-ONLY custody); human-as-key identity tiers
(`verified_human` = holding `identity.proof_of_personhood` from a
KYC-provider-issuer; recovery = re-prove the human); IdP-at-surface,
DID-at-persistence; honest not-zero-knowledge framing.

Open — owner decisions before the holder login surface is built:
1. Which IdP fronts roots.dreamtree.org login (Auth0 / homegrown magic link).
2. Passkeys as a LOGIN factor (canon rejects them for custody; silent on auth).
3. KYC vendor + pricing (vendor-diligence rule: current primary-source
   pricing, owner decides).
4. What `verification_tier` gates (sharing? issuance? nothing at v0?).
5. Cross-IdP merging (wallet-spec L1 Q4, untouched).

## Sequencing

S1 share tokens + validity page [SHIPPED 2026-07-18] → S2 HOLDER DASHBOARD
(view/add/verify/remove/share, device vault, auth-agnostic) → S3 read-mode
shares → S4 chain dashboard → S5 docs → S6 badges. User-management
conversations can proceed in parallel; nothing in S1-S6 depends on them.
