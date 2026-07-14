/**
 * routes/identity.ts — wallet creation + DID resolution.
 *
 *   POST /wallets              create a wallet + bind an IdP identity (silent
 *                              wallet on signup); idempotent per (provider, uid).
 *   GET  /w/:id/did.json       the wallet's W3C DID document (did:web-resolvable)
 *   GET  /w/:id/did.jsonl      the wallet's append-only history (did:webvh seed)
 *   GET  /tenants/:tid/did.json an issuer's DID document (e.g. the export signer)
 *
 * V0 identity is did:web — resolvable now by the lifted verifier and by anyone
 * fetching the served did.json (this is what makes the export proof + issued
 * credentials externally verifiable). The wallet key is a server-custodied
 * receiver key (hosted custody; the custody handoff moves it to the holder).
 *
 * did.jsonl carries the SIGNED inception entry — the foundation of a did:webvh
 * history. It is honestly v0: a single deterministic inception entry, NOT yet
 * full did:webvh SCID / entry-hash chain verification (that is later hardening).
 */
import { Hono, type Context } from 'hono'
import type { Env } from '../auth'
import { consumerAuth, delegatedHolderAuth, requireScope } from '../auth'
import { dbAll, dbFirst, dbRun } from '../db'
import { getOrCreateReceiverKey } from '../credentials/keystore'
import { DID_WEB_DOMAIN, multikeyFromPublicKey } from '../credentials/keys'
import { multibase58Decode } from '../credentials/canonical'
import { buildWebvhInception, buildWebvhHandoffEntry } from '../credentials/webvh'

const identity = new Hono<Env>()

const walletDid = (id: string): string => `did:web:${DID_WEB_DOMAIN}:w:${id}`

async function resolveKek(c: Context<Env>): Promise<string | null> {
  return typeof c.env.ROOTS_KEK === 'string' ? c.env.ROOTS_KEK : (await c.env.ROOTS_KEK?.get()) ?? null
}

// A multibase Ed25519 Multikey is 34 bytes: 0xed 0x01 (multicodec) + 32-byte key.
function isEd25519Multikey(mk: string): boolean {
  try {
    const d = multibase58Decode(mk)
    return d.length === 34 && d[0] === 0xed && d[1] === 0x01
  } catch {
    return false
  }
}

// A W3C DID doc from a did + a Multikey (z6Mk…) publicKeyMultibase.
function didDocWithMultikey(did: string, multikey: string): Record<string, unknown> {
  const vm = `${did}#key-1`
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [{ id: vm, type: 'Multikey', controller: did, publicKeyMultibase: multikey }],
    assertionMethod: [vm],
    authentication: [vm],
  }
}

// A W3C DID doc from a did + the stored RAW-multibase pubkey (converted to the
// Multikey form the spec + the resolver expect).
function didDoc(did: string, rawMultibase: string): Record<string, unknown> {
  return didDocWithMultikey(did, multikeyFromPublicKey(multibase58Decode(rawMultibase)))
}

// ---------------------------------------------------------------- create wallet
// guid:roots-identity-create
identity.post('/wallets', consumerAuth, requireScope('wallets:create'), async (c) => {
  const b = await c.req.json<{ provider?: string; provider_uid?: string }>().catch(() => null)
  const provider = b?.provider?.trim()
  const providerUid = b?.provider_uid?.trim()
  if (!provider || !providerUid) return c.json({ error: 'provider and provider_uid required' }, 400)

  // Silent wallet: an existing (provider, uid) returns its wallet, never a dup.
  const bound = await dbFirst<{ wallet_id: string }>(
    c.env.DB, 'SELECT wallet_id FROM wallet_identities WHERE provider = ? AND provider_uid = ?', provider, providerUid,
  )
  if (bound) {
    const w = await dbFirst<{ id: string; did: string; verification_tier: string }>(
      c.env.DB, 'SELECT id, did, verification_tier FROM wallets WHERE id = ?', bound.wallet_id,
    )
    return c.json({ ok: true, existing: true, wallet_id: w?.id, did: w?.did, verification_tier: w?.verification_tier })
  }

  const kek = await resolveKek(c)
  if (!kek) return c.json({ error: 'wallet key provisioning unavailable (ROOTS_KEK not provisioned)' }, 503)

  const id = crypto.randomUUID()
  const did = walletDid(id)
  await dbRun(c.env.DB, 'INSERT INTO wallets (id, did) VALUES (?, ?)', id, did)
  const ins = await c.env.DB.prepare(
    `INSERT INTO wallet_identities (wallet_id, provider, provider_uid) VALUES (?, ?, ?)
     ON CONFLICT (provider, provider_uid) DO NOTHING`,
  ).bind(id, provider, providerUid).run()

  // Lost a concurrent same-identity race: our identity insert was a no-op, so
  // our wallet is an unbound orphan. Drop it and return the winner — never hand
  // back a wallet id whose identity binding didn't take.
  if (ins.meta.changes === 0) {
    await dbRun(c.env.DB, 'DELETE FROM wallets WHERE id = ?', id)
    const owner = await dbFirst<{ wallet_id: string }>(
      c.env.DB, 'SELECT wallet_id FROM wallet_identities WHERE provider = ? AND provider_uid = ?', provider, providerUid,
    )
    const w = owner && await dbFirst<{ id: string; did: string; verification_tier: string }>(
      c.env.DB, 'SELECT id, did, verification_tier FROM wallets WHERE id = ?', owner.wallet_id,
    )
    if (!w) return c.json({ error: 'wallet creation raced and could not resolve — retry' }, 409)
    return c.json({ ok: true, existing: true, wallet_id: w.id, did: w.did, verification_tier: w.verification_tier })
  }

  // Won the binding — mint the wallet's key (server-custodied; handoff moves it later).
  await getOrCreateReceiverKey(c.env.DB, kek, id)
  // Silent-wallet bootstrap: the creating consumer may CONTRIBUTE to the wallet
  // it created (write grant, all types) and READ BACK its own contributions
  // ('own'-scoped read grant, purpose-agnostic). It cannot read another
  // contributor's data without an explicit grant from the holder. Both revocable.
  const consumer = c.get('reader') ?? 'consumer'
  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO grants (id, wallet_id, grantee, capability, scope, data_type, purpose, granted_by)
       VALUES (?, ?, ?, 'write', 'all', NULL, NULL, 'system:creation')`,
    ).bind(crypto.randomUUID(), id, consumer),
    c.env.DB.prepare(
      `INSERT INTO grants (id, wallet_id, grantee, capability, scope, data_type, purpose, granted_by)
       VALUES (?, ?, ?, 'read', 'own', NULL, NULL, 'system:creation')`,
    ).bind(crypto.randomUUID(), id, consumer),
  ])
  return c.json({ ok: true, existing: false, wallet_id: id, did })
})

// ---------------------------------------------------------------- did.json (wallet)
// Public: DID documents are meant to be resolved by anyone.
// guid:roots-identity-wallet-diddoc
identity.get('/w/:id/did.json', async (c) => {
  const id = c.req.param('id')!
  const w = await dbFirst<{ did: string; custody_state: string; holder_multikey: string | null }>(
    c.env.DB, 'SELECT did, custody_state, holder_multikey FROM wallets WHERE id = ?', id,
  )
  if (!w?.did) return c.json({ error: 'not found' }, 404)
  // Self-custody: the holder key is authoritative — never serve the retired
  // server key. (The verifiable did:webvh history in did.jsonl is the full story.)
  if (w.custody_state === 'self' && w.holder_multikey) {
    return c.json(didDocWithMultikey(w.did, w.holder_multikey))
  }
  const rk = await dbFirst<{ public_key_multibase: string }>(
    c.env.DB, 'SELECT public_key_multibase FROM receiver_keys WHERE user_id = ?', id,
  )
  if (!rk) return c.json({ error: 'wallet key not provisioned' }, 404)
  return c.json(didDoc(w.did, rk.public_key_multibase))
})

// ---------------------------------------------------------------- did.jsonl (history)
// A did:webvh log: the deterministic inception (version 1) regenerated from the
// wallet's receiver key + created_at, followed by any appended entries (e.g. a
// custody handoff, version >= 2) persisted in did_log. The log SCID + entry-hash
// chain + proofs are verifiable by credentials/webvh.ts verifyWebvhLog.
// guid:roots-identity-wallet-history
identity.get('/w/:id/did.jsonl', async (c) => {
  const id = c.req.param('id')!
  const w = await dbFirst<{ did: string; created_at: string }>(
    c.env.DB, 'SELECT did, created_at FROM wallets WHERE id = ?', id,
  )
  if (!w?.did) return c.json({ error: 'not found' }, 404)
  const kek = await resolveKek(c)
  if (!kek) return c.json({ error: 'history signing unavailable (ROOTS_KEK not provisioned)' }, 503)
  const key = await getOrCreateReceiverKey(c.env.DB, kek, id)
  const serverMultikey = multikeyFromPublicKey(multibase58Decode(key.publicKeyMultibase))
  const inception = await buildWebvhInception({
    walletId: id, domain: DID_WEB_DOMAIN, serverMultikey, privateJwk: key.privateJwk, created: w.created_at,
  })
  const extra = await dbAll<{ entry_json: string }>(
    c.env.DB, 'SELECT entry_json FROM did_log WHERE wallet_id = ? ORDER BY version', id,
  )
  const lines = [JSON.stringify(inception.entry), ...extra.map((r) => r.entry_json)]
  return c.text(lines.join('\n') + '\n', 200, { 'content-type': 'application/jsonl' })
})

// ---------------------------------------------------------------- custody handoff
// The holder takes their own key: they submit a client-generated Ed25519 public
// key (Multikey), roots appends a chained did:webvh entry rotating authority to
// it, marks the wallet self-custodied, and disables (retains) the server key.
// After this the server can no longer sign NEW updates for the wallet — future
// entries require the holder key, which the server never holds. See
// docs/custody-handoff.md. Holder-authed (delegation) with operator break-glass.
// guid:roots-identity-custody-handoff
identity.post('/w/:id/custody/handoff', delegatedHolderAuth, async (c) => {
  const id = c.req.param('id')!
  const w = await dbFirst<{ did: string; created_at: string; custody_state: string }>(
    c.env.DB, 'SELECT did, created_at, custody_state FROM wallets WHERE id = ?', id,
  )
  if (!w?.did) return c.json({ error: 'wallet not found' }, 404)
  if (w.custody_state === 'self') return c.json({ error: 'wallet is already self-custodied' }, 409)
  const b = await c.req.json<{ public_key_multibase?: string }>().catch(() => null)
  const holderMultikey = b?.public_key_multibase?.trim()
  if (!holderMultikey || !isEd25519Multikey(holderMultikey)) {
    return c.json({ error: 'public_key_multibase (an Ed25519 Multikey, z6Mk…) required' }, 400)
  }
  const kek = await resolveKek(c)
  if (!kek) return c.json({ error: 'handoff signing unavailable (ROOTS_KEK not provisioned)' }, 503)
  const key = await getOrCreateReceiverKey(c.env.DB, kek, id)
  const serverMultikey = multikeyFromPublicKey(multibase58Decode(key.publicKeyMultibase))
  // Recompute the deterministic inception to chain the handoff onto it, and to
  // authorize the handoff with the server key (still in inception.updateKeys).
  const inception = await buildWebvhInception({
    walletId: id, domain: DID_WEB_DOMAIN, serverMultikey, privateJwk: key.privateJwk, created: w.created_at,
  })
  const last = await dbFirst<{ version: number }>(
    c.env.DB, 'SELECT version FROM did_log WHERE wallet_id = ? ORDER BY version DESC LIMIT 1', id,
  )
  const nextVersion = (last?.version ?? 1) + 1
  const created = new Date().toISOString()
  const handoff = await buildWebvhHandoffEntry({
    did: inception.did, scid: inception.scid, version: nextVersion, prevVersionId: inception.versionId,
    serverMultikey, holderMultikey, privateJwk: key.privateJwk, created,
  })
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT INTO did_log (wallet_id, version, entry_json) VALUES (?, ?, ?)')
      .bind(id, nextVersion, JSON.stringify(handoff.entry)),
    c.env.DB.prepare("UPDATE wallets SET custody_state = 'self', holder_multikey = ? WHERE id = ?").bind(holderMultikey, id),
    c.env.DB.prepare("UPDATE receiver_keys SET retired_at = datetime('now') WHERE user_id = ? AND retired_at IS NULL").bind(id),
  ])
  return c.json({
    ok: true, wallet_id: id, custody_state: 'self',
    did: inception.did, version_id: handoff.versionId, holder_key: holderMultikey,
  })
})

// ---------------------------------------------------------------- did.json (issuer)
// Makes did:web:dreamtree.org:tenants:<tid> resolvable — e.g. the export signer,
// so the export proof + issued credentials verify externally.
// guid:roots-identity-issuer-diddoc
identity.get('/tenants/:tid/did.json', async (c) => {
  const ik = await dbFirst<{ did: string; public_key_multibase: string }>(
    c.env.DB, 'SELECT did, public_key_multibase FROM issuer_keys WHERE tenant_id = ?', c.req.param('tid'),
  )
  if (!ik) return c.json({ error: 'not found' }, 404)
  return c.json(didDoc(ik.did, ik.public_key_multibase))
})

export default identity
