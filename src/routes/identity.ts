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
import { consumerAuth, requireScope } from '../auth'
import { dbFirst, dbRun } from '../db'
import { getOrCreateReceiverKey } from '../credentials/keystore'
import { DID_WEB_DOMAIN, multikeyFromPublicKey } from '../credentials/keys'
import { multibase58Decode } from '../credentials/canonical'
import { createDataIntegrityProof } from '../credentials/di'

const identity = new Hono<Env>()

const walletDid = (id: string): string => `did:web:${DID_WEB_DOMAIN}:w:${id}`

async function resolveKek(c: Context<Env>): Promise<string | null> {
  return typeof c.env.ROOTS_KEK === 'string' ? c.env.ROOTS_KEK : (await c.env.ROOTS_KEK?.get()) ?? null
}

// A W3C DID doc from a did + the stored RAW-multibase pubkey (converted to the
// Multikey form the spec + the resolver expect).
function didDoc(did: string, rawMultibase: string): Record<string, unknown> {
  const multikey = multikeyFromPublicKey(multibase58Decode(rawMultibase))
  const vm = `${did}#key-1`
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [{ id: vm, type: 'Multikey', controller: did, publicKeyMultibase: multikey }],
    assertionMethod: [vm],
    authentication: [vm],
  }
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
  // Silent-wallet bootstrap: the creating consumer may contribute to the wallet
  // it just created (write grant, all types). The holder can revoke it later.
  await dbRun(
    c.env.DB,
    `INSERT INTO grants (id, wallet_id, grantee, capability, data_type, purpose, granted_by)
     VALUES (?, ?, ?, 'write', NULL, NULL, 'system:creation')`,
    crypto.randomUUID(), id, c.get('reader') ?? 'consumer',
  )
  return c.json({ ok: true, existing: false, wallet_id: id, did })
})

// ---------------------------------------------------------------- did.json (wallet)
// Public: DID documents are meant to be resolved by anyone.
// guid:roots-identity-wallet-diddoc
identity.get('/w/:id/did.json', async (c) => {
  const id = c.req.param('id')!
  const w = await dbFirst<{ did: string }>(c.env.DB, 'SELECT did FROM wallets WHERE id = ?', id)
  if (!w?.did) return c.json({ error: 'not found' }, 404)
  const rk = await dbFirst<{ public_key_multibase: string }>(
    c.env.DB, 'SELECT public_key_multibase FROM receiver_keys WHERE user_id = ?', id,
  )
  if (!rk) return c.json({ error: 'wallet key not provisioned' }, 404)
  return c.json(didDoc(w.did, rk.public_key_multibase))
})

// ---------------------------------------------------------------- did.jsonl (history)
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
  const doc = didDoc(w.did, key.publicKeyMultibase)
  const entry: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    versionId: '1',
    versionTime: w.created_at,
    state: doc,
  }
  // Deterministic: `created` is pinned to the wallet's creation, so the inception
  // entry regenerates identically (Ed25519 is deterministic) — no history table
  // needed while the log is immutable at v0.
  const proof = await createDataIntegrityProof(entry, {
    privateJwk: key.privateJwk,
    verificationMethod: `${w.did}#key-1`,
    proofPurpose: 'assertionMethod',
    created: w.created_at,
  })
  return c.text(JSON.stringify({ ...entry, proof }) + '\n', 200, { 'content-type': 'application/jsonl' })
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
