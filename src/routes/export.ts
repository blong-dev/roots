/**
 * routes/export.ts — sovereignty. The holder leaves with everything, intact.
 *
 *   GET /w/:id/export   holder-authed; a signed, self-contained bundle of the
 *                       ENTIRE wallet — records (all states), the full audit
 *                       chain, identities, grants, and the access log.
 *
 * Hard rule #4 (protocol-spec §Access): the owner can leave and take their data,
 * unconditionally. The bundle carries an eddsa-jcs-2022 proof (the same signing
 * path the credential engine uses) AND the signer's public key inline, so it is
 * integrity-verifiable OFFLINE — you never phone home to roots to trust your own
 * export. (Full authenticity resolves the signer's did:web doc once the wellknown
 * route ships; the embedded key covers integrity today.)
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { delegatedHolderAuth } from '../auth'
import { dbFirst } from '../db'
import { getOrCreateIssuerKey } from '../credentials/keystore'
import { createDataIntegrityProof } from '../credentials/di'
import { issuerVerificationMethod } from '../credentials/keys'
import { decryptRecords } from '../wallet-crypto'

const exportRoutes = new Hono<Env>()

const ROOTS_SIGNER = 'roots' // issuer scope for the export-signing key

// guid:roots-export
exportRoutes.get('/:id/export', delegatedHolderAuth, async (c) => {
  const walletId = c.req.param('id')!
  const wallet = await dbFirst<Record<string, unknown>>(
    c.env.DB, 'SELECT id, did, verification_tier, created_at FROM wallets WHERE id = ?', walletId,
  )
  if (!wallet) return c.json({ error: 'wallet not found' }, 404)

  const kek = typeof c.env.ROOTS_KEK === 'string' ? c.env.ROOTS_KEK : await c.env.ROOTS_KEK?.get()
  if (!kek) return c.json({ error: 'export signing key unavailable (ROOTS_KEK not provisioned)' }, 503)

  const [identities, records, events, grants, access] = await Promise.all([
    c.env.DB.prepare('SELECT provider, provider_uid, created_at FROM wallet_identities WHERE wallet_id = ?').bind(walletId).all(),
    c.env.DB.prepare(
      `SELECT id, data_type, payload, encrypted, source_type, source_ref, issuer_id, signature,
              alignment_json, state, created_at, updated_at
         FROM records WHERE wallet_id = ? ORDER BY created_at`,
    ).bind(walletId).all<Record<string, unknown>>(),
    c.env.DB.prepare(
      `SELECT e.id, e.record_id, e.event, e.reason, e.actor, e.created_at
         FROM record_events e JOIN records r ON r.id = e.record_id
        WHERE r.wallet_id = ? ORDER BY e.created_at`,
    ).bind(walletId).all(),
    c.env.DB.prepare('SELECT id, grantee, capability, scope, data_type, purpose, granted_at, revoked_at, granted_by FROM grants WHERE wallet_id = ? ORDER BY granted_at').bind(walletId).all(),
    c.env.DB.prepare('SELECT reader, data_type, purpose, outcome, at FROM access_log WHERE wallet_id = ? ORDER BY at').bind(walletId).all(),
  ])

  // Decrypt at-rest payloads — the holder leaves with plaintext (bundle is signed).
  const decryptedRecords = await decryptRecords(c.env, walletId, records.results)
  if (decryptedRecords === null) return c.json({ error: 'export decryption unavailable (ROOTS_KEK not provisioned)' }, 503)

  const key = await getOrCreateIssuerKey(c.env.DB, kek, ROOTS_SIGNER)
  const unsecured: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: 'RootsWalletExport',
    exported_at: new Date().toISOString(),
    exported_by: c.get('holder') ?? 'operator',
    issuer: { did: key.did, publicKeyMultibase: key.publicKeyMultibase },
    wallet,
    identities: identities.results,
    records: decryptedRecords,
    record_events: events.results,
    grants: grants.results,
    access_log: access.results,
  }
  const proof = await createDataIntegrityProof(unsecured, {
    privateJwk: key.privateJwk,
    verificationMethod: issuerVerificationMethod(key.did),
    proofPurpose: 'assertionMethod',
  })
  return c.json({ ...unsecured, proof })
})

export default exportRoutes
