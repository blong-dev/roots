/**
 * Lazy provisioning of issuer (per-tenant) and receiver (per-user) Ed25519
 * keypairs. Created on first use; encrypted JWK stored under ROOTS_KEK
 * via api/src/crypto.ts. Race-safe: ON CONFLICT DO NOTHING and re-read.
 */

import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst, dbRun } from '../db'
import { didWebForTenant, generateEd25519Keypair, unwrapPrivateJwk, wrapKeypair } from './keys'

export interface IssuerKey {
  tenantId: string
  did: string
  publicKeyMultibase: string
  privateJwk: JsonWebKey
}

export interface ReceiverKey {
  userId: string
  did: string
  publicKeyMultibase: string
  privateJwk: JsonWebKey
}

interface KeyRow {
  did: string
  public_key_multibase: string
  encrypted_private_jwk: string
  encryption_iv: string
}

// guid:credentials-getOrCreateIssuerKey
// guid:c1adf3da-be7f-4a66-a103-feedc13008c2
export async function getOrCreateIssuerKey(
  db: D1Database,
  kekB64: string,
  tenantId: string,
): Promise<IssuerKey> {
  const existing = await dbFirst<KeyRow>(
    db,
    `SELECT did, public_key_multibase, encrypted_private_jwk, encryption_iv
       FROM issuer_keys WHERE tenant_id = ?`,
    tenantId,
  )
  if (existing) {
    return {
      tenantId,
      did: existing.did,
      publicKeyMultibase: existing.public_key_multibase,
      privateJwk: await unwrapPrivateJwk(
        kekB64, existing.encrypted_private_jwk, existing.encryption_iv,
      ),
    }
  }

  const kp = await generateEd25519Keypair()
  const wrapped = await wrapKeypair(kekB64, kp)
  // Profile §3: issuers are did:web (rotation-capable, DID doc served by the
  // worker). wrapKeypair computes did:key — override for institutional issuers.
  const issuerDid = didWebForTenant(tenantId)
  await dbRun(
    db,
    `INSERT INTO issuer_keys
       (tenant_id, did, public_key_multibase, encrypted_private_jwk, encryption_iv)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (tenant_id) DO NOTHING`,
    tenantId,
    issuerDid,
    wrapped.publicKeyMultibase,
    wrapped.encryptedPrivateJwk,
    wrapped.encryptionIv,
  )
  // Race-safe re-read — if a concurrent insert won, our generated JWK is dead.
  const final = await dbFirst<KeyRow>(
    db,
    `SELECT did, public_key_multibase, encrypted_private_jwk, encryption_iv
       FROM issuer_keys WHERE tenant_id = ?`,
    tenantId,
  )
  if (!final) throw new Error('Failed to provision issuer key for tenant ' + tenantId)
  if (final.did === issuerDid) {
    return {
      tenantId,
      did: issuerDid,
      publicKeyMultibase: wrapped.publicKeyMultibase,
      privateJwk: kp.privateJwk,
    }
  }
  return {
    tenantId,
    did: final.did,
    publicKeyMultibase: final.public_key_multibase,
    privateJwk: await unwrapPrivateJwk(
      kekB64, final.encrypted_private_jwk, final.encryption_iv,
    ),
  }
}

// guid:credentials-getOrCreateReceiverKey
// guid:0ff9e8d2-e8cd-46e9-b30b-5a67670c1dff
export async function getOrCreateReceiverKey(
  db: D1Database,
  kekB64: string,
  userId: string,
): Promise<ReceiverKey> {
  const existing = await dbFirst<KeyRow>(
    db,
    `SELECT did, public_key_multibase, encrypted_private_jwk, encryption_iv
       FROM receiver_keys WHERE user_id = ?`,
    userId,
  )
  if (existing) {
    return {
      userId,
      did: existing.did,
      publicKeyMultibase: existing.public_key_multibase,
      privateJwk: await unwrapPrivateJwk(
        kekB64, existing.encrypted_private_jwk, existing.encryption_iv,
      ),
    }
  }

  const kp = await generateEd25519Keypair()
  const wrapped = await wrapKeypair(kekB64, kp)
  await dbRun(
    db,
    `INSERT INTO receiver_keys
       (user_id, did, public_key_multibase, encrypted_private_jwk, encryption_iv)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (user_id) DO NOTHING`,
    userId,
    wrapped.did,
    wrapped.publicKeyMultibase,
    wrapped.encryptedPrivateJwk,
    wrapped.encryptionIv,
  )
  const final = await dbFirst<KeyRow>(
    db,
    `SELECT did, public_key_multibase, encrypted_private_jwk, encryption_iv
       FROM receiver_keys WHERE user_id = ?`,
    userId,
  )
  if (!final) throw new Error('Failed to provision receiver key for user ' + userId)
  if (final.did === wrapped.did) {
    return {
      userId,
      did: wrapped.did,
      publicKeyMultibase: wrapped.publicKeyMultibase,
      privateJwk: kp.privateJwk,
    }
  }
  return {
    userId,
    did: final.did,
    publicKeyMultibase: final.public_key_multibase,
    privateJwk: await unwrapPrivateJwk(
      kekB64, final.encrypted_private_jwk, final.encryption_iv,
    ),
  }
}
