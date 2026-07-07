/**
 * status.ts — W3C Bitstring Status List support (profile D2: BOTH purposes).
 *
 * Every issued credential carries two BitstringStatusListEntry members —
 * statusPurpose `revocation` (permanent) and `suspension` (reversible).
 * Per-tenant lists are generated on demand from `credential_status` rows and
 * served as signed BitstringStatusListCredentials (themselves profile-
 * conformant VCs) at  GET /status/:tenantId/:purpose .
 *
 * Index allocation: one index per credential (shared by both purposes),
 * race-safe via `UPDATE … RETURNING` on `status_counters`.
 */

import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst } from '../db'
import { createDataIntegrityProof } from './di'
import { getOrCreateIssuerKey } from './keystore'
import { issuerVerificationMethod } from './keys'

// Spec minimum list length: 131,072 entries (16 KiB) for herd privacy.
export const MIN_LIST_LENGTH = 131072

export type StatusPurpose = 'revocation' | 'suspension'

// guid:14531085-d312-48d8-a511-32b1d225da3f
export function statusListUrl(origin: string, tenantId: string, purpose: StatusPurpose): string {
  return `${origin}/status/${tenantId}/${purpose}`
}

/** Allocate the next status-list index for a tenant (race-safe). */
// guid:status-allocateIndex
// guid:b17cdad2-f006-4102-8eea-eb1bd1686737
export async function allocateStatusIndex(db: D1Database, tenantId: string): Promise<number> {
  await db.prepare('INSERT OR IGNORE INTO status_counters (tenant_id, next_index) VALUES (?, 0)')
    .bind(tenantId).run()
  const row = await dbFirst<{ next_index: number }>(
    db,
    'UPDATE status_counters SET next_index = next_index + 1 WHERE tenant_id = ? RETURNING next_index',
    tenantId,
  )
  if (!row) throw new Error('status index allocation failed for tenant ' + tenantId)
  return row.next_index - 1
}

/** Record a freshly-issued credential's status slot (both bits start 0). */
// guid:status-recordCredential
// guid:426761d2-e2f6-408d-8495-2ccde6633e6d
export async function recordCredentialStatus(
  db: D1Database,
  credentialId: string,
  tenantId: string,
  statusIndex: number,
): Promise<void> {
  await db.prepare(
    `INSERT OR IGNORE INTO credential_status (credential_id, tenant_id, status_index)
     VALUES (?, ?, ?)`,
  ).bind(credentialId, tenantId, statusIndex).run()
}

/** Flip revocation/suspension on a credential. Returns false if unknown id. */
// guid:status-setStatus
// guid:c3d3b23b-6e26-4941-b988-b12c20f77eaa
export async function setCredentialStatus(
  db: D1Database,
  credentialId: string,
  tenantId: string,
  purpose: StatusPurpose,
  value: boolean,
): Promise<boolean> {
  const col = purpose === 'revocation' ? 'revoked' : 'suspended'
  const r = await db.prepare(
    `UPDATE credential_status SET ${col} = ?, updated_at = datetime('now')
     WHERE credential_id = ? AND tenant_id = ?`,
  ).bind(value ? 1 : 0, credentialId, tenantId).run()
  return (r.meta.changes ?? 0) > 0
}

export interface CredentialStatusRow {
  status_index: number
  revoked: number
  suspended: number
}

// guid:status-getStatus
// guid:8ab33762-2c73-40f8-8a9e-f4e1d793374a
export async function getCredentialStatus(
  db: D1Database,
  credentialId: string,
): Promise<CredentialStatusRow | null> {
  return dbFirst<CredentialStatusRow>(
    db,
    'SELECT status_index, revoked, suspended FROM credential_status WHERE credential_id = ?',
    credentialId,
  )
}

/** The two credentialStatus entries stamped into every issued credential. */
// guid:status-entriesFor
// guid:885d5d5f-41fe-444c-b392-dbe21f6f39be
export function statusEntriesFor(
  origin: string,
  tenantId: string,
  statusIndex: number,
): Record<string, unknown>[] {
  return (['revocation', 'suspension'] as StatusPurpose[]).map((purpose) => ({
    id: `${statusListUrl(origin, tenantId, purpose)}#${statusIndex}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: purpose,
    statusListIndex: String(statusIndex),
    statusListCredential: statusListUrl(origin, tenantId, purpose),
  }))
}

/** GZIP via the Workers-native CompressionStream. */
// guid:4ffa7011-f5d3-4d1e-8d8b-3613d03f9a55
async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip')
  const body = new Response(bytes as unknown as BodyInit).body
  if (!body) throw new Error('gzip: empty body')
  const compressed = new Response(body.pipeThrough(cs as unknown as ReadableWritablePair<Uint8Array, Uint8Array>))
  return new Uint8Array(await compressed.arrayBuffer())
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
// guid:1d892ca6-6c98-4a23-9ca6-adb7c423b055
function base64url(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const [a, b, c] = [bytes[i], bytes[i + 1], bytes[i + 2]]
    out += B64URL[a >> 2] + B64URL[((a & 3) << 4) | ((b ?? 0) >> 4)]
    if (b !== undefined) out += B64URL[((b & 15) << 2) | ((c ?? 0) >> 6)]
    if (c !== undefined) out += B64URL[c & 63]
  }
  return out
}

/**
 * Build + sign the BitstringStatusListCredential for one tenant × purpose.
 * Bit N (MSB-first within each byte, per spec) = credential at statusListIndex N.
 */
// guid:status-buildListCredential
// guid:7d197226-5b62-4135-b917-2ed5412015f4
export async function buildStatusListCredential(
  db: D1Database,
  kekB64: string,
  origin: string,
  tenantId: string,
  purpose: StatusPurpose,
): Promise<Record<string, unknown>> {
  const col = purpose === 'revocation' ? 'revoked' : 'suspended'
  const { results } = await db.prepare(
    `SELECT status_index FROM credential_status WHERE tenant_id = ? AND ${col} = 1`,
  ).bind(tenantId).all<{ status_index: number }>()

  const maxIdx = results.reduce((m, r) => Math.max(m, r.status_index), 0)
  const length = Math.max(MIN_LIST_LENGTH, maxIdx + 1)
  const bits = new Uint8Array(Math.ceil(length / 8))
  for (const r of results) {
    const i = r.status_index
    bits[i >> 3] |= 0x80 >> (i & 7)   // MSB-first (left-to-right), per spec
  }
  const encodedList = 'u' + base64url(await gzip(bits))

  const issuer = await getOrCreateIssuerKey(db, kekB64, tenantId)
  const url = statusListUrl(origin, tenantId, purpose)
  const unsigned: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: url,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: issuer.did,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: `${url}#list`,
      type: 'BitstringStatusList',
      statusPurpose: purpose,
      encodedList,
    },
  }
  const proof = await createDataIntegrityProof(unsigned, {
    privateJwk: issuer.privateJwk,
    verificationMethod: issuerVerificationMethod(issuer.did),
    proofPurpose: 'assertionMethod',
  })
  return { ...unsigned, proof }
}
