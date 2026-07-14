/**
 * records-core.ts — the one place records are written.
 *
 * Both the HTTP routes (routes/records.ts) and the agent surface (routes/mcp.ts)
 * go through these helpers, so the two write paths can never diverge — important
 * for a wallet where the audit chain is load-bearing.
 */
import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst, dbRun } from './db'
import { verifyExternal, type ExternalInput, type ExternalReport, type ManualMeta } from './credentials/verify-external'
import { sealPayload } from './wallet-crypto'
import { allocateStatusIndex, recordCredentialStatus, statusEntriesFor } from './credentials/status'
import { getOrCreateIssuerKey } from './credentials/keystore'
import { createDataIntegrityProof } from './credentials/di'
import { issuerVerificationMethod } from './credentials/keys'

// guid:records-core-walletExists
export async function walletExists(db: D1Database, id: string): Promise<boolean> {
  return !!(await dbFirst<{ id: string }>(db, 'SELECT id FROM wallets WHERE id = ?', id))
}

// guid:records-core-toExternalInput
export function toExternalInput(body: { kind?: string; doc?: unknown; token?: string; meta?: unknown }): ExternalInput | null {
  if (body.kind === 'jwt' && typeof body.token === 'string') return { kind: 'jwt', token: body.token.trim() }
  if (body.kind === 'manual') return { kind: 'manual', meta: (body.meta as ManualMeta) ?? {} }
  if (body.doc && typeof body.doc === 'object') return { kind: 'json', doc: body.doc as Record<string, unknown> }
  if (typeof body.doc === 'string') {
    const s = body.doc.trim()
    if (/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(s)) return { kind: 'jwt', token: s }
    try { return { kind: 'json', doc: JSON.parse(s) } } catch { return null }
  }
  return null
}

// guid:records-core-upsertIssuer — seen issuers land in the registry as 'known'
// (which caps the honest tier at valid-signature; only operator promotion to
// 'trusted' yields 'verified').
export async function upsertIssuer(db: D1Database, didOrIss: string, name: string | null): Promise<string> {
  const existing = await dbFirst<{ id: string }>(db, 'SELECT id FROM issuers WHERE did_or_iss = ?', didOrIss)
  if (existing) return existing.id
  const id = crypto.randomUUID()
  await dbRun(
    db,
    `INSERT INTO issuers (id, did_or_iss, name, status) VALUES (?, ?, ?, 'known')
     ON CONFLICT(did_or_iss) DO NOTHING`,
    id, didOrIss, name,
  )
  const row = await dbFirst<{ id: string }>(db, 'SELECT id FROM issuers WHERE did_or_iss = ?', didOrIss)
  return row?.id ?? id
}

// guid:records-core-writeSelfRecord
/** Seal the payload only when the type is PII (`encrypt`); non-PII types are
 *  stored clear at rest, per the registry's PII class. */
export async function writeSelfRecord(
  db: D1Database,
  p: { walletId: string; dataType: string; payload: unknown; sourceType: 'self' | 'tool'; sourceRef?: string | null; actor: string; encrypt: boolean; dataKeyB64?: string },
): Promise<{ id: string }> {
  const id = crypto.randomUUID()
  const payloadStr = typeof p.payload === 'string' ? p.payload : JSON.stringify(p.payload)
  const stored = p.encrypt ? await sealPayload(p.dataKeyB64!, payloadStr) : payloadStr
  await db.batch([
    db.prepare(`INSERT INTO records (id, wallet_id, data_type, payload, encrypted, source_type, source_ref, contributor) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, p.walletId, p.dataType, stored, p.encrypt ? 1 : 0, p.sourceType, p.sourceRef ?? null, p.actor),
    db.prepare(`INSERT INTO record_events (id, record_id, event, actor) VALUES (?, ?, 'created', ?)`)
      .bind(crypto.randomUUID(), id, p.actor),
  ])
  return { id }
}

/**
 * When roots ISSUES its own credential (source_type='issued' + an UNSIGNED JSON
 * claim set), roots is the cryptographic issuer: it stamps a revocable
 * BitstringStatusList entry, signs the credential with its per-scope issuer key
 * (eddsa-jcs-2022), and records the status slot so the credential can later be
 * revoked/suspended by flipping a bit in the served status list. Externally-signed
 * credentials are never mutated (that would break their proof) — their status is
 * their own issuer's concern; they take the plain store path below.
 *
 * Returns the signed credential document (to store + verify) or null when the
 * input is not a roots-issuance candidate.
 */
// guid:records-core-rootsIssue
async function rootsIssueCredential(
  db: D1Database,
  recordId: string,
  p: { input: ExternalInput; sourceType: 'issued' | 'imported'; actor: string; origin?: string; kek?: string },
): Promise<Record<string, unknown> | null> {
  if (p.sourceType !== 'issued' || p.input.kind !== 'json' || !p.origin || !p.kek) return null
  const doc = p.input.doc
  // Only issue (sign) a claim that isn't already signed — never overwrite an
  // external issuer's proof.
  if (doc.proof) return null
  const tenant = p.actor // the issuing scope (opaque consumer id -> roots issuer key)
  const idx = await allocateStatusIndex(db, tenant)
  const issuer = await getOrCreateIssuerKey(db, p.kek, tenant)
  const unsigned: Record<string, unknown> = {
    '@context': doc['@context'] ?? ['https://www.w3.org/ns/credentials/v2'],
    ...doc,
    id: (typeof doc.id === 'string' && doc.id) || `urn:uuid:${recordId}`,
    issuer: doc.issuer ?? issuer.did,
    credentialStatus: statusEntriesFor(p.origin, tenant, idx),
  }
  delete (unsigned as { proof?: unknown }).proof
  const proof = await createDataIntegrityProof(unsigned, {
    privateJwk: issuer.privateJwk,
    verificationMethod: issuerVerificationMethod(issuer.did),
    proofPurpose: 'assertionMethod',
  })
  await recordCredentialStatus(db, recordId, tenant, idx)
  return { ...unsigned, proof }
}

// guid:records-core-writeCredentialRecord
/** Credentials are always encrypted at rest (owner-sovereignty default). */
export async function writeCredentialRecord(
  db: D1Database,
  p: { walletId: string; dataType: string; input: ExternalInput; sourceType: 'issued' | 'imported'; actor: string; dataKeyB64: string; sourceRef?: string | null; origin?: string; kek?: string },
): Promise<{ id: string; report: ExternalReport }> {
  const id = crypto.randomUUID()
  // roots-issuance: sign the claim + attach a revocable credentialStatus.
  const issued = await rootsIssueCredential(db, id, p)
  const effectiveInput: ExternalInput = issued ? { kind: 'json', doc: issued } : p.input
  const report = await verifyExternal(effectiveInput, db)
  const issuerId = report.issuer?.id ? await upsertIssuer(db, report.issuer.id, report.issuer.name ?? null) : null
  // Manual credentials are stored as a {kind:'manual', meta} envelope so a
  // read-time verify can reconstruct the input kind (bare meta JSON is
  // indistinguishable from a VC document).
  const payload = effectiveInput.kind === 'jwt' ? effectiveInput.token
    : effectiveInput.kind === 'json' ? JSON.stringify(effectiveInput.doc)
    : JSON.stringify({ kind: 'manual', meta: effectiveInput.meta ?? {} })
  const sealed = await sealPayload(p.dataKeyB64, payload)
  const alignmentJson = report.alignments && report.alignments.length ? JSON.stringify(report.alignments) : null
  await db.batch([
    db.prepare(
      `INSERT INTO records (id, wallet_id, data_type, payload, encrypted, source_type, source_ref, issuer_id, alignment_json, contributor)
       VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
    ).bind(id, p.walletId, p.dataType, sealed, p.sourceType, p.sourceRef ?? null, issuerId, alignmentJson, p.actor),
    db.prepare(`INSERT INTO record_events (id, record_id, event, actor) VALUES (?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), id, p.sourceType === 'issued' ? 'issued' : 'imported', p.actor),
  ])
  return { id, report }
}
