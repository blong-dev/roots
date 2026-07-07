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
export async function writeSelfRecord(
  db: D1Database,
  p: { walletId: string; dataType: string; payload: unknown; sourceType: 'self' | 'tool'; sourceRef?: string | null; actor: string },
): Promise<{ id: string }> {
  const id = crypto.randomUUID()
  const payloadStr = typeof p.payload === 'string' ? p.payload : JSON.stringify(p.payload)
  await db.batch([
    db.prepare(`INSERT INTO records (id, wallet_id, data_type, payload, source_type, source_ref) VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(id, p.walletId, p.dataType, payloadStr, p.sourceType, p.sourceRef ?? null),
    db.prepare(`INSERT INTO record_events (id, record_id, event, actor) VALUES (?, ?, 'created', ?)`)
      .bind(crypto.randomUUID(), id, p.actor),
  ])
  return { id }
}

// guid:records-core-writeCredentialRecord
export async function writeCredentialRecord(
  db: D1Database,
  p: { walletId: string; input: ExternalInput; sourceType: 'issued' | 'imported'; actor: string },
): Promise<{ id: string; report: ExternalReport }> {
  const report = await verifyExternal(p.input, db)
  const issuerId = report.issuer?.id ? await upsertIssuer(db, report.issuer.id, report.issuer.name ?? null) : null
  const payload = p.input.kind === 'jwt' ? p.input.token
    : p.input.kind === 'json' ? JSON.stringify(p.input.doc)
    : JSON.stringify(p.input.meta ?? {})
  const alignmentJson = report.alignments && report.alignments.length ? JSON.stringify(report.alignments) : null
  const id = crypto.randomUUID()
  await db.batch([
    db.prepare(
      `INSERT INTO records (id, wallet_id, data_type, payload, source_type, issuer_id, alignment_json)
       VALUES (?, ?, 'credential', ?, ?, ?, ?)`,
    ).bind(id, p.walletId, payload, p.sourceType, issuerId, alignmentJson),
    db.prepare(`INSERT INTO record_events (id, record_id, event, actor) VALUES (?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), id, p.sourceType === 'issued' ? 'issued' : 'imported', p.actor),
  ])
  return { id, report }
}
