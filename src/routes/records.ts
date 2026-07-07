/**
 * routes/records.ts — writes + credential intake + lifecycle, mounted at /w.
 *
 *   POST /w/:id/records                 self/tool typed record (no signature)
 *   POST /w/:id/credentials             an issuer writes a VC (verified on intake)
 *   GET  /w/:id/records/:rid/verify     recompute the honest tier over the stored VC
 *   POST /w/:id/records/:rid/retract    append-only retract (owner)
 *   POST /w/:id/records/:rid/reinstate  append-only reinstate (owner)
 *   GET  /w/:id/records/:rid/history    the audit chain (owner)
 *   GET  /w/:id/records/:rid            record detail (owner)
 *
 * Writes are consumer-authed (credentials:import — the interim write scope;
 * records:write lands in the scope rename). Lifecycle + detail use
 * delegatedHolderAuth (per-user; operator break-glass). The verification TIER is
 * never stored — it is recomputed as a reading over the stored VC + registry.
 */
import { Hono, type Context } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import type { Env } from '../auth'
import { consumerAuth, delegatedHolderAuth, requireScope } from '../auth'
import { dbFirst, dbRun } from '../db'
import { verifyExternal, type ExternalInput, type ManualMeta } from '../credentials/verify-external'

const records = new Hono<Env>()

// guid:roots-records-walletExists
async function walletExists(db: D1Database, id: string): Promise<boolean> {
  return !!(await dbFirst<{ id: string }>(db, 'SELECT id FROM wallets WHERE id = ?', id))
}

// guid:roots-records-loadRecord
async function loadRecord(db: D1Database, walletId: string, rid: string): Promise<Record<string, unknown> | null> {
  return await dbFirst<Record<string, unknown>>(
    db, 'SELECT * FROM records WHERE id = ? AND wallet_id = ?', rid, walletId,
  )
}

// guid:roots-records-toInput  (lifted from Telekora wallet.ts)
function toInput(body: { kind?: string; doc?: unknown; token?: string; meta?: unknown }): ExternalInput | null {
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

// guid:roots-records-upsertIssuer — seen issuers land in the registry as 'known'
async function upsertIssuer(db: D1Database, didOrIss: string, name: string | null): Promise<string> {
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

// ---------------------------------------------------------------- self/tool write
// guid:roots-records-write
records.post('/:id/records', consumerAuth, requireScope('credentials:import'), async (c) => {
  const walletId = c.req.param('id')!
  if (!(await walletExists(c.env.DB, walletId))) return c.json({ error: 'wallet not found' }, 404)
  const b = await c.req.json<{ data_type?: string; payload?: unknown; source_type?: string; source_ref?: string }>().catch(() => null)
  const dataType = b?.data_type?.trim()
  if (!dataType) return c.json({ error: 'data_type required' }, 400)
  if (b?.payload === undefined || b?.payload === null) return c.json({ error: 'payload required' }, 400)
  const sourceType = b.source_type === 'tool' ? 'tool' : 'self'
  const payload = typeof b.payload === 'string' ? b.payload : JSON.stringify(b.payload)
  const id = crypto.randomUUID()
  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO records (id, wallet_id, data_type, payload, source_type, source_ref)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(id, walletId, dataType, payload, sourceType, b.source_ref ?? null),
    c.env.DB.prepare(
      `INSERT INTO record_events (id, record_id, event, actor) VALUES (?, ?, 'created', ?)`,
    ).bind(crypto.randomUUID(), id, c.get('reader') ?? 'consumer'),
  ])
  return c.json({ ok: true, id, data_type: dataType, source_type: sourceType })
})

// ---------------------------------------------------------------- credential write
// guid:roots-records-credential
records.post('/:id/credentials', consumerAuth, requireScope('credentials:import'), async (c) => {
  const walletId = c.req.param('id')!
  if (!(await walletExists(c.env.DB, walletId))) return c.json({ error: 'wallet not found' }, 404)
  const body = await c.req.json<{ kind?: string; doc?: unknown; token?: string; meta?: unknown; source_type?: string }>().catch(() => null)
  const input = body && toInput(body)
  if (!input) return c.json({ error: 'provide a credential ({doc}/{token}/{manual meta})' }, 400)

  const report = await verifyExternal(input, c.env.DB)
  const issuerId = report.issuer?.id ? await upsertIssuer(c.env.DB, report.issuer.id, report.issuer.name ?? null) : null
  const sourceType = body?.source_type === 'issued' ? 'issued' : 'imported'
  const payload = input.kind === 'jwt' ? input.token
    : input.kind === 'json' ? JSON.stringify(input.doc)
    : JSON.stringify(input.meta ?? {})
  const alignmentJson = report.alignments && report.alignments.length ? JSON.stringify(report.alignments) : null
  const id = crypto.randomUUID()
  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO records (id, wallet_id, data_type, payload, source_type, issuer_id, alignment_json)
       VALUES (?, ?, 'credential', ?, ?, ?, ?)`,
    ).bind(id, walletId, payload, sourceType, issuerId, alignmentJson),
    c.env.DB.prepare(
      `INSERT INTO record_events (id, record_id, event, actor) VALUES (?, ?, ?, ?)`,
    ).bind(crypto.randomUUID(), id, sourceType === 'issued' ? 'issued' : 'imported', c.get('reader') ?? 'issuer'),
  ])
  // tier is a reading — returned for convenience, never stored.
  return c.json({ ok: true, id, tier: report.tier, issuer: report.issuer ?? null, alignments: report.alignments ?? [] })
})

// ---------------------------------------------------------------- verify (tier reading)
// guid:roots-records-verify
records.get('/:id/records/:rid/verify', delegatedHolderAuth, async (c) => {
  const rec = await loadRecord(c.env.DB, c.req.param('id')!, c.req.param('rid')!)
  if (!rec) return c.json({ error: 'not found' }, 404)
  const p = String(rec.payload ?? '').trim()
  let input: ExternalInput
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(p)) input = { kind: 'jwt', token: p }
  else { try { input = { kind: 'json', doc: JSON.parse(p) } } catch { return c.json({ error: 'record payload is not a verifiable credential' }, 400) } }
  const report = await verifyExternal(input, c.env.DB)
  return c.json({ id: rec.id, report })
})

// ---------------------------------------------------------------- lifecycle (owner)
// guid:roots-records-retract
records.post('/:id/records/:rid/retract', delegatedHolderAuth, (c) => transition(c, 'retracted'))
// guid:roots-records-reinstate
records.post('/:id/records/:rid/reinstate', delegatedHolderAuth, (c) => transition(c, 'reinstated'))

// guid:roots-records-transition — a mis-written record is never deleted; it is
// retracted by APPENDING an event and flipping the materialized state.
async function transition(c: Context<Env>, event: 'retracted' | 'reinstated'): Promise<Response> {
  const walletId = c.req.param('id')!
  const rid = c.req.param('rid')!
  const rec = await loadRecord(c.env.DB, walletId, rid)
  if (!rec) return c.json({ error: 'not found' }, 404)
  const from = event === 'retracted' ? 'active' : 'retracted'
  const to = event === 'retracted' ? 'retracted' : 'active'
  if (rec.state !== from) return c.json({ error: `record is already ${rec.state}` }, 409)
  const b = await c.req.json<{ reason?: string }>().catch(() => null)
  const reason = typeof b?.reason === 'string' ? b.reason.slice(0, 500) : null
  await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE records SET state = ?, updated_at = datetime('now') WHERE id = ? AND wallet_id = ?`)
      .bind(to, rid, walletId),
    c.env.DB.prepare(`INSERT INTO record_events (id, record_id, event, reason, actor) VALUES (?, ?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), rid, event, reason, c.get('holder') ?? 'operator'),
  ])
  return c.json({ ok: true, id: rid, state: to, event })
}

// guid:roots-records-history
records.get('/:id/records/:rid/history', delegatedHolderAuth, async (c) => {
  const rec = await loadRecord(c.env.DB, c.req.param('id')!, c.req.param('rid')!)
  if (!rec) return c.json({ error: 'not found' }, 404)
  const { results } = await c.env.DB.prepare(
    `SELECT event, reason, actor, created_at FROM record_events WHERE record_id = ? ORDER BY created_at`,
  ).bind(rec.id).all()
  return c.json({ id: rec.id, state: rec.state, events: results })
})

// guid:roots-records-detail
records.get('/:id/records/:rid', delegatedHolderAuth, async (c) => {
  const rec = await loadRecord(c.env.DB, c.req.param('id')!, c.req.param('rid')!)
  if (!rec) return c.json({ error: 'not found' }, 404)
  return c.json({ record: rec })
})

export default records
