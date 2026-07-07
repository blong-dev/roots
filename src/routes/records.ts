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
import { dbFirst } from '../db'
import { verifyExternal, type ExternalInput } from '../credentials/verify-external'
import { walletExists, toExternalInput, writeSelfRecord, writeCredentialRecord } from '../records-core'
import { activeWriteGrant } from '../grants'

const records = new Hono<Env>()

// guid:roots-records-loadRecord
async function loadRecord(db: D1Database, walletId: string, rid: string): Promise<Record<string, unknown> | null> {
  return await dbFirst<Record<string, unknown>>(
    db, 'SELECT * FROM records WHERE id = ? AND wallet_id = ?', rid, walletId,
  )
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
  const consumer = c.get('reader') ?? 'consumer'
  if (!(await activeWriteGrant(c.env.DB, walletId, consumer, dataType))) {
    return c.json({ error: 'no live write grant for this consumer + wallet + data_type' }, 403)
  }
  const sourceType = b.source_type === 'tool' ? 'tool' : 'self'
  const { id } = await writeSelfRecord(c.env.DB, {
    walletId, dataType, payload: b.payload, sourceType, sourceRef: b.source_ref ?? null, actor: consumer,
  })
  return c.json({ ok: true, id, data_type: dataType, source_type: sourceType })
})

// ---------------------------------------------------------------- credential write
// guid:roots-records-credential
records.post('/:id/credentials', consumerAuth, requireScope('credentials:import'), async (c) => {
  const walletId = c.req.param('id')!
  if (!(await walletExists(c.env.DB, walletId))) return c.json({ error: 'wallet not found' }, 404)
  const body = await c.req.json<{ kind?: string; doc?: unknown; token?: string; meta?: unknown; source_type?: string }>().catch(() => null)
  const input = body && toExternalInput(body)
  if (!input) return c.json({ error: 'provide a credential ({doc}/{token}/{manual meta})' }, 400)
  const consumer = c.get('reader') ?? 'issuer'
  if (!(await activeWriteGrant(c.env.DB, walletId, consumer, 'credential'))) {
    return c.json({ error: 'no live write grant for this consumer + wallet' }, 403)
  }
  const sourceType = body?.source_type === 'issued' ? 'issued' : 'imported'
  const { id, report } = await writeCredentialRecord(c.env.DB, {
    walletId, input, sourceType, actor: consumer,
  })
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
