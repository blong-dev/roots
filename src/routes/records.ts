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
import { anchorRecord } from '../anchor'
import { activeWriteGrant, logAccess } from '../grants'
import { resolveKek, getWalletDataKey, openPayload } from '../wallet-crypto'
import { lookupDataType } from '../data-types'

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
  // Fail-closed: the registry is authoritative. Records go to POST /records; VCs
  // to POST /credentials.
  const entry = lookupDataType(dataType)
  if (!entry || entry.kind !== 'record') {
    return c.json({ error: `unknown or non-record data_type '${dataType}' (see GET /data-types)` }, 400)
  }
  if (b?.payload === undefined || b?.payload === null) return c.json({ error: 'payload required' }, 400)
  const consumer = c.get('reader') ?? 'consumer'
  if (!(await activeWriteGrant(c.env.DB, walletId, consumer, dataType))) {
    return c.json({ error: 'no live write grant for this consumer + wallet + data_type' }, 403)
  }
  // Encrypt at rest only when the type is PII (registry-derived).
  let dataKeyB64: string | undefined
  if (entry.encrypted) {
    const kek = await resolveKek(c.env)
    if (!kek) return c.json({ error: 'record encryption unavailable (ROOTS_KEK not provisioned)' }, 503)
    dataKeyB64 = await getWalletDataKey(c.env.DB, kek, walletId)
  }
  const sourceType = b.source_type === 'tool' ? 'tool' : 'self'
  const { id } = await writeSelfRecord(c.env.DB, {
    walletId, dataType, payload: b.payload, sourceType, sourceRef: b.source_ref ?? null, actor: consumer, encrypt: entry.encrypted, dataKeyB64,
  })
  c.executionCtx.waitUntil(anchorRecord(c.env, c.env.DB, id))
  return c.json({ ok: true, id, data_type: dataType, source_type: sourceType, encrypted: entry.encrypted })
})

// ---------------------------------------------------------------- credential write
// guid:roots-records-credential
records.post('/:id/credentials', consumerAuth, requireScope('credentials:import'), async (c) => {
  const walletId = c.req.param('id')!
  if (!(await walletExists(c.env.DB, walletId))) return c.json({ error: 'wallet not found' }, 404)
  const body = await c.req.json<{ kind?: string; doc?: unknown; token?: string; meta?: unknown; source_type?: string; data_type?: string; source_ref?: string }>().catch(() => null)
  const input = body && toExternalInput(body)
  if (!input) return c.json({ error: 'provide a credential ({doc}/{token}/{manual meta})' }, 400)
  const dataType = body?.data_type?.trim() || 'dt.attestation@1'
  const entry = lookupDataType(dataType)
  if (!entry || entry.kind !== 'credential') {
    return c.json({ error: `unknown or non-credential data_type '${dataType}' (see GET /data-types)` }, 400)
  }
  const consumer = c.get('reader') ?? 'issuer'
  if (!(await activeWriteGrant(c.env.DB, walletId, consumer, dataType))) {
    return c.json({ error: 'no live write grant for this consumer + wallet' }, 403)
  }
  const kek = await resolveKek(c.env)
  if (!kek) return c.json({ error: 'record encryption unavailable (ROOTS_KEK not provisioned)' }, 503)
  const dataKeyB64 = await getWalletDataKey(c.env.DB, kek, walletId)
  const sourceType = body?.source_type === 'issued' ? 'issued' : 'imported'
  const { id, report } = await writeCredentialRecord(c.env.DB, {
    walletId, dataType, input, sourceType, actor: consumer, dataKeyB64, sourceRef: body?.source_ref?.trim() || null,
  })
  c.executionCtx.waitUntil(anchorRecord(c.env, c.env.DB, id))
  // tier is a reading — returned for convenience, never stored.
  return c.json({ ok: true, id, tier: report.tier, issuer: report.issuer ?? null, alignments: report.alignments ?? [] })
})

// Decrypt a record's stored payload for an authorized (holder) reader. Returns
// null only if the record is encrypted and the KEK is unavailable.
async function plaintextPayload(c: Context<Env>, walletId: string, rec: Record<string, unknown>): Promise<string | null> {
  const stored = String(rec.payload ?? '')
  if (!rec.encrypted) return stored
  const kek = await resolveKek(c.env)
  if (!kek) return null
  const dataKey = await getWalletDataKey(c.env.DB, kek, walletId)
  return await openPayload(dataKey, stored)
}

// ---------------------------------------------------------------- verify (tier reading)
// guid:roots-records-verify
records.get('/:id/records/:rid/verify', delegatedHolderAuth, async (c) => {
  const walletId = c.req.param('id')!
  const rec = await loadRecord(c.env.DB, walletId, c.req.param('rid')!)
  if (!rec) return c.json({ error: 'not found' }, 404)
  const pt = await plaintextPayload(c, walletId, rec)
  if (pt === null) return c.json({ error: 'record decryption unavailable (ROOTS_KEK not provisioned)' }, 503)
  const p = pt.trim()
  let input: ExternalInput
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(p)) input = { kind: 'jwt', token: p }
  else { try { input = { kind: 'json', doc: JSON.parse(p) } } catch { return c.json({ error: 'record payload is not a verifiable credential' }, 400) } }
  const report = await verifyExternal(input, c.env.DB)
  await logAccess(c.env.DB, {
    walletId, reader: c.get('holder') ?? 'operator',
    dataType: String(rec.data_type), purpose: 'verify', outcome: 'allowed',
  })
  return c.json({ id: rec.id, report })
})

// ---------------------------------------------------------------- lifecycle (owner)
// guid:roots-records-retract
records.post('/:id/records/:rid/retract', delegatedHolderAuth, (c) => transition(c, 'retracted'))
// guid:roots-records-reinstate
records.post('/:id/records/:rid/reinstate', delegatedHolderAuth, (c) => transition(c, 'reinstated'))

// ---------------------------------------------------------------- lifecycle (contributor)
// An attester may withdraw (or reinstate) ITS OWN attestation — append-only, the
// actor recorded as the consumer. It cannot touch another contributor's records;
// the holder's own retract (above) covers everything.
// guid:roots-records-retract-contribution
records.post('/:id/records/:rid/retract-contribution', consumerAuth, requireScope('credentials:retract'), (c) => contributorTransition(c, 'retracted'))
// guid:roots-records-reinstate-contribution
records.post('/:id/records/:rid/reinstate-contribution', consumerAuth, requireScope('credentials:retract'), (c) => contributorTransition(c, 'reinstated'))

// guid:roots-records-contributorTransition
async function contributorTransition(c: Context<Env>, event: 'retracted' | 'reinstated'): Promise<Response> {
  const walletId = c.req.param('id')!
  const rid = c.req.param('rid')!
  const consumer = c.get('reader')!
  const rec = await loadRecord(c.env.DB, walletId, rid)
  if (!rec) return c.json({ error: 'not found' }, 404)
  if (rec.contributor !== consumer) return c.json({ error: 'not your contribution' }, 403)
  const from = event === 'retracted' ? 'active' : 'retracted'
  const to = event === 'retracted' ? 'retracted' : 'active'
  if (rec.state !== from) return c.json({ error: `record is already ${rec.state}` }, 409)
  const b = await c.req.json<{ reason?: string }>().catch(() => null)
  const reason = typeof b?.reason === 'string' ? b.reason.slice(0, 500) : null
  await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE records SET state = ?, updated_at = datetime('now') WHERE id = ? AND wallet_id = ?`)
      .bind(to, rid, walletId),
    c.env.DB.prepare(`INSERT INTO record_events (id, record_id, event, reason, actor) VALUES (?, ?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), rid, event, reason, consumer),
  ])
  return c.json({ ok: true, id: rid, state: to, event, actor: consumer })
}

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
  const walletId = c.req.param('id')!
  const rec = await loadRecord(c.env.DB, walletId, c.req.param('rid')!)
  if (!rec) return c.json({ error: 'not found' }, 404)
  const pt = await plaintextPayload(c, walletId, rec)
  if (pt === null) return c.json({ error: 'record decryption unavailable (ROOTS_KEK not provisioned)' }, 503)
  // A single-record plaintext read — logged so operator break-glass and
  // holder reads alike appear in the owner's access log (audit F2).
  await logAccess(c.env.DB, {
    walletId, reader: c.get('holder') ?? 'operator',
    dataType: String(rec.data_type), purpose: 'read', outcome: 'allowed',
  })
  return c.json({ record: { ...rec, payload: pt } })
})

// ---------------------------------------------------------------- contributions (mounted at /contributions)
// Contributor-addressed record access: a consumer reaches ITS OWN contribution by
// source_ref alone (unique per contributor by construction), with no wallet id in
// hand — the Stage-4 path where the consumer keeps no local mirror. Ambiguity
// (same ref reused across wallets) is a 409, never a guess.
export const contributions = new Hono<Env>()

// guid:roots-contributions-load
async function loadContribution(c: Context<Env>): Promise<{ rec?: Record<string, unknown>; err?: Response }> {
  const ref = c.req.param('ref')!
  const consumer = c.get('reader')!
  const { results } = await c.env.DB.prepare(
    'SELECT id, wallet_id, data_type, state, contributor FROM records WHERE contributor = ? AND source_ref = ? LIMIT 2',
  ).bind(consumer, ref).all<Record<string, unknown>>()
  if (results.length === 0) return { err: c.json({ error: 'no contribution with that source_ref' }, 404) }
  if (results.length > 1) return { err: c.json({ error: 'ambiguous source_ref (multiple contributions)' }, 409) }
  return { rec: results[0] }
}

// guid:roots-contributions-get
contributions.get('/:ref', consumerAuth, requireScope('credentials:read'), async (c) => {
  const { rec, err } = await loadContribution(c)
  if (err) return err
  return c.json({ id: rec!.id, wallet_id: rec!.wallet_id, data_type: rec!.data_type, state: rec!.state })
})

// guid:roots-contributions-transition
async function contributionLifecycle(c: Context<Env>, event: 'retracted' | 'reinstated'): Promise<Response> {
  const { rec, err } = await loadContribution(c)
  if (err) return err
  const from = event === 'retracted' ? 'active' : 'retracted'
  const to = event === 'retracted' ? 'retracted' : 'active'
  if (rec!.state !== from) return c.json({ error: `record is already ${rec!.state}` }, 409)
  const b = await c.req.json<{ reason?: string }>().catch(() => null)
  const reason = typeof b?.reason === 'string' ? b.reason.slice(0, 500) : null
  await c.env.DB.batch([
    c.env.DB.prepare(`UPDATE records SET state = ?, updated_at = datetime('now') WHERE id = ?`).bind(to, rec!.id),
    c.env.DB.prepare(`INSERT INTO record_events (id, record_id, event, reason, actor) VALUES (?, ?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), rec!.id, event, reason, c.get('reader')!),
  ])
  return c.json({ ok: true, id: rec!.id, wallet_id: rec!.wallet_id, state: to, event })
}

// guid:roots-contributions-retract
contributions.post('/:ref/retract', consumerAuth, requireScope('credentials:retract'), (c) => contributionLifecycle(c, 'retracted'))
// guid:roots-contributions-reinstate
contributions.post('/:ref/reinstate', consumerAuth, requireScope('credentials:retract'), (c) => contributionLifecycle(c, 'reinstated'))

export default records
