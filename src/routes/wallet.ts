/**
 * routes/wallet.ts — the consent surface, mounted at /w.
 *
 *   GET  /w/:id/records?data_type=&purpose=   consumer read — grant-gated, logged
 *   POST /w/:id/grants                        owner: issue a scoped grant
 *   POST /w/:id/grants/:gid/revoke            owner: revoke (append-only)
 *   GET  /w/:id/grants                        owner: who can read what
 *   GET  /w/:id/access-log                    owner: every read + denied attempt
 *
 * Reads are authorized PER READ against a live grant — never a session. The
 * owner routes use delegatedHolderAuth (a Telekora-signed per-user assertion;
 * operator token only as owner break-glass — see auth.ts).
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { consumerAuth, delegatedHolderAuth, requireScope } from '../auth'
import { activeReadGrant, logAccess } from '../grants'
import { dbFirst, dbRun } from '../db'
import { decryptRecords } from '../wallet-crypto'

const wallet = new Hono<Env>()

// ---------------------------------------------------------------- consumer read
// guid:roots-wallet-read
// records subsume credentials, so the existing `credentials:read` scope gates it.
wallet.get('/:id/records', consumerAuth, requireScope('credentials:read'), async (c) => {
  const walletId = c.req.param('id')! // route guarantees :id
  const reader = c.get('reader')!
  // No blanket reads: the consumer must name exactly what it reads and why.
  const dataType = c.req.query('data_type')
  const purpose = c.req.query('purpose')
  if (!dataType || !purpose) {
    return c.json({ error: 'data_type and purpose are required — reads are scoped, not blanket' }, 400)
  }

  const grant = await activeReadGrant(c.env.DB, walletId, reader, dataType, purpose)
  if (!grant) {
    await logAccess(c.env.DB, { walletId, reader, dataType, purpose, outcome: 'denied' })
    return c.json({ error: 'no live grant for this wallet + data_type + purpose' }, 403)
  }

  // An 'own'-scoped grant reads only what this grantee contributed.
  const ownFilter = grant.scope === 'own' ? 'AND contributor = ?' : ''
  const stmt = c.env.DB.prepare(
    `SELECT id, data_type, payload, encrypted, source_type, source_ref, issuer_id, alignment_json, created_at, updated_at
       FROM records
      WHERE wallet_id = ? AND data_type = ? AND state = 'active' ${ownFilter}
      ORDER BY created_at DESC`,
  )
  const { results } = await (grant.scope === 'own' ? stmt.bind(walletId, dataType, reader) : stmt.bind(walletId, dataType))
    .all<Record<string, unknown>>()

  // Decrypt at-rest payloads for this authorized (granted) consumer.
  const records = await decryptRecords(c.env, walletId, results)
  if (records === null) {
    return c.json({ error: 'record decryption unavailable (ROOTS_KEK not provisioned)' }, 503)
  }
  await logAccess(c.env.DB, { walletId, reader, dataType, purpose, outcome: 'allowed' })
  return c.json({ wallet_id: walletId, data_type: dataType, purpose, records })
})

// ---------------------------------------------------------------- owner: grant
// guid:roots-wallet-grant-create
wallet.post('/:id/grants', delegatedHolderAuth, async (c) => {
  const walletId = c.req.param('id')
  const b = await c.req.json<{ grantee?: string; capability?: string; scope?: string; data_type?: string; purpose?: string }>().catch(() => null)
  const grantee = b?.grantee?.trim()
  const capability = b?.capability === 'write' ? 'write' : 'read'
  const scope = b?.scope === 'own' ? 'own' : 'all'
  const purpose = b?.purpose?.trim() || null
  if (!grantee) return c.json({ error: 'grantee required' }, 400)
  // Cross-contributor ('all') reads are purpose-gated; 'own' reads (your own
  // contributions) are not; writes have no purpose.
  if (capability === 'read' && scope === 'all' && !purpose) {
    return c.json({ error: "purpose required for a cross-contributor ('all') read grant" }, 400)
  }
  const w = await dbFirst<{ id: string }>(c.env.DB, 'SELECT id FROM wallets WHERE id = ?', walletId)
  if (!w) return c.json({ error: 'wallet not found' }, 404)
  const dataType = b?.data_type?.trim() || null
  const storedPurpose = capability === 'write' ? null : purpose
  const id = crypto.randomUUID()
  await dbRun(
    c.env.DB,
    `INSERT INTO grants (id, wallet_id, grantee, capability, scope, data_type, purpose, granted_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    id, walletId, grantee, capability, scope, dataType, storedPurpose, c.get('holder') ?? 'operator',
  )
  return c.json({ ok: true, id, wallet_id: walletId, grantee, capability, scope, data_type: dataType, purpose: storedPurpose })
})

// guid:roots-wallet-grant-revoke — append-only: stamp revoked_at, never delete
wallet.post('/:id/grants/:gid/revoke', delegatedHolderAuth, async (c) => {
  const res = await c.env.DB.prepare(
    `UPDATE grants SET revoked_at = datetime('now')
      WHERE id = ? AND wallet_id = ? AND revoked_at IS NULL`,
  ).bind(c.req.param('gid'), c.req.param('id')).run()
  if (!res.meta.changes) return c.json({ error: 'grant not found or already revoked' }, 404)
  return c.json({ ok: true, id: c.req.param('gid'), revoked: true })
})

// guid:roots-wallet-grant-list
wallet.get('/:id/grants', delegatedHolderAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id, grantee, capability, scope, data_type, purpose, granted_at, revoked_at, granted_by
       FROM grants WHERE wallet_id = ? ORDER BY granted_at DESC`,
  ).bind(c.req.param('id')).all()
  return c.json({ wallet_id: c.req.param('id'), grants: results })
})

// guid:roots-wallet-access-log — the owner's window into every read + denial
wallet.get('/:id/access-log', delegatedHolderAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT reader, data_type, purpose, outcome, at
       FROM access_log WHERE wallet_id = ? ORDER BY at DESC LIMIT 500`,
  ).bind(c.req.param('id')).all()
  return c.json({ wallet_id: c.req.param('id'), access: results })
})

export default wallet
