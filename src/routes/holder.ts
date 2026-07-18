/**
 * Holder dashboard API (share-and-verify S2, docs/share-and-verify.md §2).
 *
 * The wallet owner's own surface: list records (metadata — content stays
 * sealed or on-device), register device-vault documents (metadata + file
 * sha256 only; the file itself NEVER reaches us — owner ruling 2026-07-18).
 * Auth = the existing delegatedHolderAuth seam (delegation or operator
 * break-glass); holder login is a pluggable front door for later.
 */
import { Hono } from 'hono'
import type { Bindings } from '../index'
import { delegatedHolderAuth } from '../auth'
import { DATA_TYPES } from '../data-types'
import { writeSelfRecord } from '../records-core'
import { resolveKek, getWalletDataKey } from '../wallet-crypto'

type Env = { Bindings: Bindings }

export const holder = new Hono<Env>()

// Metadata list — the dashboard's View. No payloads: sealed content stays
// sealed; document content lives in the device vault; credential rendering
// goes through the existing verify/export routes.
holder.get('/:id/holder/records', delegatedHolderAuth, async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT r.id, r.data_type, r.state, r.source_type, r.source_ref, r.created_at,
            r.anchor_state, r.seed_id, r.anchor_tx, r.anchor_height,
            i.name AS issuer_name, i.status AS issuer_trust
     FROM records r LEFT JOIN issuers i ON i.id = r.issuer_id
     WHERE r.wallet_id = ? ORDER BY r.created_at DESC LIMIT 500`,
  ).bind(c.req.param('id')).all()
  return c.json({ records: rows.results ?? [] })
})

// Register a device-vault document: metadata + the PLAINTEXT file's sha256.
// The blob never arrives here. The record anchors like any other (cron sweep).
holder.post('/:id/documents', delegatedHolderAuth, async (c) => {
  const walletId = c.req.param('id')!
  const body = await c.req.json().catch(() => null) as
    | { filename?: string; size?: number; mime?: string; sha256?: string; note?: string }
    | null
  if (!body?.filename || !body?.sha256 || !/^[0-9a-f]{64}$/.test(body.sha256))
    return c.json({ error: 'filename and sha256 (64-hex of the plaintext file) required' }, 400)

  const dataType = 'dt.document.file@1'
  const entry = DATA_TYPES[dataType]
  if (!entry) return c.json({ error: 'document type not registered' }, 500)

  const kek = await resolveKek(c.env)
  if (!kek) return c.json({ error: 'KEK unavailable' }, 503)
  const dataKey = await getWalletDataKey(c.env.DB, kek, walletId)

  const { id } = await writeSelfRecord(c.env.DB, {
    walletId,
    dataType,
    payload: {
      filename: body.filename.slice(0, 300),
      size: Number(body.size ?? 0),
      mime: String(body.mime ?? 'application/octet-stream').slice(0, 100),
      sha256: body.sha256,
      note: body.note ? String(body.note).slice(0, 500) : undefined,
      storage: 'device-vault',
    },
    sourceType: 'self',
    sourceRef: `sha256:${body.sha256}`,
    actor: String(c.get('holder' as never) ?? 'holder'),
    encrypt: entry.encrypted,
    dataKeyB64: dataKey,
  })
  return c.json({
    id,
    data_type: dataType,
    anchor_state: 'pending',
    note: 'metadata recorded; the file stays on your device. Anchoring is asynchronous (~2 min).',
  }, 201)
})
