/**
 * Share-and-verify (S1, docs/share-and-verify.md): holder-minted, revocable,
 * expiring share tokens; a public verdict page that shows VALIDITY without
 * content ("start with secure sharing, push legal towards just validation").
 *
 * S1 ships `validity` mode only. `read` mode (grant-gated content) is S2 —
 * the mint API already accepts the mode so S2 is additive.
 */
import { Hono } from 'hono'
import type { Bindings } from '../index'
import { delegatedHolderAuth } from '../auth'
import { recordCommitment, walletDid } from '../anchor'
import { resolveKek, getWalletDataKey, openPayload } from '../wallet-crypto'

type Env = { Bindings: Bindings }

const DAY_S = 86400
const DEFAULT_TTL_S = 7 * DAY_S
const MAX_TTL_S = 90 * DAY_S

function newToken(): string {
  const b = crypto.getRandomValues(new Uint8Array(16))
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

// ---- holder surface (wallet-scoped; delegation or operator break-glass) ----

export const shareMint = new Hono<Env>()

shareMint.post('/:id/shares', delegatedHolderAuth, async (c) => {
  const walletId = c.req.param('id')
  const body = await c.req.json().catch(() => null) as
    | { record_id?: string; mode?: string; expires_in_s?: number; max_uses?: number }
    | null
  if (!body?.record_id) return c.json({ error: 'record_id required' }, 400)
  const mode = body.mode ?? 'validity'
  if (mode !== 'validity' && mode !== 'read')
    return c.json({ error: "mode must be 'validity' or 'read'" }, 400)
  const ttl = Math.min(Math.max(Number(body.expires_in_s ?? DEFAULT_TTL_S), 60), MAX_TTL_S)
  const maxUses = body.max_uses != null ? Math.max(1, Number(body.max_uses)) : null

  const rec = await c.env.DB.prepare(
    'SELECT id FROM records WHERE id = ? AND wallet_id = ?',
  ).bind(body.record_id, walletId).first<{ id: string }>()
  if (!rec) return c.json({ error: 'record not found in this wallet' }, 404)

  const token = newToken()
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString()
  await c.env.DB.prepare(
    `INSERT INTO share_tokens (token, wallet_id, record_id, mode, created_by, expires_at, max_uses)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(token, walletId, body.record_id, mode, String(c.get('holder' as never) ?? 'holder'), expiresAt, maxUses).run()

  const base = new URL(c.req.url).origin
  return c.json({
    token,
    url: `${base}/s/${token}`,
    mode,
    expires_at: expiresAt,
    max_uses: maxUses,
    revocable: 'DELETE /w/{wallet}/shares/{token} — revocation lands on next open',
  }, 201)
})

shareMint.delete('/:id/shares/:token', delegatedHolderAuth, async (c) => {
  const r = await c.env.DB.prepare(
    `UPDATE share_tokens SET revoked_at = datetime('now')
     WHERE token = ? AND wallet_id = ? AND revoked_at IS NULL`,
  ).bind(c.req.param('token'), c.req.param('id')).run()
  const changed = (r as { meta?: { changes?: number } }).meta?.changes ?? 0
  return changed ? c.json({ revoked: true }) : c.json({ error: 'unknown or already revoked' }, 404)
})

shareMint.get('/:id/shares', delegatedHolderAuth, async (c) => {
  const rows = await c.env.DB.prepare(
    `SELECT token, record_id, mode, created_at, expires_at, max_uses, use_count, revoked_at
     FROM share_tokens WHERE wallet_id = ? ORDER BY created_at DESC LIMIT 100`,
  ).bind(c.req.param('id')).all()
  return c.json({ shares: rows.results ?? [] })
})

// ---- public verdict surface ------------------------------------------------

export const sharePublic = new Hono<Env>()

interface Verdict {
  share_status: 'valid' | 'revoked' | 'expired' | 'exhausted' | 'unknown'
  mode?: string
  content?: unknown
  content_error?: string
  record?: {
    exists: true
    state: string
    data_type: string
    kind: string
    issued_at: string
    issuer: { name: string | null; did: string | null; trust: string | null } | null
    holder_did: string
    commitment_sha256: string
    anchor: {
      state: string
      chain_id: string
      seed_id: number | null
      tx: string | null
      height: number | null
    }
    retracted: boolean
  }
  disclosure: string
}

async function buildVerdict(c: { env: Bindings }, token: string): Promise<{ code: number; v: Verdict }> {
  const s = await c.env.DB.prepare(
    `SELECT st.*, r.state AS r_state, r.data_type, r.payload, r.encrypted, r.created_at AS r_created,
            r.seed_id, r.anchor_tx, r.anchor_height, r.anchor_state,
            i.name AS issuer_name, i.did_or_iss AS issuer_did, i.status AS issuer_trust
     FROM share_tokens st
     JOIN records r ON r.id = st.record_id
     LEFT JOIN issuers i ON i.id = r.issuer_id
     WHERE st.token = ?`,
  ).bind(token).first<Record<string, unknown>>()
  const gone = (status: Verdict['share_status'], code = 410): { code: number; v: Verdict } => ({
    code,
    v: { share_status: status, disclosure: 'No record information is disclosed for an inactive share.' },
  })
  if (!s) return gone('unknown', 404)
  if (s.revoked_at) return gone('revoked')
  if (Date.parse(String(s.expires_at)) < Date.now()) return gone('expired')
  if (s.max_uses != null && Number(s.use_count) >= Number(s.max_uses)) return gone('exhausted')

  // Count the use + write the holder-visible audit entry.
  await c.env.DB.prepare('UPDATE share_tokens SET use_count = use_count + 1 WHERE token = ?').bind(token).run()
  await c.env.DB.prepare(
    `INSERT INTO access_log (id, wallet_id, reader, data_type, purpose, outcome)
     VALUES (?, ?, ?, ?, ?, 'allowed')`,
  ).bind(crypto.randomUUID(), s.wallet_id, `share:${token.slice(0, 8)}…`, s.data_type, `share:${String(s.mode)}`).run()

  const commitment = await recordCommitment(String(s.record_id), String(s.data_type), String(s.payload))
  const out: { code: number; v: Verdict } = {
    code: 200,
    v: {
      share_status: 'valid',
      mode: String(s.mode),
      record: {
        exists: true,
        state: String(s.r_state),
        data_type: String(s.data_type),
        kind: String(s.data_type).includes('credential') ? 'credential' : 'record',
        issued_at: String(s.r_created),
        issuer: s.issuer_did
          ? { name: (s.issuer_name as string) ?? null, did: String(s.issuer_did), trust: (s.issuer_trust as string) ?? null }
          : null,
        holder_did: walletDid(String(s.wallet_id)),
        commitment_sha256: commitment,
        anchor: {
          state: String(s.anchor_state ?? 'pending'),
          chain_id: 'dreamtree',
          seed_id: (s.seed_id as number) ?? null,
          tx: (s.anchor_tx as string) ?? null,
          height: (s.anchor_height as number) ?? null,
        },
        retracted: s.r_state === 'retracted',
      },
      disclosure:
        String(s.mode) === 'read'
          ? 'Read view: the holder chose to share this record’s CONTENT with whoever holds this link, revocably. Each open is logged to the holder’s wallet audit trail.'
          : 'Validity view: this page discloses that the record exists, its type, issuer, dates, revocation state, and its on-chain anchor — never its content. Each open is logged to the holder’s wallet audit trail.',
    },
  }
  // Read mode (S3): decrypt-at-read through the wallet data key — the share
  // token IS the capability (holder-minted, expiring, revocable, audited).
  if (String(s.mode) === 'read') {
    try {
      let content = String(s.payload)
      if (Number(s.encrypted) === 1) {
        const kek = await resolveKek(c.env)
        if (!kek) throw new Error('KEK unavailable')
        const dataKey = await getWalletDataKey(c.env.DB, kek, String(s.wallet_id))
        content = await openPayload(dataKey, content)
      }
      try { out.v.content = JSON.parse(content) } catch { out.v.content = content }
    } catch {
      out.v.content_error = 'content could not be opened; the validity facts above still hold'
    }
  }
  return out
}

function esc(x: unknown): string {
  return String(x ?? '—').replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`)
}

function renderPage(v: Verdict): string {
  const ok = v.share_status === 'valid' && v.record && v.record.state === 'active'
  const badge = v.share_status !== 'valid'
    ? `share ${v.share_status}`
    : v.record?.retracted ? 'RETRACTED by holder/issuer' : 'VALID'
  const r = v.record
  const row = (k: string, val: string) =>
    `<tr><td style="color:#667;padding:4px 14px 4px 0;white-space:nowrap">${k}</td><td style="font-family:ui-monospace,monospace;word-break:break-all">${val}</td></tr>`
  const contentBlock = v.content !== undefined
    ? '<h2 style="font-size:1rem;margin:1.2rem 0 .3rem">Shared content</h2><pre style="background:#f3f6f4;border:1px solid #dde;border-radius:8px;padding:.8rem;overflow-x:auto;font-size:.82rem">' +
      esc(typeof v.content === 'string' ? v.content : JSON.stringify(v.content, null, 2)) + '</pre>'
    : v.content_error ? '<p style="color:#a33">' + esc(v.content_error) + '</p>' : ''
  const body = r ? `<table style="border-collapse:collapse;margin:1rem 0">${[
    row('status', r.retracted ? 'retracted' : 'active'),
    row('type', esc(r.data_type)),
    row('issuer', r.issuer ? `${esc(r.issuer.name ?? r.issuer.did)} <span style="color:#667">(${esc(r.issuer.trust)})</span>` : 'self / imported'),
    row('holder DID', esc(r.holder_did)),
    row('issued', esc(r.issued_at)),
    row('commitment', esc(r.commitment_sha256)),
    row('anchor', r.anchor.tx
      ? `dreamtree chain · height ${esc(r.anchor.height)} · tx ${esc(r.anchor.tx).slice(0, 16)}… · seed ${esc(r.anchor.seed_id)}`
      : `${esc(r.anchor.state)} (anchoring is asynchronous)`),
  ].join('')}</table>${contentBlock}` : ''
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dreamtree · shared credential check</title>
<body style="font:16px/1.55 system-ui,sans-serif;max-width:680px;margin:8vh auto;padding:0 1.2rem;color:#182028">
<p style="letter-spacing:.14em;color:#667;font-size:.8rem">DREAMTREE VERIFICATION</p>
<h1 style="font-size:1.6rem;margin:.2em 0">${ok ? '✓' : '✗'} ${esc(badge)}</h1>
${body}
<p style="color:#556;font-size:.9rem;border-top:1px solid #dde;padding-top:1rem;margin-top:1.4rem">${esc(v.disclosure)}</p>
<p style="color:#889;font-size:.8rem">machine-readable: append <code>?format=json</code> · protocol: <a href="https://dreamtree.org" style="color:#265">dreamtree.org</a></p>
</body>`
}

// S6: the embeddable badge — a share link wearing a pixel. Light status only:
// does NOT count a use and does NOT log (clicking through to /s/{token} does).
sharePublic.get('/:token/badge.svg', async (c) => {
  const s = await c.env.DB.prepare(
    `SELECT st.revoked_at, st.expires_at, r.state
     FROM share_tokens st JOIN records r ON r.id = st.record_id WHERE st.token = ?`,
  ).bind(c.req.param('token')).first<Record<string, unknown>>()
  let label = 'unknown', color = '#8a958f'
  if (s) {
    if (s.revoked_at) { label = 'revoked'; color = '#a33' }
    else if (Date.parse(String(s.expires_at)) < Date.now()) { label = 'expired'; color = '#a33' }
    else if (s.state === 'retracted') { label = 'retracted'; color = '#a33' }
    else { label = 'verified · dreamtree'; color = '#1d7a55' }
  }
  const w = 26 + label.length * 7
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + (w + 22) + '" height="20" role="img">' +
    '<rect rx="4" width="' + (w + 22) + '" height="20" fill="#182028"/>' +
    '<circle cx="11" cy="10" r="4" fill="' + color + '"/>' +
    '<text x="' + ((w + 44) / 2 - 1) + '" y="14" fill="#fff" font-family="system-ui,sans-serif" font-size="11" text-anchor="middle">' + label + '</text></svg>'
  return c.body(svg, 200, { 'content-type': 'image/svg+xml', 'cache-control': 'public, max-age=300' })
})

sharePublic.get('/:token', async (c) => {
  const { code, v } = await buildVerdict(c, c.req.param('token'))
  if (c.req.query('format') === 'json') {
    return c.json(v, code as 200, { 'access-control-allow-origin': '*' })
  }
  return c.html(renderPage(v), code as 200)
})
