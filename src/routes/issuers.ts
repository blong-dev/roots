/**
 * routes/issuers.ts — the trust registry, mounted at /issuers.
 *
 *   GET  /issuers   list known/trusted/revoked issuers
 *   POST /issuers   curate: promote to 'trusted', mark 'revoked', etc.
 *
 * Curating trust is a platform decision → operator-gated. Issuers seen on a
 * credential write auto-land here as 'known' (which caps the honest tier at
 * valid-signature); only an explicit promotion to 'trusted' yields 'verified'.
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { operatorAuth } from '../auth'

const issuers = new Hono<Env>()

// guid:roots-issuers-list
issuers.get('/', operatorAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT did_or_iss, name, method, status, created_at FROM issuers ORDER BY status, name`,
  ).all()
  return c.json({ issuers: results })
})

// guid:roots-issuers-curate
issuers.post('/', operatorAuth, async (c) => {
  const b = await c.req.json<{ didOrIss?: string; name?: string; method?: string; status?: string }>().catch(() => null)
  const didOrIss = b?.didOrIss?.trim()
  const status = b?.status ?? 'known'
  if (!didOrIss) return c.json({ error: 'didOrIss required' }, 400)
  if (!['trusted', 'known', 'revoked'].includes(status)) {
    return c.json({ error: 'status must be trusted|known|revoked' }, 400)
  }
  await c.env.DB.prepare(
    `INSERT INTO issuers (id, did_or_iss, name, method, status) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(did_or_iss) DO UPDATE SET
       name = excluded.name, method = excluded.method, status = excluded.status`,
  ).bind(crypto.randomUUID(), didOrIss, b?.name ?? null, b?.method ?? null, status).run()
  return c.json({ ok: true, didOrIss, status })
})

export default issuers
