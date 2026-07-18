/**
 * routes/admin.ts — operator-only key management, mounted at /admin.
 *
 *   POST /admin/kek/rotate   re-wrap every KEK-encrypted secret old KEK → new KEK
 *
 * KEK rotation recovers from a suspected KEK compromise without re-issuing keys.
 * Procedure: provision ROOTS_KEK_NEXT (a fresh 32-byte key) alongside the current
 * ROOTS_KEK, POST here to re-wrap all secrets under it, verify, then swap
 * ROOTS_KEK := ROOTS_KEK_NEXT and remove ROOTS_KEK_NEXT. (Separately: the KEK must
 * be BACKED UP out-of-band — losing it is unrecoverable. See deploy-readiness.md.)
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { operatorAuth } from '../auth'
import { resolveKek } from '../wallet-crypto'
import { decryptSecret, encryptSecret } from '../crypto'
import { anchorSweep, MAX_ANCHOR_ATTEMPTS } from '../anchor'

const admin = new Hono<Env>()

// guid:roots-admin-anchor-backfill
// Anchor un-anchored active records on demand (backfill / retry failures).
// Bounded per call; poll until { swept: 0 }. The cron does this automatically,
// but this gives the operator a controllable trigger.
//
// ?reset=1 first clears anchor_attempts on capped-out failed rows, so records
// the sweep gave up on (attempts >= MAX_ANCHOR_ATTEMPTS) retry once the
// underlying anchord problem is fixed. Without it, backfill only touches rows
// still under the cap — same set the cron already sweeps.
admin.post('/anchor/backfill', operatorAuth, async (c) => {
  const q = Number(c.req.query('limit') ?? '25')
  let reset = 0
  if (c.req.query('reset') === '1') {
    const r = await c.env.DB.prepare(
      `UPDATE records SET anchor_attempts = 0
        WHERE state = 'active' AND anchor_state = 'failed' AND anchor_attempts >= ?`,
    ).bind(MAX_ANCHOR_ATTEMPTS).run()
    reset = r.meta.changes ?? 0
  }
  const swept = await anchorSweep(c.env, c.env.DB, Number.isFinite(q) && q > 0 ? Math.min(q, 50) : 25)
  return c.json({ swept, reset })
})

async function resolveNextKek(env: Env['Bindings']): Promise<string | null> {
  return typeof env.ROOTS_KEK_NEXT === 'string' ? env.ROOTS_KEK_NEXT : (await env.ROOTS_KEK_NEXT?.get()) ?? null
}

// guid:roots-admin-kek-rotate
admin.post('/kek/rotate', operatorAuth, async (c) => {
  const oldKek = await resolveKek(c.env)
  const newKek = await resolveNextKek(c.env)
  if (!oldKek || !newKek) return c.json({ error: 'ROOTS_KEK and ROOTS_KEK_NEXT must both be provisioned' }, 400)
  if (oldKek === newKek) return c.json({ error: 'ROOTS_KEK_NEXT must differ from ROOTS_KEK' }, 400)

  // Table/column names are fixed constants (not user input) — safe to inline.
  // Resumable: a row that no longer decrypts under the old KEK is skipped (it was
  // already re-wrapped), so a re-run after a partial failure completes cleanly.
  const rewrap = async (table: string, idCol: string, ctCol: string, ivCol: string): Promise<{ rewrapped: number; skipped: number }> => {
    const { results } = await c.env.DB.prepare(
      `SELECT ${idCol} AS id, ${ctCol} AS ct, ${ivCol} AS iv FROM ${table}`,
    ).all<{ id: string; ct: string; iv: string }>()
    let rewrapped = 0, skipped = 0
    for (const r of results) {
      let plain: string
      try { plain = await decryptSecret(oldKek, r.ct, r.iv) }
      catch { skipped++; continue } // already under the new KEK (or unreadable) — leave it
      const w = await encryptSecret(newKek, plain)
      await c.env.DB.prepare(`UPDATE ${table} SET ${ctCol} = ?, ${ivCol} = ? WHERE ${idCol} = ?`)
        .bind(w.ciphertext, w.iv, r.id).run()
      rewrapped++
    }
    return { rewrapped, skipped }
  }

  const issuer_keys = await rewrap('issuer_keys', 'tenant_id', 'encrypted_private_jwk', 'encryption_iv')
  const receiver_keys = await rewrap('receiver_keys', 'user_id', 'encrypted_private_jwk', 'encryption_iv')
  const wallet_data_keys = await rewrap('wallet_data_keys', 'wallet_id', 'enc_key', 'iv')

  return c.json({
    ok: true,
    rewrapped: { issuer_keys, receiver_keys, wallet_data_keys },
    next: 'verify, then set ROOTS_KEK := ROOTS_KEK_NEXT and remove ROOTS_KEK_NEXT',
  })
})

export default admin
