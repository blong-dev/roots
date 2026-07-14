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
import { Hono, type Context } from 'hono'
import type { Env } from '../auth'
import { operatorAuth } from '../auth'
import { resolveKek } from '../wallet-crypto'
import { decryptSecret, encryptSecret } from '../crypto'
import { anchorSweep } from '../anchor'
import { dbFirst } from '../db'
import { getCredentialStatus, setCredentialStatusAudited, type StatusPurpose } from '../credentials/status'
import { generateApiKey, normalizeScopes } from '../apikeys'

const admin = new Hono<Env>()

// ---------------------------------------------------------------- credential status (operator)
// Flip a credential's revocation/suspension bit. The credential id is the roots
// record id (the credential_status primary key). revoke/reinstate touch the
// permanent 'revocation' purpose; suspend/unsuspend the reversible 'suspension'.
// The change lands in the served status list on its next fetch.
// guid:roots-admin-status-mutate
async function mutateStatus(c: Context<Env>, purpose: StatusPurpose, value: boolean): Promise<Response> {
  const credentialId = c.req.param('id')!
  const row = await getCredentialStatus(c.env.DB, credentialId)
  if (!row) return c.json({ error: 'no status slot for that credential id' }, 404)
  const b = await c.req.json<{ reason?: string }>().catch(() => null)
  const reason = typeof b?.reason === 'string' ? b.reason.slice(0, 500) : null
  await setCredentialStatusAudited(c.env.DB, credentialId, row.tenant_id, purpose, value, 'operator', reason)
  return c.json({ ok: true, credential_id: credentialId, purpose, value })
}

// guid:roots-admin-revoke
admin.post('/credentials/:id/revoke', operatorAuth, (c) => mutateStatus(c, 'revocation', true))
// guid:roots-admin-reinstate — clears revocation (a mis-revoke correction).
admin.post('/credentials/:id/reinstate', operatorAuth, (c) => mutateStatus(c, 'revocation', false))
// guid:roots-admin-suspend
admin.post('/credentials/:id/suspend', operatorAuth, (c) => mutateStatus(c, 'suspension', true))
// guid:roots-admin-unsuspend
admin.post('/credentials/:id/unsuspend', operatorAuth, (c) => mutateStatus(c, 'suspension', false))

// ---------------------------------------------------------------- API keys (operator)
// Mint a scoped consumer key. The plaintext (`tk_…`) is returned ONCE and never
// again — only its SHA-256 hash is stored. Losing it means minting a new one.
// guid:roots-admin-keys-mint
admin.post('/keys', operatorAuth, async (c) => {
  const b = await c.req.json<{ tenant_id?: string; name?: string; scopes?: unknown }>().catch(() => null)
  const tenantId = b?.tenant_id?.trim()
  if (!tenantId) return c.json({ error: 'tenant_id required' }, 400)
  const scopes = normalizeScopes(b?.scopes)
  if (scopes.length === 0) return c.json({ error: 'at least one valid scope required (see apikeys.ts ALL_SCOPES)' }, 400)
  const { plaintext, prefix, hash } = await generateApiKey()
  const id = crypto.randomUUID()
  await c.env.DB.prepare(
    `INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, created_by)
     VALUES (?, ?, ?, ?, ?, ?, 'operator')`,
  ).bind(id, tenantId, b?.name ?? null, prefix, hash, scopes.join(',')).run()
  // key is shown exactly once.
  return c.json({ ok: true, id, tenant_id: tenantId, key_prefix: prefix, scopes, key: plaintext }, 201)
})

// guid:roots-admin-keys-list — metadata only; the hash and plaintext are never returned.
admin.get('/keys', operatorAuth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT id, tenant_id, name, key_prefix, scopes, created_at, last_used_at, revoked_at
       FROM api_keys ORDER BY created_at DESC`,
  ).all()
  return c.json({ keys: results })
})

// guid:roots-admin-keys-revoke
admin.post('/keys/:id/revoke', operatorAuth, async (c) => {
  const id = c.req.param('id')!
  const existing = await dbFirst<{ id: string; revoked_at: string | null }>(
    c.env.DB, 'SELECT id, revoked_at FROM api_keys WHERE id = ?', id,
  )
  if (!existing) return c.json({ error: 'api key not found' }, 404)
  if (existing.revoked_at) return c.json({ ok: true, id, already_revoked: true, revoked_at: existing.revoked_at })
  await c.env.DB.prepare("UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ?").bind(id).run()
  return c.json({ ok: true, id, revoked: true })
})

// guid:roots-admin-anchor-backfill
// Anchor un-anchored active records on demand (backfill / retry failures).
// Bounded per call; poll until { swept: 0 }. The cron does this automatically,
// but this gives the operator a controllable trigger.
admin.post('/anchor/backfill', operatorAuth, async (c) => {
  const q = Number(c.req.query('limit') ?? '25')
  const swept = await anchorSweep(c.env, c.env.DB, Number.isFinite(q) && q > 0 ? Math.min(q, 50) : 25)
  return c.json({ swept })
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
