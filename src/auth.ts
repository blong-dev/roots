/**
 * auth.ts — roots authentication.
 *
 * Two modes:
 *  - consumerAuth: a scoped API key (`tk_…`) identifies the READING service. Its
 *    identity becomes the `reader` on grants + access_log. This is how Telekora
 *    (and any future consumer) reads a wallet's records.
 *  - operatorAuth: the ROOTS_OPS_TOKEN bearer. INTERIM stand-in for the wallet
 *    OWNER on the consent surface (grant/revoke, access-log). Replaced by holder
 *    sessions (IdP → did:webvh, per wallet-spec L2 Q5) when they ship. Marked
 *    clearly so it isn't mistaken for the final holder-auth mechanism.
 */
import type { Context, Next } from 'hono'
import type { Bindings } from './index'
import { resolveApiKey } from './apikeys'

export type Vars = { reader?: string; scopes?: Set<string>; isOperator?: boolean }
export type Env = { Bindings: Bindings; Variables: Vars }

// guid:roots-auth-bearer
function bearer(c: Context): string | null {
  const h = c.req.header('authorization') ?? ''
  if (h.startsWith('Bearer ')) return h.slice(7).trim()
  return c.req.header('x-api-key')?.trim() ?? null
}

// guid:roots-auth- cteq — constant-time compare (length is not secret for a fixed token)
function ctEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return d === 0
}

// guid:roots-auth-consumer
export async function consumerAuth(c: Context<Env>, next: Next): Promise<Response | void> {
  const key = bearer(c)
  if (!key) return c.json({ error: 'api key required' }, 401)
  const resolved = await resolveApiKey(c.env.DB, key)
  if (!resolved) return c.json({ error: 'invalid api key' }, 401)
  c.set('reader', resolved.tenantId) // opaque consumer id (api_keys.tenant_id; remap pending)
  c.set('scopes', resolved.scopes)
  await next()
}

// guid:roots-auth-requireScope
export function requireScope(scope: string) {
  return async (c: Context<Env>, next: Next): Promise<Response | void> => {
    if (!c.get('scopes')?.has(scope)) return c.json({ error: `scope '${scope}' required` }, 403)
    await next()
  }
}

// guid:roots-auth-operator
export async function operatorAuth(c: Context<Env>, next: Next): Promise<Response | void> {
  const tok = c.env.ROOTS_OPS_TOKEN
  const got = bearer(c)
  if (!tok || tok.length < 24 || !got || !ctEq(got, tok)) {
    return c.json({ error: 'operator auth required' }, 401)
  }
  c.set('isOperator', true)
  await next()
}
