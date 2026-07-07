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
import { resolveIssuerKey } from './credentials/resolve'
import { ed25519Verify } from './credentials/keys'

export type Vars = { reader?: string; scopes?: Set<string>; isOperator?: boolean; holder?: string }
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

// ---------------------------------------------------------------- delegated holder auth
// The real per-user holder path. A trusted consumer (Telekora) authenticates
// the human, then signs a short-lived assertion "user U owns wallet W". roots
// verifies it with the SAME crypto the credential verifier uses (did:web/did:key
// resolution + Ed25519), so no new trust root and no roots-side IdP. Only DIDs
// in ROOTS_DELEGATION_ISSUERS may vouch — a scope distinct from the credential
// trust registry. Replaces the operator god-token as the holder mechanism; the
// operator token is kept only as owner break-glass.
export interface Delegation { holder: string; wallet: string; issuer: string }

// guid:roots-auth-b64urlDecode
function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : ''
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// guid:roots-auth-verifyDelegation
async function verifyDelegation(c: Context<Env>, token: string): Promise<Delegation | null> {
  const allow = (c.env.ROOTS_DELEGATION_ISSUERS ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  if (!allow.length) return null // deny-all unless explicitly configured
  const parts = token.split('.')
  if (parts.length !== 3) return null
  let header: { alg?: string; kid?: string }
  let payload: { iss?: string; sub?: string; wallet?: string; exp?: number; jti?: string }
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])))
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])))
  } catch { return null }
  if (header.alg !== 'EdDSA') return null
  const vm = header.kid ?? payload.iss
  if (!vm) return null
  const signerDid = vm.split('#')[0]
  // Only an allowlisted party may vouch, and it must sign as itself.
  if (!allow.includes(signerDid) || (payload.iss && payload.iss !== signerDid)) return null
  const key = await resolveIssuerKey(vm, c.env.DB)
  if (!key) return null
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  const sig = b64urlDecode(parts[2])
  let ok = false
  if (key.raw) ok = await ed25519Verify(key.raw, signingInput, sig)
  else if (key.jwk) {
    const ck = await crypto.subtle.importKey('jwk', key.jwk, { name: 'Ed25519' }, false, ['verify'])
    ok = await crypto.subtle.verify('Ed25519', ck, sig, signingInput)
  }
  if (!ok) return null
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) return null
  if (!payload.sub || !payload.wallet || !payload.jti) return null
  // Single-use: consume the jti. A replay (jti already seen) is rejected. Reached
  // only after the signature is valid, so an attacker can't flood this table with
  // garbage jtis. D1's strong consistency catches replays across Worker isolates.
  const consumed = await c.env.DB.prepare(
    'INSERT INTO used_delegations (jti, expires_at) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING',
  ).bind(payload.jti, payload.exp).run()
  if (consumed.meta.changes === 0) return null // replay
  // Opportunistic sweep of expired jtis (bounded by the token TTL).
  try {
    await c.env.DB.prepare('DELETE FROM used_delegations WHERE expires_at < ?').bind(Math.floor(Date.now() / 1000)).run()
  } catch { /* best effort */ }
  return { holder: payload.sub, wallet: payload.wallet, issuer: signerDid }
}

// guid:roots-auth-delegatedHolder
export async function delegatedHolderAuth(c: Context<Env>, next: Next): Promise<Response | void> {
  const del = c.req.header('x-roots-delegation')
  if (del) {
    const d = await verifyDelegation(c, del.trim())
    if (!d) return c.json({ error: 'invalid holder delegation' }, 401)
    if (d.wallet !== c.req.param('id')) return c.json({ error: 'delegation not scoped to this wallet' }, 403)
    c.set('holder', d.holder)
    return await next()
  }
  // Owner break-glass: the platform operator acting headlessly (not per-user).
  const tok = c.env.ROOTS_OPS_TOKEN
  const got = bearer(c)
  if (tok && tok.length >= 24 && got && ctEq(got, tok)) {
    c.set('holder', 'operator')
    return await next()
  }
  return c.json({ error: 'holder delegation or operator break-glass required' }, 401)
}
