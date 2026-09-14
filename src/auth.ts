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

// guid:roots-auth-mtls
// The mTLS second factor. When ROOTS_REQUIRE_MTLS is set, every authenticated
// entry point additionally requires a valid client certificate (validated by
// Cloudflare API Shield at the edge, surfaced as request.cf.tlsClientAuth). A
// leaked API key or delegation is useless without the cert — two independent
// cryptographic factors, no account coupling. Public routes (DID docs, health,
// data-types) do NOT call this. Returns a 401 Response to short-circuit, or null.
export function requireMtls(c: Context<Env>): Response | null {
  if (!c.env.ROOTS_REQUIRE_MTLS) return null
  const auth = (c.req.raw as unknown as {
    cf?: { tlsClientAuth?: { certVerified?: string; certFingerprintSHA256?: string } }
  }).cf?.tlsClientAuth
  if (!auth || auth.certVerified !== 'SUCCESS') {
    return c.json({ error: 'client certificate required (mTLS)' }, 401)
  }
  const allow = (c.env.ROOTS_MTLS_FINGERPRINTS ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
  if (allow.length && !allow.includes(String(auth.certFingerprintSHA256 ?? '').toLowerCase())) {
    return c.json({ error: 'client certificate not recognized' }, 401)
  }
  return null
}

// guid:roots-auth-consumer
export async function consumerAuth(c: Context<Env>, next: Next): Promise<Response | void> {
  const mtls = requireMtls(c); if (mtls) return mtls
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
  const mtls = requireMtls(c); if (mtls) return mtls
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
  const mtls = requireMtls(c); if (mtls) return mtls
  const del = c.req.header('x-roots-delegation')
  if (del) {
    const d = await verifyDelegation(c, del.trim())
    if (!d) return c.json({ error: 'invalid holder delegation' }, 401)
    if (d.wallet !== c.req.param('id')) return c.json({ error: 'delegation not scoped to this wallet' }, 403)
    c.set('holder', d.holder)
    return await next()
  }
  // Holder session (user-management v0): an HMAC-signed short-lived token
  // minted by POST /w/:id/holder/session after a valid delegation. Lets the
  // dashboard make many requests from one single-use delegation.
  const sess = c.req.header('x-roots-session')
  if (sess && c.env.ROOTS_SESSION_SECRET) {
    const v = await verifyHolderSession(c.env.ROOTS_SESSION_SECRET, sess)
    if (v && v.wallet === c.req.param('id')) {
      c.set('holder', v.holder)
      return await next()
    }
    return c.json({ error: 'invalid or expired session' }, 401)
  }
  // Owner break-glass: the platform operator acting headlessly (not per-user).
  const tok = c.env.ROOTS_OPS_TOKEN
  const got = bearer(c)
  if (tok && tok.length >= 24 && got && ctEq(got, tok)) {
    c.set('holder', 'operator')
    return await next()
  }
  return c.json({ error: 'holder delegation, session, or operator break-glass required' }, 401)
}

// ---- holder sessions (HMAC, stateless) -------------------------------------

function b64u(b: ArrayBuffer | Uint8Array): string {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b)
  let s = ''
  for (const x of u) s += String.fromCharCode(x)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function sessionHmac(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return b64u(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)))
}

export async function mintHolderSession(secret: string, wallet: string, holder: string, ttlS = 3600): Promise<{ token: string; expires_at: string }> {
  const exp = Math.floor(Date.now() / 1000) + ttlS
  const body = b64u(new TextEncoder().encode(JSON.stringify({ w: wallet, h: holder, exp })))
  return { token: `${body}.${await sessionHmac(secret, body)}`, expires_at: new Date(exp * 1000).toISOString() }
}

export async function verifyHolderSession(secret: string, token: string): Promise<{ wallet: string; holder: string } | null> {
  const [body, mac] = token.split('.')
  if (!body || !mac) return null
  const want = await sessionHmac(secret, body)
  if (mac.length !== want.length) return null
  let diff = 0
  for (let i = 0; i < mac.length; i++) diff |= mac.charCodeAt(i) ^ want.charCodeAt(i)
  if (diff !== 0) return null
  try {
    const p = JSON.parse(new TextDecoder().decode(b64urlDecode(body))) as { w?: string; h?: string; exp?: number }
    if (!p.w || !p.h || typeof p.exp !== 'number' || p.exp < Math.floor(Date.now() / 1000)) return null
    return { wallet: p.w, holder: p.h }
  } catch { return null }
}
