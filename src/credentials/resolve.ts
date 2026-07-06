/**
 * resolve.ts — external issuer key resolution (VC Phase 2, profile §6 check 2).
 *
 * Phase 1 could only resolve issuers whose key we hold (our own `issuer_keys`).
 * To verify a credential someone ELSE issued we must fetch the issuer's public
 * key from the network: its did:web / did:webvh DID document, or a hosted JWKS.
 *
 * Every outbound fetch goes through `safeFetch` — the server is dereferencing
 * attacker-supplied URLs, so SSRF hardening is mandatory (profile §6; spec
 * "system-design fit"). Cloudflare Workers egress already can't reach the
 * origin's private network, but the literal-IP + https-only + no-redirect +
 * timeout + size caps here are defense in depth and portable off-Workers.
 */

import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst } from '../db'
import { multibase58Decode } from './canonical'
import { publicKeyFromDidKey } from './keys'

// Ed25519 multicodec prefix inside a Multikey (z6Mk…): varint 0xed 0x01.
const ED25519_MULTICODEC = [0xed, 0x01]

export interface ResolvedKey {
  raw?: Uint8Array // raw 32-byte Ed25519 pubkey, when the method is Ed25519
  jwk?: JsonWebKey // JWK for ES256/RS256 (and optionally Ed25519)
  method: 'did:key' | 'did:web' | 'did:webvh' | 'jwks'
  /** did:webvh only: whether the entry hash-chain was verified (MVP: false). */
  historyVerified?: boolean
}

// ------------------------------------------------------------- SSRF-safe fetch
const PRIVATE_IPV4 =
  /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/
const BLOCKED_HOST =
  /^(localhost|.*\.local|.*\.internal|metadata\.google\.internal)$/i

// guid:resolve-safeHost
// guid:c1f0a2b7-8e34-4d19-9a6c-2b7e1f04d8a5
function hostIsBlocked(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '') // strip IPv6 brackets
  if (BLOCKED_HOST.test(hostname)) return true
  if (PRIVATE_IPV4.test(h)) return true
  // IPv6 loopback / link-local / unique-local.
  if (h === '::1' || /^fe80:/i.test(h) || /^f[cd][0-9a-f]{2}:/i.test(h)) return true
  return false
}

/**
 * https-only, public-host-only, 5s, 256 KiB. Follows redirects but RE-VALIDATES
 * every hop's host against the blocklist — real hosted credentials redirect
 * (e.g. api.badgr.io → badgr.com), so refusing all redirects is too strict; the
 * SSRF protection is that a redirect to a private/loopback/non-https target is
 * still rejected at the next hop. Throws on any violation.
 */
// guid:resolve-safeFetch
// guid:2d9c4e61-7a05-4b3f-8c12-6e9a0d5b1f38
export async function safeFetch(url: string): Promise<Response> {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), 5000)
  try {
    let current = url
    for (let hop = 0; hop < 5; hop++) {
      let u: URL
      try { u = new URL(current) } catch { throw new Error('invalid URL') }
      if (u.protocol !== 'https:') throw new Error('non-https URL rejected')
      if (hostIsBlocked(u.hostname)) throw new Error('private/loopback host rejected')
      const res = await fetch(u.toString(), {
        redirect: 'manual', // we follow manually so each hop's host is re-checked
        signal: ctl.signal,
        headers: { accept: 'application/json, application/did+json, application/ld+json, */*' },
      })
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location')
        if (!loc) throw new Error('redirect without Location')
        current = new URL(loc, u).toString() // re-validated at the top of the next hop
        continue
      }
      if (!res.ok) throw new Error(`fetch ${res.status}`)
      const len = Number(res.headers.get('content-length') ?? '0')
      if (len > 262144) throw new Error('response too large')
      return res
    }
    throw new Error('too many redirects')
  } finally {
    clearTimeout(timer)
  }
}

/** Read a capped JSON body (guards against a missing content-length). */
// guid:resolve-fetchJson
// guid:8f3b2a17-6d40-49e5-b8c1-0a7e6d92f451
export async function fetchJson(url: string): Promise<unknown> {
  const res = await safeFetch(url)
  const buf = await res.arrayBuffer()
  if (buf.byteLength > 262144) throw new Error('response too large')
  return JSON.parse(new TextDecoder().decode(buf))
}

/** Read a capped text body (JWKS PEM, did.jsonl, hosted OB2). */
// guid:resolve-fetchText
// guid:a4e1c9d2-3b58-4f07-9e6a-1d8c5b2f70a3
export async function fetchText(url: string): Promise<string> {
  const res = await safeFetch(url)
  const buf = await res.arrayBuffer()
  if (buf.byteLength > 262144) throw new Error('response too large')
  return new TextDecoder().decode(buf)
}

// ------------------------------------------------------------- Multikey → raw
/** Decode a Multikey `z6Mk…` multibase to the raw 32-byte Ed25519 pubkey. */
// guid:resolve-rawFromMultikey
// guid:5c7f1e08-9a26-4d34-b1e7-3f0a8c6d2b95
export function rawEd25519FromMultikey(multibase: string): Uint8Array | null {
  try {
    const decoded = multibase58Decode(multibase)
    if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) return null
    return decoded.slice(2)
  } catch {
    return null
  }
}

// ------------------------------------------------------------- did:web URL
/**
 * did:web:example.com            → https://example.com/.well-known/did.json
 * did:web:example.com:a:b        → https://example.com/a/b/did.json
 * (port encoded as %3A in the first segment per did:web spec)
 */
// guid:resolve-didWebUrl
// guid:e2a7d418-0c95-4b63-8f21-7a4e9c0d5b16
export function didWebToUrl(did: string): string | null {
  if (!did.startsWith('did:web:')) return null
  const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent)
  const domain = parts[0]
  if (!domain) return null
  const path = parts.slice(1)
  return path.length === 0
    ? `https://${domain}/.well-known/did.json`
    : `https://${domain}/${path.join('/')}/did.json`
}

// ------------------------------------------------------------- DID doc key pick
interface Vm { id?: string; type?: string; publicKeyMultibase?: string; publicKeyJwk?: JsonWebKey }
// guid:resolve-pickVm
// guid:7b1e6f92-4a08-4d57-9c31-2e8a0d6b4f19
function pickVerificationMethod(doc: Record<string, unknown>, vm: string): Vm | null {
  const methods = (doc.verificationMethod as Vm[] | undefined) ?? []
  // Exact id match first; else the fragment; else the sole method.
  return (
    methods.find((m) => m.id === vm) ??
    methods.find((m) => m.id && vm.includes('#') && m.id.endsWith(vm.slice(vm.indexOf('#')))) ??
    (methods.length === 1 ? methods[0] : null)
  )
}

// guid:resolve-keyFromVm
// guid:9d0c3a75-1e46-4b28-8f93-6a1e7c5d20b8
function keyFromVm(m: Vm | null, method: ResolvedKey['method']): ResolvedKey | null {
  if (!m) return null
  if (m.publicKeyMultibase) {
    const raw = rawEd25519FromMultikey(m.publicKeyMultibase)
    if (raw) return { raw, method }
  }
  if (m.publicKeyJwk) return { jwk: m.publicKeyJwk, method }
  return null
}

// ------------------------------------------------------------- resolver
/**
 * Resolve the public key named by a proof's `verificationMethod` (or a JWT
 * kid / iss). Our own tenants short-circuit to the local keystore (no fetch).
 */
// guid:resolve-issuerKey
// guid:0a6d2f83-5b17-4e49-9c02-8d3a1e7b6f04
export async function resolveIssuerKey(
  vm: string,
  db?: D1Database,
): Promise<ResolvedKey | null> {
  const did = vm.split('#')[0]

  // did:key — self-contained, no network.
  if (did.startsWith('did:key:')) {
    try { return { raw: publicKeyFromDidKey(did), method: 'did:key' } } catch { return null }
  }

  // did:web — our own tenants resolve locally; external ones fetch the DID doc.
  if (did.startsWith('did:web:')) {
    if (db) {
      const local =
        (await dbFirst<{ public_key_multibase: string }>(
          db, 'SELECT public_key_multibase FROM issuer_keys WHERE did = ?', did,
        )) ??
        (await dbFirst<{ public_key_multibase: string }>(
          db, 'SELECT public_key_multibase FROM receiver_keys WHERE did = ?', did,
        ))
      if (local) {
        const raw = rawEd25519FromMultikey(local.public_key_multibase)
        // Our stored form is the RAW pubkey multibase (not Multikey); handle both.
        if (raw) return { raw, method: 'did:web' }
        try { return { raw: multibase58Decode(local.public_key_multibase), method: 'did:web' } }
        catch { /* fall through to network */ }
      }
    }
    const url = didWebToUrl(did)
    if (!url) return null
    try {
      const doc = (await fetchJson(url)) as Record<string, unknown>
      return keyFromVm(pickVerificationMethod(doc, vm), 'did:web')
    } catch { return null }
  }

  // did:webvh — verifiable-history DID. MVP: fetch the log, take the latest
  // entry's DID document, resolve its key, flag history as unverified.
  if (did.startsWith('did:webvh:')) {
    try {
      const doc = await resolveWebvhLatest(did)
      if (!doc) return null
      const k = keyFromVm(pickVerificationMethod(doc, vm), 'did:webvh')
      return k ? { ...k, historyVerified: false } : null
    } catch { return null }
  }

  // Hosted JWKS — `iss` is an https URL; fetch <iss>/.well-known/jwks.json.
  if (did.startsWith('https://')) {
    try {
      const kid = vm.includes('#') ? vm.slice(vm.indexOf('#') + 1) : undefined
      const base = did.replace(/\/$/, '')
      const jwks = (await fetchJson(`${base}/.well-known/jwks.json`)) as { keys?: JsonWebKey[] }
      const keys = jwks.keys ?? []
      const jwk = (kid && keys.find((k) => (k as { kid?: string }).kid === kid)) ?? keys[0]
      return jwk ? { jwk, method: 'jwks' } : null
    } catch { return null }
  }

  return null
}

/** Best-effort did:webvh: fetch did.jsonl, parse the last entry's DID document. */
// guid:resolve-webvhLatest
// guid:3e8b1d47-6c29-4a05-9f83-2b7e0a6d5c14
async function resolveWebvhLatest(did: string): Promise<Record<string, unknown> | null> {
  // did:webvh:<scid>:<domain>[:<path…>]
  const rest = did.slice('did:webvh:'.length).split(':').map(decodeURIComponent)
  const domain = rest[1]
  if (!domain) return null
  const path = rest.slice(2)
  const url = path.length === 0
    ? `https://${domain}/.well-known/did.jsonl`
    : `https://${domain}/${path.join('/')}/did.jsonl`
  const text = await fetchText(url)
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean)
  if (lines.length === 0) return null
  const last = JSON.parse(lines[lines.length - 1]) as unknown
  // Entry shapes vary by webvh version: object with {state|value} or an array
  // whose last element carries {value: didDoc}. Extract the DID document.
  const asObj = last as Record<string, unknown>
  const state = (asObj.state ?? asObj.value) as Record<string, unknown> | undefined
  if (state && typeof state === 'object' && 'id' in state) return state
  if (Array.isArray(last)) {
    for (const el of last) {
      const v = (el as { value?: Record<string, unknown> })?.value
      if (v && typeof v === 'object' && 'id' in v) return v
    }
  }
  if ('id' in asObj && 'verificationMethod' in asObj) return asObj
  return null
}
