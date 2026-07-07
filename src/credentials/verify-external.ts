/**
 * verify-external.ts — the general third-party verifier (VC Phase 2).
 *
 * Verifies credentials Telekora did NOT issue, across four formats, and assigns
 * an HONEST tier (profile §6): the five checks (proof, issuer-resolution,
 * status, time, trust) collapse into verified → valid-signature → self-reported.
 * An unverified credential must NEVER surface as verified — that label's honesty
 * is the product.
 *
 *   vc-di      W3C VC 2.0 + DataIntegrityProof (eddsa-jcs-2022) — reuses Phase 1.
 *   vc-jwt     Compact JWS credential (EdDSA / ES256 / RS256).
 *   ob2-hosted Open Badges 2.0 hosted assertion — domain-control, not a signature.
 *   ob2-signed Open Badges 2.0 signed assertion — RS256 JWS over creator's key.
 *   manual     PDF / hand-entered — no crypto, always self-reported.
 *
 * Never throws on hostile input: a malformed credential resolves to
 * self-reported with a reason, not a 500.
 */

import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst } from '../db'
import { verifyDataIntegrityProof, type DataIntegrityProof } from './di'
import { ed25519Verify } from './keys'
import { resolveIssuerKey, fetchJson, type ResolvedKey } from './resolve'

export type Tier = 'verified' | 'valid-signature' | 'self-reported'
export type Format = 'vc-di' | 'vc-jwt' | 'ob2-hosted' | 'ob2-signed' | 'manual' | 'unknown'

export interface Check { name: string; ok: boolean; detail?: string }

/** Issuer-asserted alignment to a standard/framework (OB alignment). Captured
 *  as raw taxonomy material — never used for name-matching. */
export interface Alignment {
  targetName?: string
  targetUrl?: string
  targetFramework?: string
  targetCode?: string
}

export interface ExternalReport {
  tier: Tier
  format: Format
  issuer?: { id?: string; name?: string }
  subject?: { id?: string }
  credentialName?: string
  issuedAt?: string
  expiresAt?: string
  checks: Check[]
  proofMethod?: string
  registered: boolean
  reason?: string
  /** Issuer-asserted framework/standard alignment, when the credential carries it. */
  alignments?: Alignment[]
}

// guid:vx-extractAlignments
// guid:d4e5f607-8192-4a3b-b5c6-e7f8091a2b3c
function extractAlignments(source: unknown): Alignment[] | undefined {
  if (!Array.isArray(source) || source.length === 0) return undefined
  const out = source.map((a) => {
    const o = (a ?? {}) as Record<string, unknown>
    return {
      targetName: typeof o.targetName === 'string' ? o.targetName : undefined,
      targetUrl: typeof o.targetUrl === 'string' ? o.targetUrl : undefined,
      targetFramework: typeof o.targetFramework === 'string' ? o.targetFramework : undefined,
      targetCode: typeof o.targetCode === 'string' ? o.targetCode : undefined,
    }
  }).filter((a) => a.targetName || a.targetUrl)
  return out.length ? out : undefined
}

export type ExternalInput =
  | { kind: 'json'; doc: Record<string, unknown> }
  | { kind: 'jwt'; token: string }
  | { kind: 'manual'; meta: ManualMeta }

export interface ManualMeta {
  issuerName?: string
  credentialName?: string
  issuedAt?: string
  expiresAt?: string
}

const OB2_CONTEXT = 'openbadges/v2'

// ------------------------------------------------------------- small crypto utils
// guid:vx-b64urlDecode
// guid:1a2b3c4d-5e6f-4708-9a1b-2c3d4e5f6071
function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// guid:vx-gunzip
// guid:2b3c4d5e-6f70-4819-a2b3-c4d5e6f70812
async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('gzip')
  const body = new Response(bytes as unknown as BodyInit).body
  if (!body) throw new Error('gunzip: empty body')
  const out = new Response(body.pipeThrough(ds as unknown as ReadableWritablePair<Uint8Array, Uint8Array>))
  return new Uint8Array(await out.arrayBuffer())
}

// guid:vx-pemToDer
// guid:3c4d5e6f-7081-492a-b3c4-d5e6f7081923
function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Verify a compact JWS against a resolved key. Supports EdDSA/ES256/RS256. */
// guid:vx-verifyJws
// guid:4d5e6f70-8192-4a3b-b4c5-d6e7f8192a34
async function verifyJws(token: string, key: ResolvedKey): Promise<boolean> {
  const [h, p, s] = token.split('.')
  if (!h || !p || !s) return false
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h))) as { alg?: string }
  const signingInput = new TextEncoder().encode(`${h}.${p}`)
  const sig = b64urlDecode(s)
  try {
    if (header.alg === 'EdDSA') {
      if (key.raw) return await ed25519Verify(key.raw, signingInput, sig)
      if (key.jwk) {
        const ck = await crypto.subtle.importKey('jwk', key.jwk, { name: 'Ed25519' }, false, ['verify'])
        return await crypto.subtle.verify('Ed25519', ck, sig, signingInput)
      }
      return false
    }
    if (header.alg === 'ES256' && key.jwk) {
      const ck = await crypto.subtle.importKey('jwk', key.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ck, sig, signingInput)
    }
    if (header.alg === 'RS256' && key.jwk) {
      const ck = await crypto.subtle.importKey('jwk', key.jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
      return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', ck, sig, signingInput)
    }
  } catch { return false }
  return false
}

// ------------------------------------------------------------- registry / tier
// guid:vx-isRegistered
// guid:5e6f7081-92a3-4b4c-b5d6-e7f8192a3b45
async function isRegistered(db: D1Database, issuerId: string | undefined): Promise<boolean> {
  if (!issuerId) return false
  const candidates = new Set<string>([issuerId])
  try { candidates.add(new URL(issuerId).origin) } catch { /* not a URL */ }
  for (const c of candidates) {
    const row = await dbFirst<{ status: string }>(
      db, 'SELECT status FROM issuers WHERE did_or_iss = ?', c,
    )
    if (row?.status === 'trusted') return true
    if (row?.status === 'revoked') return false
  }
  return false
}

/** Collapse the five checks + registry standing into the honest tier. */
// guid:vx-tierFor
// guid:6f708192-a3b4-4c5d-b6e7-f8192a3b4c56
function tierFor(checks: Check[], registered: boolean): Tier {
  const cryptoOk = checks.length > 0 && checks.every((c) => c.ok)
  if (!cryptoOk) return 'self-reported'
  return registered ? 'verified' : 'valid-signature'
}

/**
 * Bind the proof key to the NAMED issuer. Without this, a signature that verifies
 * against an attacker's own key (e.g. a self-contained did:key) while the
 * credential claims a registered issuer would surface as `verified` — the trust
 * decision (vc.issuer) and the signature (verificationMethod) weren't tied
 * together. Conservative heuristic: same DID, same did:web[vh] authority, or same
 * host. An issuer that signs with a cross-scheme key its own DID document lists
 * will UNDER-verify (drop to self-reported) — safe, never the reverse.
 */
// guid:vx-didBoundToIssuer
function didBoundToIssuer(vm: string | undefined, issuerId: string | undefined): boolean {
  if (!vm || !issuerId) return false
  const vmDid = vm.split('#')[0]
  if (vmDid === issuerId) return true
  const authority = (s: string): string | null => {
    const m = /^did:web(?:vh)?:([^:]+)/.exec(s)
    if (m) return decodeURIComponent(m[1]).toLowerCase()
    try { return new URL(s).host.toLowerCase() } catch { return null }
  }
  const a = authority(vmDid)
  const b = authority(issuerId)
  return !!a && a === b
}

/** OB2-signed binding: the key document URL and the claimed owner must share a
 *  host, so a key doc hosted anywhere can't self-assert a trusted `owner`. */
// guid:vx-sameHost
function sameHost(a: string | undefined, b: string | undefined): boolean {
  if (!a || !b) return false
  try { return new URL(a).host.toLowerCase() === new URL(b).host.toLowerCase() } catch { return false }
}

// ------------------------------------------------------------- status (external)
/** Read an external BitstringStatusList bit for a credential. false = clear. */
// guid:vx-statusRevoked
// guid:708192a3-b4c5-4d6e-b7f8-192a3b4c5d67
async function statusFlagged(status: unknown): Promise<{ flagged: boolean; checked: boolean; hadEntries: boolean }> {
  const entries = Array.isArray(status) ? status : status ? [status] : []
  const hadEntries = entries.length > 0
  let checked = false
  for (const e of entries as Record<string, unknown>[]) {
    const url = e.statusListCredential as string | undefined
    const idx = Number(e.statusListIndex)
    if (!url || Number.isNaN(idx)) continue
    try {
      const listVc = (await fetchJson(url)) as { credentialSubject?: { encodedList?: string } }
      const encoded = listVc.credentialSubject?.encodedList
      if (!encoded) continue
      const gz = b64urlDecode(encoded.replace(/^u/, '')) // multibase 'u' = base64url
      const bits = await gunzip(gz)
      checked = true
      const byte = bits[idx >> 3] ?? 0
      if ((byte & (0x80 >> (idx & 7))) !== 0) return { flagged: true, checked: true, hadEntries }
    } catch { /* status list unreachable — treat as unchecked, not clear */ }
  }
  return { flagged: false, checked, hadEntries }
}

/** Honest status Check: revoked → fail; claimed-but-unreachable → surfaced, not hidden. */
// guid:vx-statusCheck
// guid:c3d4e5f6-7081-4293-b1c2-d3e4f5061728
function statusCheck(st: { flagged: boolean; checked: boolean; hadEntries: boolean }): Check {
  if (st.flagged) return { name: 'status', ok: false, detail: 'revoked/suspended' }
  if (st.hadEntries && !st.checked) return { name: 'status', ok: true, detail: 'status list present but unreachable — not confirmed' }
  return { name: 'status', ok: true, detail: st.checked ? 'clear' : 'no status list' }
}

// guid:vx-timeOk
// guid:8192a3b4-c5d6-4e7f-b819-2a3b4c5d6e78
function timeCheck(validFrom?: string, validUntil?: string): Check {
  const now = Date.now()
  if (validUntil && new Date(validUntil).getTime() < now) {
    return { name: 'time', ok: false, detail: 'expired' }
  }
  if (validFrom && new Date(validFrom).getTime() > now) {
    return { name: 'time', ok: false, detail: 'not yet valid' }
  }
  return { name: 'time', ok: true }
}

// ------------------------------------------------------------- entry point
// guid:vx-verifyExternal
// guid:92a3b4c5-d6e7-4f80-b92a-3b4c5d6e7f89
export async function verifyExternal(
  input: ExternalInput,
  db: D1Database,
): Promise<ExternalReport> {
  try {
    if (input.kind === 'manual') return manualReport(input.meta)
    if (input.kind === 'jwt') return await verifyJwtCredential(input.token, db)
    // JSON: OB 2.0 hosted, or a VC with Data Integrity.
    const ctx = JSON.stringify(input.doc['@context'] ?? '')
    if (ctx.includes(OB2_CONTEXT)) return await verifyOb2Hosted(input.doc, db)
    return await verifyDiCredential(input.doc, db)
  } catch (e) {
    return {
      tier: 'self-reported', format: 'unknown', registered: false, checks: [],
      reason: 'verification error: ' + (e instanceof Error ? e.message : 'unknown'),
    }
  }
}

// guid:vx-manualReport
// guid:a3b4c5d6-e7f8-4091-ba3b-4c5d6e7f8091
function manualReport(meta: ManualMeta): ExternalReport {
  return {
    tier: 'self-reported', format: 'manual', registered: false,
    issuer: { name: meta.issuerName }, credentialName: meta.credentialName,
    issuedAt: meta.issuedAt, expiresAt: meta.expiresAt,
    proofMethod: 'none',
    checks: [{ name: 'proof', ok: false, detail: 'manual entry — no cryptographic proof' }],
    reason: 'self-reported: hand-entered, no verifiable proof',
  }
}

// ------------------------------------------------------------- VC Data Integrity
// guid:vx-verifyDi
// guid:b4c5d6e7-f809-41a2-bb4c-5d6e7f8091a2
async function verifyDiCredential(
  vc: Record<string, unknown>,
  db: D1Database,
): Promise<ExternalReport> {
  const proofs = Array.isArray(vc.proof) ? (vc.proof as DataIntegrityProof[]) : vc.proof ? [vc.proof as DataIntegrityProof] : []
  const { proof: _omit, ...unsigned } = vc as Record<string, unknown>
  const issuerRaw = vc.issuer as { id?: string; name?: string } | string | undefined
  const issuerId = typeof issuerRaw === 'string' ? issuerRaw : issuerRaw?.id
  const issuerName = typeof issuerRaw === 'string' ? undefined : issuerRaw?.name
  const subject = vc.credentialSubject as Record<string, unknown> | undefined

  const checks: Check[] = []
  // Proof: the issuer (assertionMethod) proof must verify against a resolved key.
  const issuerProof = proofs.find((p) => (p as { proofPurpose?: string }).proofPurpose === 'assertionMethod') ?? proofs[0]
  let proofOk = false
  if (issuerProof?.type === 'DataIntegrityProof') {
    const key = await resolveIssuerKey(issuerProof.verificationMethod, db)
    if (key?.raw) proofOk = await verifyDataIntegrityProof(unsigned, issuerProof, key.raw)
    checks.push({ name: 'proof', ok: proofOk, detail: proofOk ? issuerProof.cryptosuite : 'signature invalid or key unresolved' })
    checks.push({ name: 'issuer-resolution', ok: !!key, detail: key?.method })
  } else {
    checks.push({ name: 'proof', ok: false, detail: 'no supported DataIntegrityProof (eddsa-jcs-2022)' })
    checks.push({ name: 'issuer-resolution', ok: false })
  }
  // Issuer binding — see didBoundToIssuer. An unbound but otherwise-valid signature
  // can't be attributed to the issuer it names, so it collapses to self-reported
  // via tierFor (the failed check), never verified/valid-signature.
  const bound = didBoundToIssuer(issuerProof?.verificationMethod, issuerId)
  checks.push({ name: 'issuer-binding', ok: bound, detail: bound ? 'proof key controlled by the named issuer' : 'proof key not bound to the named issuer' })
  // Status + time.
  const st = await statusFlagged(vc.credentialStatus)
  checks.push(statusCheck(st))
  checks.push(timeCheck(vc.validFrom as string | undefined, vc.validUntil as string | undefined))

  const registered = proofOk && bound && (await isRegistered(db, issuerId))
  return {
    tier: tierFor(checks, registered), format: 'vc-di', registered,
    issuer: { id: issuerId, name: issuerName },
    subject: { id: typeof subject?.id === 'string' ? (subject.id as string) : undefined },
    credentialName: (vc.name as string | undefined) ?? achievementName(subject),
    issuedAt: vc.validFrom as string | undefined,
    expiresAt: vc.validUntil as string | undefined,
    proofMethod: 'eddsa-jcs-2022',
    alignments: extractAlignments((subject?.achievement as { alignment?: unknown } | undefined)?.alignment),
    checks,
  }
}

// guid:vx-achievementName
// guid:c5d6e7f8-0912-41b3-bc5d-6e7f8091a2b3
function achievementName(subject: Record<string, unknown> | undefined): string | undefined {
  const ach = subject?.achievement as { name?: string } | undefined
  return ach?.name
}

// ------------------------------------------------------------- VC-JWT
// guid:vx-verifyJwtCred
// guid:d6e7f809-1a2b-41c4-bd6e-7f8091a2b3c4
async function verifyJwtCredential(token: string, db: D1Database): Promise<ExternalReport> {
  const parts = token.split('.')
  if (parts.length !== 3) return manualReason('vc-jwt', 'not a compact JWS')
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))) as { kid?: string; alg?: string }
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]))) as Record<string, unknown>

  // OB 2.0 signed assertions ride in a JWS whose payload is the OB2 assertion.
  const pctx = JSON.stringify(payload['@context'] ?? '')
  if (pctx.includes(OB2_CONTEXT)) return await verifyOb2Signed(token, payload, db)

  // VC-JWT: the credential is payload.vc (JWT-VC 1.1) or the payload itself (VC 2.0).
  const cred = (payload.vc as Record<string, unknown> | undefined) ?? payload
  const issuerRaw = (cred.issuer ?? payload.iss) as { id?: string; name?: string } | string | undefined
  const issuerId = typeof issuerRaw === 'string' ? issuerRaw : issuerRaw?.id
  const issuerName = typeof issuerRaw === 'string' ? undefined : issuerRaw?.name
  const subject = cred.credentialSubject as Record<string, unknown> | undefined

  // Resolve via kid (DID URL / JWKS kid) or iss.
  const vm = header.kid ?? (typeof issuerId === 'string'
    ? (issuerId.startsWith('did:') ? issuerId : `${issuerId}${header.kid ? '#' + header.kid : ''}`)
    : '')
  const key = vm ? await resolveIssuerKey(vm, db) : null
  const proofOk = key ? await verifyJws(token, key) : false

  const checks: Check[] = [
    { name: 'proof', ok: proofOk, detail: proofOk ? header.alg : 'JWS signature invalid or key unresolved' },
    { name: 'issuer-resolution', ok: !!key, detail: key?.method },
  ]
  // Issuer binding — the JWS key (kid/iss) must be controlled by the named issuer.
  const bound = didBoundToIssuer(vm, issuerId)
  checks.push({ name: 'issuer-binding', ok: bound, detail: bound ? 'proof key controlled by the named issuer' : 'proof key not bound to the named issuer' })
  const st = await statusFlagged(cred.credentialStatus)
  checks.push(statusCheck(st))
  const validUntil = (cred.validUntil as string | undefined) ?? (payload.exp ? new Date(Number(payload.exp) * 1000).toISOString() : undefined)
  const validFrom = (cred.validFrom as string | undefined) ?? (payload.nbf ? new Date(Number(payload.nbf) * 1000).toISOString() : undefined)
  checks.push(timeCheck(validFrom, validUntil))

  const registered = proofOk && bound && (await isRegistered(db, issuerId))
  return {
    tier: tierFor(checks, registered), format: 'vc-jwt', registered,
    issuer: { id: issuerId, name: issuerName },
    subject: { id: (typeof subject?.id === 'string' ? subject.id : payload.sub) as string | undefined },
    credentialName: (cred.name as string | undefined) ?? achievementName(subject),
    issuedAt: validFrom, expiresAt: validUntil, proofMethod: `jws-${header.alg}`, checks,
  }
}

// ------------------------------------------------------------- OB 2.0 hosted
// guid:vx-verifyOb2Hosted
// guid:e7f80912-a3b4-41d5-be7f-8091a2b3c4d5
async function verifyOb2Hosted(
  doc: Record<string, unknown>,
  db: D1Database,
): Promise<ExternalReport> {
  const assertionId = typeof doc.id === 'string' ? doc.id : undefined
  const checks: Check[] = []

  // Proof (domain-control): the assertion must be live at its own https id and
  // self-consistent — the issuer's domain served it.
  let live: Record<string, unknown> | undefined
  if (assertionId?.startsWith('https://')) {
    try {
      live = (await fetchJson(assertionId)) as Record<string, unknown>
    } catch { /* unreachable */ }
  }
  const liveOk = !!live && live.id === assertionId
  checks.push({ name: 'proof', ok: liveOk, detail: liveOk ? 'hosted assertion live at issuer domain' : 'assertion not live at its id (domain-control failed)' })

  // Resolve badge → issuer, and confirm same-origin with the assertion.
  let issuerId: string | undefined
  let issuerName: string | undefined
  let issuerOrigin: string | undefined
  let credentialName: string | undefined
  let alignments: Alignment[] | undefined
  try {
    const badge = typeof doc.badge === 'string' ? (await fetchJson(doc.badge)) as Record<string, unknown> : (doc.badge as Record<string, unknown>)
    credentialName = badge?.name as string | undefined
    alignments = extractAlignments(badge?.alignment)
    const issuerRef = badge?.issuer
    const issuer = typeof issuerRef === 'string' ? (await fetchJson(issuerRef)) as Record<string, unknown> : (issuerRef as Record<string, unknown>)
    issuerId = (typeof issuerRef === 'string' ? issuerRef : (issuer?.id as string)) ?? undefined
    issuerName = issuer?.name as string | undefined
    if (issuerId) { try { issuerOrigin = new URL(issuerId).origin } catch { /* */ } }
  } catch { /* issuer chain unreachable */ }
  const sameOrigin = !!assertionId && !!issuerOrigin && (() => {
    try { return new URL(assertionId).origin === issuerOrigin } catch { return false }
  })()
  checks.push({ name: 'issuer-resolution', ok: !!issuerId && sameOrigin, detail: sameOrigin ? 'issuer domain matches assertion origin' : 'issuer/assertion origin mismatch' })

  // Status: OB2 `revoked` flag.
  const revoked = (live?.revoked ?? doc.revoked) === true
  checks.push({ name: 'status', ok: !revoked, detail: revoked ? 'revoked' : 'not revoked' })
  checks.push(timeCheck(doc.issuedOn as string | undefined, doc.expires as string | undefined))

  const cryptoOk = checks.every((c) => c.ok)
  const registered = cryptoOk && (await isRegistered(db, issuerId));
  return {
    tier: tierFor(checks, registered), format: 'ob2-hosted', registered,
    issuer: { id: issuerId, name: issuerName },
    subject: { id: (doc.recipient as { identity?: string } | undefined)?.identity },
    credentialName: credentialName ?? badgeName(doc),
    issuedAt: doc.issuedOn as string | undefined, expiresAt: doc.expires as string | undefined,
    proofMethod: 'domain-control', alignments, checks,
  }
}

// guid:vx-badgeName
// guid:f8091a2b-3c4d-41e6-bf80-91a2b3c4d5e6
function badgeName(doc: Record<string, unknown>): string | undefined {
  const b = doc.badge
  if (b && typeof b === 'object') return (b as { name?: string }).name
  return undefined
}

// ------------------------------------------------------------- OB 2.0 signed
// guid:vx-verifyOb2Signed
// guid:091a2b3c-4d5e-41f7-b091-a2b3c4d5e6f7
async function verifyOb2Signed(
  token: string,
  payload: Record<string, unknown>,
  db: D1Database,
): Promise<ExternalReport> {
  const verification = payload.verification as { creator?: string } | undefined
  const creator = verification?.creator
  const checks: Check[] = []
  let proofOk = false
  let issuerId: string | undefined
  let issuerName: string | undefined
  try {
    if (creator?.startsWith('https://')) {
      const keyDoc = (await fetchJson(creator)) as { publicKeyPem?: string; owner?: string }
      if (keyDoc.publicKeyPem) {
        const der = pemToDer(keyDoc.publicKeyPem)
        const ck = await crypto.subtle.importKey('spki', der as unknown as BufferSource, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
        const [h, p, s] = token.split('.')
        proofOk = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', ck, b64urlDecode(s), new TextEncoder().encode(`${h}.${p}`))
      }
      issuerId = keyDoc.owner
    }
  } catch { /* creator/key unreachable */ }
  checks.push({ name: 'proof', ok: proofOk, detail: proofOk ? 'RS256 over creator publicKeyPem' : 'signed-badge signature invalid or key unreachable' })
  checks.push({ name: 'issuer-resolution', ok: !!issuerId, detail: issuerId ? 'creator key owner' : 'no key owner' })
  // Issuer binding — the creator key document and its self-asserted `owner` must
  // share a host, else a key doc hosted anywhere could claim a trusted owner.
  const bound = sameHost(creator, issuerId)
  checks.push({ name: 'issuer-binding', ok: bound, detail: bound ? 'key document hosted by the owner domain' : 'key document not same-host as claimed owner' })
  const revoked = payload.revoked === true
  checks.push({ name: 'status', ok: !revoked, detail: revoked ? 'revoked' : 'not revoked' })
  checks.push(timeCheck(payload.issuedOn as string | undefined, payload.expires as string | undefined))

  const registered = proofOk && bound && (await isRegistered(db, issuerId))
  return {
    tier: tierFor(checks, registered), format: 'ob2-signed', registered,
    issuer: { id: issuerId, name: issuerName },
    subject: { id: (payload.recipient as { identity?: string } | undefined)?.identity },
    credentialName: badgeName(payload),
    issuedAt: payload.issuedOn as string | undefined, expiresAt: payload.expires as string | undefined,
    proofMethod: 'jws-RS256', checks,
  }
}

// guid:vx-manualReason
// guid:1b2c3d4e-5f60-4172-b1b2-c3d4e5f60718
function manualReason(format: Format, reason: string): ExternalReport {
  return { tier: 'self-reported', format, registered: false, checks: [{ name: 'proof', ok: false, detail: reason }], reason }
}
