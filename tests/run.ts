/**
 * tests/run.ts — headless acceptance for the four roots dormant features.
 *
 * Drives the REAL Hono worker (src/index) against an in-memory SQLite D1 (with
 * every migration applied), plus direct calls into the credential modules. No
 * network, no mocks of our own code. Bundle + run via `npm test`.
 *
 *   ① BitstringStatusList — issuance attaches a credentialStatus; the served
 *     status VC verifies; an operator revoke flips the bit.
 *   ② API keys — mint returns a working key; list is metadata-only; revoke
 *     disables it.
 *   ③ Custody handoff — flips custody to self; the did.jsonl gains a chained,
 *     verifiable entry rotating authority to the holder key.
 *   ④ did:webvh — verifyWebvhLog passes on a good log, fails closed on tampering.
 */
import { join } from 'node:path'
import worker from '../src/index'
import type { Bindings } from '../src/index'
import { freshDb, type ShimD1 } from './d1-shim'
import { verifyDataIntegrityProof, type DataIntegrityProof } from '../src/credentials/di'
import { multibase58Decode } from '../src/credentials/canonical'
import { verifyWebvhLog } from '../src/credentials/webvh'
import { generateEd25519Keypair, multikeyFromPublicKey } from '../src/credentials/keys'

// npm runs scripts from the package root; migrations live there.
const MIGRATIONS = join(process.cwd(), 'migrations')

const KEK = 'IgLShw+xovqhyoxH5Z8EBnAyuwmqg9El9MmSjwpK/PQ=' // 32-byte base64 (from .dev.vars)
const OPS = 'roots-operator-token-testing-1234567890'

let pass = 0
let fail = 0
function ok(name: string, cond: boolean, detail?: string) {
  if (cond) { pass++; console.log(`  ✓ ${name}${detail ? ' — ' + detail : ''}`) }
  else { fail++; console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

// ----------------------------------------------------------------- worker harness
type Env = { DB: ShimD1 } & Partial<Bindings>
const ctx = {
  waitUntil(p: Promise<unknown>) { try { void (p as { catch?: (f: () => void) => void })?.catch?.(() => {}) } catch { /* */ } },
  passThroughOnException() { /* */ },
}

function makeEnv(): Env {
  return { DB: freshDb(MIGRATIONS), ROOTS_KEK: KEK, ROOTS_OPS_TOKEN: OPS, ROOTS_DELEGATION_ISSUERS: '' }
}

interface CallOpts { token?: string; json?: unknown; headers?: Record<string, string> }
async function call(env: Env, method: string, path: string, opts: CallOpts = {}): Promise<Response> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) }
  let body: string | undefined
  if (opts.json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(opts.json) }
  if (opts.token) headers['authorization'] = `Bearer ${opts.token}`
  const req = new Request('https://id.dreamtree.org' + path, { method, headers, body })
  return worker.fetch(req, env as unknown as Bindings, ctx as unknown as ExecutionContext)
}

// ----------------------------------------------------------------- bit decoding
function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('gzip')
  const body = new Response(bytes as unknown as BodyInit).body!
  return new Uint8Array(await new Response(body.pipeThrough(ds as unknown as ReadableWritablePair<Uint8Array, Uint8Array>)).arrayBuffer())
}
async function statusBit(vc: { credentialSubject?: { encodedList?: string } }, index: number): Promise<boolean> {
  const encoded = vc.credentialSubject?.encodedList ?? ''
  const bits = await gunzip(b64urlDecode(encoded.replace(/^u/, '')))
  const byte = bits[index >> 3] ?? 0
  return (byte & (0x80 >> (index & 7))) !== 0
}

async function mintKey(env: Env, tenant: string, scopes: string[]): Promise<{ id: string; key: string }> {
  const res = await call(env, 'POST', '/admin/keys', { token: OPS, json: { tenant_id: tenant, scopes } })
  const j = await res.json() as { id: string; key: string }
  return j
}
async function newWallet(env: Env, key: string): Promise<string> {
  const res = await call(env, 'POST', '/wallets', { token: key, json: { provider: 'test', provider_uid: crypto.randomUUID() } })
  const j = await res.json() as { wallet_id: string }
  return j.wallet_id
}

// ===================================================================== ① status
async function testStatusList() {
  console.log('\n[①] BitstringStatusList — issuance + served VC + revoke')
  const env = makeEnv()
  const tenant = 'telekora-test'
  const { key } = await mintKey(env, tenant, ['wallets:create', 'credentials:import'])
  const walletId = await newWallet(env, key)

  const doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    credentialSubject: { id: 'did:example:holder', achievement: { name: 'Test Achievement' } },
  }
  const issueRes = await call(env, 'POST', `/w/${walletId}/credentials`, {
    token: key, json: { doc, source_type: 'issued', data_type: 'dt.attestation@1' },
  })
  const issued = await issueRes.json() as { ok?: boolean; id?: string }
  ok('credential issued', issueRes.status === 200 && !!issued.id, `tier via detail below`)

  // Stored doc must carry a credentialStatus (operator break-glass detail read).
  const detailRes = await call(env, 'GET', `/w/${walletId}/records/${issued.id}`, { token: OPS })
  const detail = await detailRes.json() as { record?: { payload?: string } }
  const storedDoc = JSON.parse(detail.record?.payload ?? '{}') as {
    credentialStatus?: Array<{ statusPurpose: string; statusListIndex: string; statusListCredential: string }>
    proof?: unknown
  }
  const entries = storedDoc.credentialStatus ?? []
  ok('issued credential carries a credentialStatus (both purposes)', entries.length === 2)
  ok('issued credential is roots-signed', !!storedDoc.proof)
  const revEntry = entries.find((e) => e.statusPurpose === 'revocation')
  ok('revocation status entry points at the served list',
    revEntry?.statusListCredential === `https://id.dreamtree.org/status/${tenant}/revocation`,
    revEntry?.statusListCredential)
  const idx = Number(revEntry?.statusListIndex ?? -1)

  // The served status VC verifies (roots-signed) and the bit is CLEAR pre-revoke.
  const before = await (await call(env, 'GET', `/status/${tenant}/revocation`)).json() as {
    proof: DataIntegrityProof; credentialSubject: { encodedList: string }
  }
  const issuerRow = await env.DB.prepare('SELECT public_key_multibase FROM issuer_keys WHERE tenant_id = ?').bind(tenant).first<{ public_key_multibase: string }>()
  const raw = multibase58Decode(issuerRow!.public_key_multibase)
  const { proof: bproof, ...bUnsigned } = before
  ok('served status VC signature verifies', await verifyDataIntegrityProof(bUnsigned as Record<string, unknown>, bproof, raw))
  ok('bit is clear before revoke', (await statusBit(before, idx)) === false, `index ${idx}`)

  // Revoke → bit flips.
  const revoke = await call(env, 'POST', `/admin/credentials/${issued.id}/revoke`, { token: OPS, json: { reason: 'test revoke' } })
  ok('operator revoke accepted', revoke.status === 200)
  const after = await (await call(env, 'GET', `/status/${tenant}/revocation`)).json() as {
    proof: DataIntegrityProof; credentialSubject: { encodedList: string }
  }
  const { proof: aproof, ...aUnsigned } = after
  ok('revoked status VC still verifies', await verifyDataIntegrityProof(aUnsigned as Record<string, unknown>, aproof, raw))
  ok('bit is SET after revoke', (await statusBit(after, idx)) === true, `index ${idx}`)

  // Operator revoke requires auth.
  const noauth = await call(env, 'POST', `/admin/credentials/${issued.id}/revoke`, { json: {} })
  ok('revoke without operator auth is 401', noauth.status === 401)
}

// ===================================================================== ② api keys
async function testApiKeys() {
  console.log('\n[②] API keys — mint / use / list / revoke')
  const env = makeEnv()
  const mintRes = await call(env, 'POST', '/admin/keys', { token: OPS, json: { tenant_id: 'consumer-x', scopes: ['wallets:create', 'credentials:read'] } })
  const minted = await mintRes.json() as { id: string; key: string; key_prefix: string; key_hash?: string }
  ok('mint returns plaintext tk_ key', mintRes.status === 201 && minted.key?.startsWith('tk_'))
  ok('mint never returns the hash', minted.key_hash === undefined)

  // The key works against an authed route.
  const useRes = await call(env, 'POST', '/wallets', { token: minted.key, json: { provider: 'p', provider_uid: 'u1' } })
  ok('minted key authenticates a request', useRes.status === 200)

  // Minting requires operator auth and a valid scope.
  const noauth = await call(env, 'POST', '/admin/keys', { json: { tenant_id: 'x', scopes: ['wallets:create'] } })
  ok('mint without operator auth is 401', noauth.status === 401)
  const badScope = await call(env, 'POST', '/admin/keys', { token: OPS, json: { tenant_id: 'x', scopes: ['not:a:scope'] } })
  ok('mint with no valid scope is 400', badScope.status === 400)

  // List is metadata-only.
  const list = await (await call(env, 'GET', '/admin/keys', { token: OPS })).json() as { keys: Array<Record<string, unknown>> }
  const row = list.keys.find((k) => k.id === minted.id)
  ok('list shows the key by prefix', row?.key_prefix === minted.key_prefix)
  ok('list never leaks hash or plaintext', row !== undefined && !('key_hash' in row!) && !('key' in row!))

  // Revoke disables it.
  const revoke = await call(env, 'POST', `/admin/keys/${minted.id}/revoke`, { token: OPS })
  ok('revoke accepted', revoke.status === 200)
  const afterRevoke = await call(env, 'POST', '/wallets', { token: minted.key, json: { provider: 'p', provider_uid: 'u2' } })
  ok('revoked key no longer authenticates', afterRevoke.status === 401)
}

// ===================================================================== ③ custody
async function testCustodyHandoff() {
  console.log('\n[③] Custody handoff — server → self')
  const env = makeEnv()
  const { key } = await mintKey(env, 'consumer-c', ['wallets:create'])
  const walletId = await newWallet(env, key)

  // Holder generates their OWN key client-side.
  const holder = await generateEd25519Keypair()
  const holderMultikey = multikeyFromPublicKey(holder.publicKey)

  const before = await (await call(env, 'GET', `/w/${walletId}/did.jsonl`)).text()
  ok('pre-handoff log verifies (inception only)', (await verifyWebvhLog(before)).verified, `${before.trim().split('\n').length} entry`)

  const handoff = await call(env, 'POST', `/w/${walletId}/custody/handoff`, { token: OPS, json: { public_key_multibase: holderMultikey } })
  const hj = await handoff.json() as { ok?: boolean; custody_state?: string; did?: string }
  ok('handoff accepted, custody_state self', handoff.status === 200 && hj.custody_state === 'self')

  const wRow = await env.DB.prepare('SELECT custody_state FROM wallets WHERE id = ?').bind(walletId).first<{ custody_state: string }>()
  ok('wallet marked self-custodied in DB', wRow?.custody_state === 'self')
  const rk = await env.DB.prepare('SELECT retired_at FROM receiver_keys WHERE user_id = ?').bind(walletId).first<{ retired_at: string | null }>()
  ok('server receiver key retired (retained, disabled)', !!rk?.retired_at)

  const after = await (await call(env, 'GET', `/w/${walletId}/did.jsonl`)).text()
  const lines = after.trim().split('\n')
  ok('post-handoff log has 2 chained entries', lines.length === 2)
  const verified = await verifyWebvhLog(after)
  ok('post-handoff log verifies end-to-end', verified.verified, verified.reason)
  const latest = verified.doc as { authentication?: string[]; verificationMethod?: Array<{ id: string; publicKeyMultibase: string }> } | undefined
  const authoritative = latest?.authentication?.[0]
  const holderVm = latest?.verificationMethod?.find((v) => v.id === authoritative)
  ok('holder key is now authoritative', holderVm?.publicKeyMultibase === holderMultikey)

  // The did:web mirror (did.json) must also present the holder key, never the
  // retired server key.
  const didJson = await (await call(env, 'GET', `/w/${walletId}/did.json`)).json() as { verificationMethod?: Array<{ publicKeyMultibase: string }> }
  ok('did.json now serves the holder key', didJson.verificationMethod?.[0]?.publicKeyMultibase === holderMultikey)

  const twice = await call(env, 'POST', `/w/${walletId}/custody/handoff`, { token: OPS, json: { public_key_multibase: holderMultikey } })
  ok('second handoff is rejected (409)', twice.status === 409)

  const badKey = await call(env, 'POST', `/w/${await newWallet(env, key)}/custody/handoff`, { token: OPS, json: { public_key_multibase: 'znotakey' } })
  ok('non-Ed25519 key rejected (400)', badKey.status === 400)
}

// ===================================================================== ④ did:webvh
async function testWebvhVerification() {
  console.log('\n[④] did:webvh — good log passes, tampered fails closed')
  const env = makeEnv()
  const { key } = await mintKey(env, 'consumer-w', ['wallets:create'])
  const walletId = await newWallet(env, key)
  const good = await (await call(env, 'GET', `/w/${walletId}/did.jsonl`)).text()

  ok('known-good emitted log verifies', (await verifyWebvhLog(good)).verified)

  const entry = JSON.parse(good.trim()) as Record<string, unknown>

  // Tamper 1 — scid.
  const t1 = structuredClone(entry) as { parameters: { scid: string } }
  t1.parameters.scid = t1.parameters.scid.slice(0, -2) + 'xy'
  ok('tampered scid fails', !(await verifyWebvhLog(JSON.stringify(t1))).verified)

  // Tamper 2 — the signed state (controller swap) breaks the proof + chain.
  const t2 = structuredClone(entry) as { state: { verificationMethod: Array<{ publicKeyMultibase: string }> } }
  t2.state.verificationMethod[0].publicKeyMultibase = 'z6Mkfake0000000000000000000000000000000000000000'
  ok('tampered DID document fails', !(await verifyWebvhLog(JSON.stringify(t2))).verified)

  // Tamper 3 — the proof value.
  const t3 = structuredClone(entry) as { proof: { proofValue: string } }
  const pv = t3.proof.proofValue
  t3.proof.proofValue = pv.slice(0, -3) + (pv.endsWith('z') ? 'aaa' : 'zzz')
  ok('tampered proofValue fails', !(await verifyWebvhLog(JSON.stringify(t3))).verified)

  // Tamper 4 — versionTime breaks the entry-hash chain.
  const t4 = structuredClone(entry) as { versionTime: string }
  t4.versionTime = '1999-01-01T00:00:00.000Z'
  ok('tampered entry-hash chain fails', !(await verifyWebvhLog(JSON.stringify(t4))).verified)

  // Empty / malformed logs fail closed.
  ok('empty log fails', !(await verifyWebvhLog('')).verified)
  ok('malformed JSONL fails', !(await verifyWebvhLog('{not json')).verified)
}

async function main() {
  await testStatusList()
  await testApiKeys()
  await testCustodyHandoff()
  await testWebvhVerification()
  console.log(`\n${fail === 0 ? 'ACCEPTANCE PASS' : 'ACCEPTANCE FAIL'} — ${pass} passed, ${fail} failed`)
  if (fail > 0) (globalThis as { process?: { exitCode: number } }).process!.exitCode = 1
}

main().catch((e) => { console.error(e); (globalThis as { process?: { exitCode: number } }).process!.exitCode = 1 })
