/**
 * phase2-acceptance.ts — offline + live acceptance for the VC Phase 2 verifier.
 *
 * Exercises the REAL verifier modules (no reimplementation) against:
 *   1. LIVE  — a real Phase-1 credential fetched from telekora.com, verified via
 *      a genuine over-the-network did:web DID-document resolution.
 *   2. VC-JWT (EdDSA) — construct + verify a compact JWS credential.
 *   3. Tamper — a mutated credential must drop to self-reported.
 *   4. SSRF  — safeFetch must reject http/private-IP/loopback.
 *   5. Tier  — the honest collapse of checks → tier.
 *
 * Bundle + run:  npx esbuild scripts/phase2-acceptance.ts --bundle --format=esm
 *   --platform=node --outfile=/tmp/.../p2.mjs && node /tmp/.../p2.mjs
 */
import { verifyExternal } from '../src/credentials/verify-external'
import { safeFetch, resolveIssuerKey } from '../src/credentials/resolve'
import { generateEd25519Keypair, didKeyFromPublicKey, verificationMethodFromDid, ed25519Sign } from '../src/credentials/keys'

// A D1 stub that answers every query with null / empty (no registry, no status).
const stubDb: any = {
  prepare: () => ({
    bind: () => ({ first: async () => null, all: async () => ({ results: [] }), run: async () => ({}) }),
    first: async () => null, all: async () => ({ results: [] }), run: async () => ({}),
  }),
}

let pass = 0, fail = 0
// guid:b951c729-fc06-4b43-8481-c437321caae0
function check(name: string, cond: boolean, detail?: string) {
  if (cond) { pass++; console.log(`  ✓ ${name}${detail ? ' — ' + detail : ''}`) }
  else { fail++; console.log(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

// guid:35447458-7129-416f-9961-277d06b36a39
function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// guid:9c3840ca-0c0f-4f3f-8bfb-22b2ff095d45
async function main() {
  // ---------------------------------------------------------------- 1. LIVE
  console.log('\n[1] LIVE — real Phase-1 credential, network did:web resolution')
  // Re-use the known Phase-1 acceptance credential id.
  const KNOWN = '6a1e41d6-fcea-402e-9a65-f250387c6e59'
  const vc = await fetch(`https://telekora.com/api/credentials/${KNOWN}?proofs=external`).then((r) => r.json()).catch(() => null)
  if (!vc || !vc.proof) {
    check('fetched live credential', false, 'could not fetch known Phase-1 credential')
  } else {
    check('fetched live credential', true, `${vc.type?.join?.('+')}`)
    // Force the network path: resolve the issuer's did:web with NO db.
    const vm = (Array.isArray(vc.proof) ? vc.proof : [vc.proof]).find((p: any) => p.proofPurpose === 'assertionMethod')?.verificationMethod
    const key = await resolveIssuerKey(vm, undefined)
    check('did:web resolved over the network', !!key?.raw, key?.method)
    const report = await verifyExternal({ kind: 'json', doc: vc }, stubDb)
    check('proof check passes on live credential', report.checks.find((c) => c.name === 'proof')?.ok === true)
    check('issuer-resolution check passes', report.checks.find((c) => c.name === 'issuer-resolution')?.ok === true)
    // stub db → issuer not in registry → honest tier is valid-signature, NOT verified.
    check('tier is valid-signature (issuer unknown to stub registry)', report.tier === 'valid-signature', report.tier)
  }

  // ---------------------------------------------------------------- 2. VC-JWT
  console.log('\n[2] VC-JWT (EdDSA) — construct + verify')
  {
    const kp = await generateEd25519Keypair()
    const did = didKeyFromPublicKey(kp.publicKey)
    const kid = verificationMethodFromDid(did)
    const header = { alg: 'EdDSA', typ: 'JWT', kid }
    const payload = {
      iss: did, sub: 'did:example:holder',
      vc: {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'], issuer: did,
        name: 'Test JWT Credential',
        credentialSubject: { id: 'did:example:holder' },
        validFrom: new Date(Date.now() - 1000).toISOString(),
      },
    }
    const signingInput = `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.${b64url(new TextEncoder().encode(JSON.stringify(payload)))}`
    const sig = await ed25519Sign(kp.privateJwk, new TextEncoder().encode(signingInput))
    const jwt = `${signingInput}.${b64url(sig)}`
    const report = await verifyExternal({ kind: 'jwt', token: jwt }, stubDb)
    check('VC-JWT proof verifies', report.checks.find((c) => c.name === 'proof')?.ok === true, report.proofMethod)
    check('VC-JWT format detected', report.format === 'vc-jwt', report.format)
    check('VC-JWT tier valid-signature', report.tier === 'valid-signature', report.tier)

    // ---- 3. TAMPER: flip a byte in the signature → must fail.
    console.log('\n[3] Tamper — mutated JWS drops to self-reported')
    const badSig = new Uint8Array(sig); badSig[0] ^= 0xff
    const badJwt = `${signingInput}.${b64url(badSig)}`
    const bad = await verifyExternal({ kind: 'jwt', token: badJwt }, stubDb)
    check('tampered signature rejected', bad.checks.find((c) => c.name === 'proof')?.ok === false)
    check('tampered credential is self-reported', bad.tier === 'self-reported', bad.tier)
  }

  // ---------------------------------------------------------------- 4. SSRF
  console.log('\n[4] SSRF — safeFetch rejects unsafe targets')
  for (const [label, url] of [
    ['http (non-TLS)', 'http://example.com/did.json'],
    ['loopback', 'https://127.0.0.1/did.json'],
    ['link-local metadata', 'https://169.254.169.254/latest/meta-data'],
    ['private 10.x', 'https://10.0.0.2/did.json'],
    ['localhost', 'https://localhost/did.json'],
  ] as const) {
    let rejected = false
    try { await safeFetch(url) } catch { rejected = true }
    check(`rejects ${label}`, rejected)
  }

  // ---------------------------------------------------------------- 5. Manual
  console.log('\n[5] Manual — no crypto is always self-reported')
  {
    const report = await verifyExternal({ kind: 'manual', meta: { issuerName: 'Acme', credentialName: 'OSHA-10' } }, stubDb)
    check('manual entry is self-reported', report.tier === 'self-reported', report.tier)
    check('manual never claims a passing proof', report.checks.every((c) => c.name !== 'proof' || !c.ok))
  }

  console.log(`\n${fail === 0 ? 'ACCEPTANCE PASS' : 'ACCEPTANCE FAIL'} — ${pass} passed, ${fail} failed`)
  if (fail > 0) throw new Error('acceptance failed')
}

main().catch((e) => { console.error(e); (globalThis as { process?: { exitCode: number } }).process!.exitCode = 1 })
