/**
 * routes/ica.ts — CAWG Identity Claims Aggregation, mounted at /ica.
 *
 * roots as an Identity Claims Aggregator (CAWG identity assertion 1.2 §8.1):
 * issues IdentityClaimsAggregationCredential VCs binding a named actor to
 * their verified identities, for embedding in C2PA manifests (sig_type
 * cawg.ica). There is deliberately no aggregator trust list in CAWG 1.2 —
 * validators exercise discretion — so a working aggregator is admissible
 * from day one; being early IS the strategy (EARWORM.md).
 *
 *   GET  /ica/status  public: enabled flag + issuer DID
 *   POST /ica/issue   operator-gated: issue an ICA for a subject
 *
 * Ships dark: every route 404s until ROOTS_ICA_ENABLED is set. First real
 * subject is HometownWire via cawg.web_site (verifiable without KYC).
 * Embedding the resulting VC as a manifest identity assertion (CBOR/COSE
 * assembly) is the post-membership CAWG work item; this endpoint makes the
 * credential side real first.
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { operatorAuth } from '../auth'
import { getOrCreateIssuerKey } from '../credentials/keystore'
import { issuerVerificationMethod } from '../credentials/keys'
import { createDataIntegrityProof } from '../credentials/di'

const ROOTS_SIGNER = 'roots' // same issuer scope as the export-signing key

// CAWG 1.2 verifiedIdentities types. cawg.web_site and cawg.affiliation are
// the pilot-relevant ones (no KYC dependency).
const IDENTITY_TYPES = new Set([
  'cawg.document_verification',
  'cawg.affiliation',
  'cawg.social_media',
  'cawg.crypto_wallet',
  'cawg.web_site',
])

// Context URL per the published CAWG identity assertion spec. Confirm against
// the ratified 1.2 artifacts once WG membership lands (MONDAY-RUNBOOK).
const ICA_CONTEXT = 'https://cawg.io/identity/1.1/ica/context/'

const PROVIDER = { id: 'https://id.dreamtree.org', name: 'dreamtree roots' }

interface VerifiedIdentityInput {
  type?: string
  name?: string
  username?: string
  uri?: string
  verifiedAt?: string
}

const ica = new Hono<Env>()

// Dark until explicitly enabled — the whole surface reads as absent.
ica.use('*', async (c, next) => {
  if (!c.env.ROOTS_ICA_ENABLED) return c.json({ error: 'not found' }, 404)
  await next()
})

// guid:roots-ica-status
ica.get('/status', async (c) => {
  const kek = typeof c.env.ROOTS_KEK === 'string' ? c.env.ROOTS_KEK : await c.env.ROOTS_KEK?.get()
  if (!kek) return c.json({ error: 'signing key unavailable (ROOTS_KEK not provisioned)' }, 503)
  const key = await getOrCreateIssuerKey(c.env.DB, kek, ROOTS_SIGNER)
  return c.json({
    enabled: true,
    issuer: key.did,
    credential: 'IdentityClaimsAggregationCredential',
    identityTypes: [...IDENTITY_TYPES],
  })
})

// guid:roots-ica-issue
ica.post('/issue', operatorAuth, async (c) => {
  const b = await c.req
    .json<{
      subject?: string
      verifiedIdentities?: VerifiedIdentityInput[]
      c2paAsset?: Record<string, unknown>
      validDays?: number
    }>()
    .catch(() => null)
  const subject = b?.subject?.trim()
  if (!subject) return c.json({ error: 'subject (DID or URI of the named actor) required' }, 400)
  const inputs = b?.verifiedIdentities
  if (!Array.isArray(inputs) || inputs.length === 0) {
    return c.json({ error: 'verifiedIdentities (non-empty array) required' }, 400)
  }

  const now = new Date()
  const verifiedIdentities = []
  for (const v of inputs) {
    if (!v.type || !IDENTITY_TYPES.has(v.type)) {
      return c.json({ error: `verifiedIdentities[].type must be one of ${[...IDENTITY_TYPES].join(', ')}` }, 400)
    }
    if ((v.type === 'cawg.web_site' || v.type === 'cawg.social_media') && !v.uri) {
      return c.json({ error: `${v.type} requires uri` }, 400)
    }
    verifiedIdentities.push({
      type: v.type,
      ...(v.name ? { name: v.name } : {}),
      ...(v.username ? { username: v.username } : {}),
      ...(v.uri ? { uri: v.uri } : {}),
      verifiedAt: v.verifiedAt ?? now.toISOString(),
      provider: PROVIDER,
    })
  }

  const kek = typeof c.env.ROOTS_KEK === 'string' ? c.env.ROOTS_KEK : await c.env.ROOTS_KEK?.get()
  if (!kek) return c.json({ error: 'signing key unavailable (ROOTS_KEK not provisioned)' }, 503)
  const key = await getOrCreateIssuerKey(c.env.DB, kek, ROOTS_SIGNER)

  const validDays = Math.min(Math.max(b?.validDays ?? 90, 1), 366)
  const unsecured: Record<string, unknown> = {
    '@context': ['https://www.w3.org/ns/credentials/v2', ICA_CONTEXT],
    type: ['VerifiableCredential', 'IdentityClaimsAggregationCredential'],
    issuer: key.did,
    validFrom: now.toISOString(),
    validUntil: new Date(now.getTime() + validDays * 86400_000).toISOString(),
    credentialSubject: {
      id: subject,
      verifiedIdentities,
      // Binds the credential to one C2PA identity assertion when supplied
      // (the signer_payload from hwsignd); omitted = subject-level credential.
      ...(b?.c2paAsset ? { c2paAsset: b.c2paAsset } : {}),
    },
  }
  const proof = await createDataIntegrityProof(unsecured, {
    privateJwk: key.privateJwk,
    verificationMethod: issuerVerificationMethod(key.did),
    proofPurpose: 'assertionMethod',
  })
  return c.json({ credential: { ...unsecured, proof } })
})

export default ica
