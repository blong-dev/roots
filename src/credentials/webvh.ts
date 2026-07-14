/**
 * webvh.ts — did:webvh verifiable-history log: emit AND verify, one source of
 * truth for the hashing so the two can never drift.
 *
 * A did:webvh log is JSON Lines, one entry per line. Each entry:
 *   { "@context", versionId, versionTime, parameters, state, proof }
 * where
 *   - versionId   = `<n>-<entryHash>`; entryHash chains the entry to the previous
 *                   one (the SCID for n=1), so re-ordering or editing any entry
 *                   breaks every later versionId.
 *   - parameters  = { method, scid, updateKeys }; updateKeys are the Multikeys
 *                   authorized to sign the NEXT entry (authority rotation).
 *   - state       = the DID document at that version.
 *   - proof       = an eddsa-jcs-2022 Data Integrity proof (reuses di.ts) by a key
 *                   authorized as of the PREVIOUS entry (self for the inception).
 *   - scid        = the Self-Certifying IDentifier: the hash of the inception
 *                   entry with every occurrence of the SCID replaced by a
 *                   placeholder. It makes the log's identity forgery-proof.
 *
 * verifyWebvhLog checks all three: SCID self-certification, the entry-hash chain,
 * and per-entry authorized signatures. It fails CLOSED — any break returns
 * { verified:false }.
 */

import { canonicalize, sha256Multihash, multibase58Decode } from './canonical'
import { createDataIntegrityProof, verifyDataIntegrityProof, type DataIntegrityProof } from './di'

const ED25519_MULTICODEC = [0xed, 0x01]
const PLACEHOLDER = '{SCID}'
const METHOD = 'did:webvh:1.0'
const ENTRY_CONTEXT = ['https://www.w3.org/ns/credentials/v2']
const DID_DOC_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1']

export type WebvhEntry = Record<string, unknown>

// guid:webvh-rawFromMultikey
function rawFromMultikey(mk: string): Uint8Array | null {
  try {
    const d = multibase58Decode(mk)
    if (d[0] !== ED25519_MULTICODEC[0] || d[1] !== ED25519_MULTICODEC[1]) return null
    return d.slice(2)
  } catch {
    return null
  }
}

// guid:webvh-didFor
export function webvhDid(scid: string, domain: string, walletId: string): string {
  return `did:webvh:${scid}:${domain}:w:${walletId}`
}

// guid:webvh-inceptionDoc
function inceptionDoc(did: string, serverMultikey: string): Record<string, unknown> {
  const vm = `${did}#key-1`
  return {
    '@context': DID_DOC_CONTEXT,
    id: did,
    verificationMethod: [{ id: vm, type: 'Multikey', controller: did, publicKeyMultibase: serverMultikey }],
    authentication: [vm],
    assertionMethod: [vm],
  }
}

// guid:webvh-handoffDoc — the holder key (#key-2) becomes authoritative; the
// server key (#key-1) is RETAINED in the doc (append-only) but dropped from
// authentication/assertionMethod and from the next-entry updateKeys.
function handoffDoc(did: string, serverMultikey: string, holderMultikey: string): Record<string, unknown> {
  const vm1 = `${did}#key-1`
  const vm2 = `${did}#key-2`
  return {
    '@context': DID_DOC_CONTEXT,
    id: did,
    verificationMethod: [
      { id: vm1, type: 'Multikey', controller: did, publicKeyMultibase: serverMultikey },
      { id: vm2, type: 'Multikey', controller: did, publicKeyMultibase: holderMultikey },
    ],
    authentication: [vm2],
    assertionMethod: [vm2],
  }
}

export interface InceptionOpts {
  walletId: string
  domain: string
  serverMultikey: string // z6Mk… Multikey of the server receiver key
  privateJwk: JsonWebKey // server receiver private key
  created: string        // deterministic (wallet created_at) so the entry regenerates identically
}

export interface InceptionResult {
  entry: WebvhEntry
  did: string
  scid: string
  versionId: string
}

/** Build the signed did:webvh inception (version 1). Deterministic given inputs. */
// guid:webvh-buildInception
export async function buildWebvhInception(o: InceptionOpts): Promise<InceptionResult> {
  // Preliminary entry: everything the SCID depends on, with the SCID itself a
  // placeholder. The SCID is the hash of this.
  const placeholderDid = webvhDid(PLACEHOLDER, o.domain, o.walletId)
  const prelim: WebvhEntry = {
    '@context': ENTRY_CONTEXT,
    versionId: PLACEHOLDER,
    versionTime: o.created,
    parameters: { method: METHOD, scid: PLACEHOLDER, updateKeys: [o.serverMultikey] },
    state: inceptionDoc(placeholderDid, o.serverMultikey),
  }
  const scid = await sha256Multihash(canonicalize(prelim))
  const did = webvhDid(scid, o.domain, o.walletId)
  const params = { method: METHOD, scid, updateKeys: [o.serverMultikey] }
  const state = inceptionDoc(did, o.serverMultikey)
  // entryHash chains to the SCID for the inception.
  const hashInput: WebvhEntry = { '@context': ENTRY_CONTEXT, versionId: scid, versionTime: o.created, parameters: params, state }
  const versionId = `1-${await sha256Multihash(canonicalize(hashInput))}`
  const unsigned: WebvhEntry = { '@context': ENTRY_CONTEXT, versionId, versionTime: o.created, parameters: params, state }
  const proof = await createDataIntegrityProof(unsigned, {
    privateJwk: o.privateJwk,
    verificationMethod: `${did}#key-1`,
    proofPurpose: 'authentication',
    created: o.created,
  })
  return { entry: { ...unsigned, proof }, did, scid, versionId }
}

export interface HandoffOpts {
  did: string
  scid: string
  version: number       // 2, 3, …
  prevVersionId: string // versionId of the entry before this one
  serverMultikey: string
  holderMultikey: string
  privateJwk: JsonWebKey // the SERVER key — authorized by the previous entry's updateKeys
  created: string
}

/** Build the signed custody-handoff entry: rotates authority to the holder key. */
// guid:webvh-buildHandoff
export async function buildWebvhHandoffEntry(o: HandoffOpts): Promise<{ entry: WebvhEntry; versionId: string }> {
  const params = { method: METHOD, scid: o.scid, updateKeys: [o.holderMultikey] }
  const state = handoffDoc(o.did, o.serverMultikey, o.holderMultikey)
  const hashInput: WebvhEntry = { '@context': ENTRY_CONTEXT, versionId: o.prevVersionId, versionTime: o.created, parameters: params, state }
  const versionId = `${o.version}-${await sha256Multihash(canonicalize(hashInput))}`
  const unsigned: WebvhEntry = { '@context': ENTRY_CONTEXT, versionId, versionTime: o.created, parameters: params, state }
  // Signed by the server key (#key-1), which IS in the previous entry's updateKeys.
  const proof = await createDataIntegrityProof(unsigned, {
    privateJwk: o.privateJwk,
    verificationMethod: `${o.did}#key-1`,
    proofPurpose: 'authentication',
    created: o.created,
  })
  return { entry: { ...unsigned, proof }, versionId }
}

export interface WebvhResult {
  verified: boolean
  doc?: Record<string, unknown>
  did?: string
  reason?: string
}

interface Vm { id?: string; publicKeyMultibase?: string }

/**
 * Verify a full did:webvh log. Returns { verified:true, doc, did } only when the
 * SCID self-certifies, every versionId hashes the previous entry, and every entry
 * carries a valid proof from a key authorized at that point. Fails CLOSED.
 */
// guid:webvh-verifyLog
export async function verifyWebvhLog(logText: string): Promise<WebvhResult> {
  const lines = logText.split('\n').map((l) => l.trim()).filter(Boolean)
  if (lines.length === 0) return { verified: false, reason: 'empty log' }
  let entries: WebvhEntry[]
  try {
    entries = lines.map((l) => JSON.parse(l) as WebvhEntry)
  } catch {
    return { verified: false, reason: 'invalid JSONL' }
  }

  const first = entries[0]
  const firstParams = first.parameters as { scid?: string; updateKeys?: string[] } | undefined
  const scid = firstParams?.scid
  if (typeof scid !== 'string' || !scid) return { verified: false, reason: 'missing scid' }

  // 1) SCID self-certification: re-derive the placeholder inception and hash it.
  {
    const prelim = structuredClone(first) as WebvhEntry
    delete prelim.proof
    const placeheld = JSON.parse(JSON.stringify(prelim).split(scid).join(PLACEHOLDER)) as WebvhEntry
    placeheld.versionId = PLACEHOLDER
    const computed = await sha256Multihash(canonicalize(placeheld))
    if (computed !== scid) return { verified: false, reason: 'scid does not self-certify' }
  }

  // 2) Entry-hash chain + 3) authorized signatures.
  let prevVersionId = scid
  let prevUpdateKeys: string[] = Array.isArray(firstParams?.updateKeys) ? firstParams!.updateKeys! : []
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]
    const n = i + 1
    if (typeof e.versionId !== 'string' || !(e.versionId as string).startsWith(`${n}-`)) {
      return { verified: false, reason: `versionId format break at entry ${n}` }
    }
    // entry-hash chain
    const hashInput = structuredClone(e) as WebvhEntry
    delete hashInput.proof
    hashInput.versionId = prevVersionId
    const computed = await sha256Multihash(canonicalize(hashInput))
    if (e.versionId !== `${n}-${computed}`) return { verified: false, reason: `entry-hash chain break at entry ${n}` }

    // authorized signer: the key must be in the PREVIOUS entry's updateKeys
    // (the inception self-authorizes with its own updateKeys).
    const authorized = i === 0 ? (Array.isArray(firstParams?.updateKeys) ? firstParams!.updateKeys! : []) : prevUpdateKeys
    const proofs = Array.isArray(e.proof) ? (e.proof as DataIntegrityProof[]) : e.proof ? [e.proof as DataIntegrityProof] : []
    const proof = proofs[0]
    if (!proof) return { verified: false, reason: `missing proof at entry ${n}` }
    const state = e.state as Record<string, unknown> | undefined
    const vms = (state?.verificationMethod as Vm[] | undefined) ?? []
    const signer = vms.find((v) => v.id === proof.verificationMethod) ?? (vms.length === 1 ? vms[0] : undefined)
    const mk = signer?.publicKeyMultibase
    if (!mk || !authorized.includes(mk)) return { verified: false, reason: `signer not authorized at entry ${n}` }
    const raw = rawFromMultikey(mk)
    if (!raw) return { verified: false, reason: `unusable signing key at entry ${n}` }
    const { proof: _omit, ...unsigned } = e
    const ok = await verifyDataIntegrityProof(unsigned as Record<string, unknown>, proof, raw)
    if (!ok) return { verified: false, reason: `proof does not verify at entry ${n}` }

    prevVersionId = e.versionId as string
    const params = e.parameters as { updateKeys?: string[] } | undefined
    if (Array.isArray(params?.updateKeys)) prevUpdateKeys = params!.updateKeys!
  }

  const latest = entries[entries.length - 1]
  const doc = latest.state as Record<string, unknown> | undefined
  return { verified: true, doc, did: typeof doc?.id === 'string' ? (doc.id as string) : undefined }
}
