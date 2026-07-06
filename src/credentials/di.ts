/**
 * di.ts — W3C Data Integrity proofs, cryptosuite `eddsa-jcs-2022`.
 *
 * Implements the ACTUAL suite transform (VC-DI-EDDSA §3.3), not a relabel:
 *   proofConfig      = proof options + the document's @context
 *   hashData         = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDoc))
 *   proofValue       = multibase base58btc of Ed25519 sig over hashData
 *
 * This replaces the pre-profile shape (an `Ed25519Signature2020` label over a
 * bare JCS of the document), which no conformant verifier accepted. Normative
 * spec: dreamtree/credential-profile.md §2 (DTW Credential Profile v1).
 */

import { canonicalize, multibase58, multibase58Decode } from './canonical'
import { ed25519Sign, ed25519Verify } from './keys'

export const CRYPTOSUITE = 'eddsa-jcs-2022'

export interface DataIntegrityProof {
  '@context'?: unknown
  type: 'DataIntegrityProof'
  cryptosuite: string
  created: string
  verificationMethod: string
  proofPurpose: string
  proofValue: string
}

// guid:abe3ea92-a338-4189-a922-d7e0407169fb
async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource))
}

// guid:22e0618e-2888-4725-8871-9cb58daf872b
async function hashData(
  proofConfig: Record<string, unknown>,
  unsecuredDoc: Record<string, unknown>,
): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const configHash = await sha256(enc.encode(canonicalize(proofConfig)))
  const docHash = await sha256(enc.encode(canonicalize(unsecuredDoc)))
  const out = new Uint8Array(64)
  out.set(configHash, 0)
  out.set(docHash, 32)
  return out
}

/** Create an eddsa-jcs-2022 DataIntegrityProof over `unsecuredDoc`. */
// guid:di-createProof
// guid:eebfeb4c-19b0-4c7c-90a5-52597d6afeae
export async function createDataIntegrityProof(
  unsecuredDoc: Record<string, unknown>,
  opts: {
    privateJwk: JsonWebKey
    verificationMethod: string
    proofPurpose: 'assertionMethod' | 'authentication'
    created?: string
  },
): Promise<DataIntegrityProof> {
  const proofConfig: Record<string, unknown> = {
    // Per the suite: proofConfig.@context MUST be the document's @context.
    '@context': unsecuredDoc['@context'],
    type: 'DataIntegrityProof',
    cryptosuite: CRYPTOSUITE,
    created: opts.created ?? new Date().toISOString(),
    verificationMethod: opts.verificationMethod,
    proofPurpose: opts.proofPurpose,
  }
  const digest = await hashData(proofConfig, unsecuredDoc)
  const sig = await ed25519Sign(opts.privateJwk, digest)
  return { ...(proofConfig as Omit<DataIntegrityProof, 'proofValue'>), proofValue: multibase58(sig) }
}

/**
 * Verify one eddsa-jcs-2022 proof against `unsecuredDoc` (the document with
 * the `proof` member removed) and a raw 32-byte Ed25519 public key.
 */
// guid:di-verifyProof
// guid:4e110812-eac5-4a1d-8482-0145466aa60d
export async function verifyDataIntegrityProof(
  unsecuredDoc: Record<string, unknown>,
  proof: DataIntegrityProof,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== CRYPTOSUITE) return false
  const { proofValue, ...proofConfig } = proof
  const digest = await hashData(proofConfig as Record<string, unknown>, unsecuredDoc)
  try {
    return await ed25519Verify(publicKey, digest, multibase58Decode(proofValue))
  } catch {
    return false
  }
}
