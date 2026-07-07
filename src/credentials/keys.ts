/**
 * Ed25519 keypair generation, signing, verification, and did:key encoding.
 *
 * Storage shape (issuer_keys / receiver_keys):
 *   - public_key_multibase  — multibase base58btc of the raw 32-byte pubkey
 *   - encrypted_private_jwk — AES-GCM ciphertext of JSON.stringify(JWK) under
 *                             TELEKORA_KEK (via api/src/crypto.ts envelope)
 *   - encryption_iv         — base64 IV
 *
 * The private key is stored as a JWK (not raw seed) because WebCrypto's
 * Ed25519 import only accepts JWK or PKCS8 for the private side — both
 * require the public point, which can't be derived from the seed alone
 * without the curve math we'd otherwise have to inline.
 */

import { encryptSecret, decryptSecret } from '../crypto'
import { multibase58, multibase58Decode } from './canonical'

// Multicodec prefix for Ed25519 pubkey (varint 0xed → 0xed 0x01).
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01])

// ----------------------------------------------------------- generation
export interface GeneratedKeypair {
  publicKey: Uint8Array              // 32 bytes raw
  privateJwk: JsonWebKey             // includes both d (seed) and x (pubkey)
}

/** Generate a fresh Ed25519 keypair via WebCrypto. */
// guid:c880b027-531c-4468-b700-93dff60f6fe1
export async function generateEd25519Keypair(): Promise<GeneratedKeypair> {
  const kp = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair
  const rawPub = (await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer
  const publicKey = new Uint8Array(rawPub)
  const privateJwk = (await crypto.subtle.exportKey('jwk', kp.privateKey)) as JsonWebKey
  return { publicKey, privateJwk }
}

// ----------------------------------------------------------- did:key (Ed25519)
/** Encode raw 32-byte pubkey as a `did:key:z6Mk…` identifier. */
// guid:83c19ee3-59c7-4b06-83b5-4074aa294a55
export function didKeyFromPublicKey(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) throw new Error('Ed25519 pubkey must be 32 bytes')
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + pubkey.length)
  prefixed.set(ED25519_MULTICODEC, 0)
  prefixed.set(pubkey, ED25519_MULTICODEC.length)
  return 'did:key:' + multibase58(prefixed)
}

/** Recover the raw 32-byte pubkey from a did:key. Throws if not Ed25519. */
// guid:e7935833-739b-487d-879a-1bc67eb71610
export function publicKeyFromDidKey(did: string): Uint8Array {
  const prefix = 'did:key:'
  if (!did.startsWith(prefix)) throw new Error('Not a did:key')
  const decoded = multibase58Decode(did.slice(prefix.length))
  if (decoded[0] !== ED25519_MULTICODEC[0] || decoded[1] !== ED25519_MULTICODEC[1]) {
    throw new Error('did:key is not Ed25519')
  }
  return decoded.slice(ED25519_MULTICODEC.length)
}

/** W3C verification method id — `<did>#<key-fragment>` per did:key resolution. */
// guid:5eb2222b-5684-4ce3-9e43-2364b75b81e8
export function verificationMethodFromDid(did: string): string {
  const fragment = did.slice('did:key:'.length)
  return `${did}#${fragment}`
}

// ----------------------------------------------------------- did:web (issuers)
// Profile §3 (dreamtree/credential-profile.md): institutional issuers use
// did:web — rotation via the served DID document. Tenant DIDs live under the
// platform domain until a white-label tenant graduates to its own domain.
export const DID_WEB_DOMAIN = 'dreamtree.org'

// guid:keys-didWebForTenant
// guid:63c8fed6-e9e1-4980-984d-66b73cd19373
export function didWebForTenant(tenantId: string, domain = DID_WEB_DOMAIN): string {
  return `did:web:${domain}:tenants:${tenantId}`
}

/** Stable key fragment for did:web issuers (rotation bumps to #key-2 …). */
// guid:keys-issuerVerificationMethod
// guid:d1a3fb5d-169b-4e7a-9cfa-fa1a53ef7177
export function issuerVerificationMethod(did: string): string {
  return did.startsWith('did:web:') ? `${did}#key-1` : verificationMethodFromDid(did)
}

/** Multikey publicKeyMultibase (z6Mk…): multicodec-prefixed base58btc pubkey. */
// guid:keys-multikeyFromPublicKey
// guid:b9f8afbf-7ef9-4581-8c81-b1e3115a1510
export function multikeyFromPublicKey(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) throw new Error('Ed25519 pubkey must be 32 bytes')
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + pubkey.length)
  prefixed.set(ED25519_MULTICODEC, 0)
  prefixed.set(pubkey, ED25519_MULTICODEC.length)
  return multibase58(prefixed)
}

// ----------------------------------------------------------- sign / verify
/** Sign a message with the keypair's private JWK. Returns the 64-byte sig. */
// guid:f8cdab1d-51d7-4ee9-91ea-4210e423a8f1
export async function ed25519Sign(
  privateJwk: JsonWebKey,
  message: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'Ed25519' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('Ed25519', key, message)
  return new Uint8Array(sig)
}

/** Verify a signature against a raw 32-byte pubkey. */
// guid:519e9f75-2e6f-4d03-9a17-b87c4b5ad8f4
export async function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  )
  return await crypto.subtle.verify('Ed25519', key, signature, message)
}

// ----------------------------------------------------------- envelope storage
/**
 * Wrap a freshly-generated keypair into the storable shape — pubkey multibase
 * + did + AES-GCM-encrypted JWK under the KEK.
 */
// guid:787980a2-f663-4cbd-9574-749da9069654
export async function wrapKeypair(
  kekB64: string,
  kp: GeneratedKeypair,
): Promise<{
  did: string
  publicKeyMultibase: string
  encryptedPrivateJwk: string
  encryptionIv: string
}> {
  const did = didKeyFromPublicKey(kp.publicKey)
  const publicKeyMultibase = multibase58(kp.publicKey)
  const { ciphertext, iv } = await encryptSecret(kekB64, JSON.stringify(kp.privateJwk))
  return {
    did,
    publicKeyMultibase,
    encryptedPrivateJwk: ciphertext,
    encryptionIv: iv,
  }
}

/** Recover the private JWK for signing. Throws on tampering (AES-GCM auth). */
// guid:fc623814-1c14-4386-a87e-8f44c5e86098
export async function unwrapPrivateJwk(
  kekB64: string,
  encryptedPrivateJwk: string,
  encryptionIv: string,
): Promise<JsonWebKey> {
  const json = await decryptSecret(kekB64, encryptedPrivateJwk, encryptionIv)
  return JSON.parse(json) as JsonWebKey
}
