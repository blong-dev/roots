/**
 * Content-addressing primitives for verifiable credentials.
 *
 * canonicalize()    — RFC 8785-style canonical JSON (keys sorted, no whitespace).
 *                     Sufficient for our payloads; no number/string normalization
 *                     beyond JSON.stringify is needed because we never put
 *                     floats with surplus precision or non-canonical strings
 *                     into hashed objects.
 * sha256Multihash() — SHA-256 over the canonical bytes, encoded as a multihash
 *                     (0x12 0x20 + 32 bytes), multibase base58btc ('z' prefix).
 *                     The resulting "zQm…" string is what `tool_hash` etc. are.
 * multibase58 / Decode — minimal base58btc codec for multibase ('z' prefix).
 *
 * All routines are pure WebCrypto (sha-256) + arithmetic; no deps.
 */

// -------------------------------------------------------------- base58btc
// Bitcoin base58 alphabet.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

// guid:base58btc-encode
// guid:df586ff0-0a68-4932-a15b-ad4d4f40e2d9
function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return ''
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++

  // log(256) / log(58) ≈ 1.366; size = ceil(n * 138/100) + 1 covers any input.
  const size = Math.ceil(((bytes.length - zeros) * 138) / 100) + 1
  const out = new Uint8Array(size)
  let length = 0

  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]
    let j = 0
    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 256 * out[k]
      out[k] = carry % 58
      carry = Math.floor(carry / 58)
    }
    length = j
  }

  let it = size - length
  while (it < size && out[it] === 0) it++

  let s = '1'.repeat(zeros)
  for (; it < size; it++) s += B58[out[it]]
  return s
}

// guid:base58btc-decode
// guid:f97c320a-8937-4f7d-a997-1220c8f3979a
function base58btcDecode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0)
  let zeros = 0
  while (zeros < str.length && str[zeros] === '1') zeros++

  const size = Math.ceil(((str.length - zeros) * 733) / 1000) + 1
  const out = new Uint8Array(size)
  let length = 0

  for (let i = zeros; i < str.length; i++) {
    const idx = B58.indexOf(str[i])
    if (idx < 0) throw new Error(`Invalid base58 character: ${str[i]}`)
    let carry = idx
    let j = 0
    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 58 * out[k]
      out[k] = carry % 256
      carry = Math.floor(carry / 256)
    }
    length = j
  }

  let it = size - length
  while (it < size && out[it] === 0) it++

  const result = new Uint8Array(zeros + (size - it))
  for (let i = 0; i < size - it; i++) result[zeros + i] = out[it + i]
  return result
}

// --------------------------------------------------------------- multibase
/** Multibase base58btc — 'z' prefix per the W3C multibase spec. */
// guid:6d7597a2-0a73-4b0c-873d-cb9ca5b4ec93
export function multibase58(bytes: Uint8Array): string {
  return 'z' + base58btcEncode(bytes)
}

// guid:fcacbfca-5f0c-4907-9395-c823bc83b7be
export function multibase58Decode(s: string): Uint8Array {
  if (!s.startsWith('z')) throw new Error('Expected multibase base58btc prefix "z"')
  return base58btcDecode(s.slice(1))
}

// --------------------------------------------------------------- canonical JSON
/**
 * RFC 8785-style canonical JSON. Object keys sorted at every level; no
 * whitespace. Sufficient for our hashed payloads — we don't put untrusted
 * numbers, dates, or non-NFC strings into them.
 */
// guid:6a28d31b-2482-43e3-a624-2e7b6ed474f9
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']'
  }
  const keys = Object.keys(value as Record<string, unknown>).sort()
  return (
    '{' +
    keys
      .map((k) => JSON.stringify(k) + ':' + canonicalize((value as Record<string, unknown>)[k]))
      .join(',') +
    '}'
  )
}

// --------------------------------------------------------------- sha-256 multihash
/**
 * SHA-256 multihash, multibase base58btc-encoded. The string returned is what
 * every `*_hash` field in the credential schema holds.
 *
 *   0x12 = multicodec sha2-256
 *   0x20 = digest length (32 bytes)
 */
// guid:af3a43c5-1b93-413c-85c4-0fc93e5866fd
export async function sha256Multihash(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  const mh = new Uint8Array(2 + digest.length)
  mh[0] = 0x12
  mh[1] = 0x20
  mh.set(digest, 2)
  return multibase58(mh)
}

/** Hash a structure: canonicalize → SHA-256 → multihash. */
// guid:e4967bc4-05ca-4398-9bee-38db306755fc
export async function hashObject(value: unknown): Promise<{ hash: string; canonical: string }> {
  const canonical = canonicalize(value)
  const hash = await sha256Multihash(canonical)
  return { hash, canonical }
}
