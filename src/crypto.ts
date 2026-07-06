/**
 * crypto.ts — envelope encryption for per-tenant secrets.
 *
 * One key-encryption key (TELEKORA_KEK, 32 random bytes base64) lives in
 * Cloudflare Secrets Store. Per-tenant LLM API keys are AES-GCM encrypted
 * under it and only `{ciphertext, iv}` (base64) are stored in D1. Plaintext
 * keys are never persisted, logged, or returned by any endpoint.
 */
function b64encode(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

async function importKek(kekB64: string): Promise<CryptoKey> {
  const raw = b64decode(kekB64.trim())
  if (raw.length !== 32) {
    throw new Error(`TELEKORA_KEK must be 32 bytes base64 (got ${raw.length})`)
  }
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ])
}

export async function encryptSecret(
  kekB64: string,
  plaintext: string,
): Promise<{ ciphertext: string; iv: string }> {
  const key = await importKek(kekB64)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const buf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext),
  )
  return { ciphertext: b64encode(new Uint8Array(buf)), iv: b64encode(iv) }
}

export async function decryptSecret(
  kekB64: string,
  ciphertextB64: string,
  ivB64: string,
): Promise<string> {
  const key = await importKek(kekB64)
  const buf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(ivB64) },
    key,
    b64decode(ciphertextB64),
  )
  return new TextDecoder().decode(buf)
}
