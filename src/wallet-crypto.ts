/**
 * wallet-crypto.ts — encryption at rest for record payloads.
 *
 * Per-wallet AES-256 data key, wrapped under ROOTS_KEK (Secrets Store). Payloads
 * are sealed under the wallet's data key; a D1 dump without the KEK is opaque.
 * Reuses crypto.ts (AES-GCM, random IV per op) for both the wrap and the seal.
 */
import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst, dbRun } from './db'
import { encryptSecret, decryptSecret } from './crypto'

// The KEK binding is a Secrets Store object (prod) or a plain string (dev).
export async function resolveKek(env: { ROOTS_KEK?: { get(): Promise<string> } | string }): Promise<string | null> {
  return typeof env.ROOTS_KEK === 'string' ? env.ROOTS_KEK : (await env.ROOTS_KEK?.get()) ?? null
}

function b64(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s)
}

// guid:roots-walletcrypto-dataKey
/** Get (or create) the wallet's data key, unwrapped. Race-safe: on a concurrent
 *  first write, ON CONFLICT keeps the winner and we re-read + unwrap that one. */
export async function getWalletDataKey(db: D1Database, kekB64: string, walletId: string): Promise<string> {
  const row = await dbFirst<{ enc_key: string; iv: string }>(
    db, 'SELECT enc_key, iv FROM wallet_data_keys WHERE wallet_id = ?', walletId,
  )
  if (row) return await decryptSecret(kekB64, row.enc_key, row.iv)
  const dataKeyB64 = b64(crypto.getRandomValues(new Uint8Array(32)))
  const wrapped = await encryptSecret(kekB64, dataKeyB64)
  await dbRun(
    db,
    `INSERT INTO wallet_data_keys (wallet_id, enc_key, iv) VALUES (?, ?, ?)
     ON CONFLICT (wallet_id) DO NOTHING`,
    walletId, wrapped.ciphertext, wrapped.iv,
  )
  const final = await dbFirst<{ enc_key: string; iv: string }>(
    db, 'SELECT enc_key, iv FROM wallet_data_keys WHERE wallet_id = ?', walletId,
  )
  if (!final) throw new Error('failed to provision wallet data key')
  return await decryptSecret(kekB64, final.enc_key, final.iv)
}

// guid:roots-walletcrypto-seal
/** Seal a plaintext payload into a stored envelope string. */
export async function sealPayload(dataKeyB64: string, plaintext: string): Promise<string> {
  const { ciphertext, iv } = await encryptSecret(dataKeyB64, plaintext)
  return JSON.stringify({ v: 1, iv, ciphertext })
}

// guid:roots-walletcrypto-open
/** Open a stored payload. Decrypts a v1 envelope; passes through legacy plaintext
 *  (records written before encryption-at-rest have encrypted=0).
 *
 *  The legacy fallthrough applies ONLY to non-envelope content. Once the stored
 *  string parses as a v1 envelope, a decrypt failure (wrong data key after a
 *  botched KEK rotation, corruption) THROWS — silently returning the ciphertext
 *  envelope as if it were the payload would poison record reads and the signed
 *  export bundle (audit F8). */
export async function openPayload(dataKeyB64: string, stored: string): Promise<string> {
  let env: { v?: number; iv?: string; ciphertext?: string } | null = null
  try {
    env = JSON.parse(stored) as { v?: number; iv?: string; ciphertext?: string }
  } catch { /* not JSON — legacy plaintext */ }
  if (env && env.v === 1 && env.iv && env.ciphertext) {
    try {
      return await decryptSecret(dataKeyB64, env.ciphertext, env.iv)
    } catch (e) {
      throw new Error('payload decrypt failed (envelope v1): ' + (e instanceof Error ? e.message : 'unknown'))
    }
  }
  return stored
}

// guid:roots-walletcrypto-decryptRecords
/** Decrypt the `payload` of any encrypted rows in a result set. Returns null if a
 *  row needs decryption but the KEK is unavailable (caller should 503). */
export async function decryptRecords(
  env: { DB: D1Database; ROOTS_KEK?: { get(): Promise<string> } | string },
  walletId: string,
  rows: Record<string, unknown>[],
): Promise<Record<string, unknown>[] | null> {
  if (!rows.some((r) => Number(r.encrypted) === 1)) return rows
  const kek = await resolveKek(env)
  if (!kek) return null
  const dataKey = await getWalletDataKey(env.DB, kek, walletId)
  return await Promise.all(rows.map(async (r) =>
    Number(r.encrypted) === 1 ? { ...r, payload: await openPayload(dataKey, String(r.payload)) } : r,
  ))
}
