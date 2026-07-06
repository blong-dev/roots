/**
 * apikeys.ts — scoped per-tenant API keys (GNS-845).
 *
 * A key is `tk_<base64url(32 random bytes)>`. Only its SHA-256 hash is stored;
 * the plaintext is shown once at creation. Auth hashes the presented key and
 * looks it up. Scopes are least-privilege and checked per operation.
 *
 * This is the handable credential the ops god-token can't be — every key names
 * exactly one tenant and carries only the scopes it was granted.
 */
import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst } from './db'

export type Scope =
  | 'credentials:verify'
  | 'credentials:read'
  | 'credentials:import'
  | 'credentials:retract'
  | 'registry:read'

export const ALL_SCOPES: Scope[] = [
  'credentials:verify',
  'credentials:read',
  'credentials:import',
  'credentials:retract',
  'registry:read',
]

export interface ApiKeyRow {
  id: string
  tenant_id: string
  name: string | null
  key_prefix: string
  scopes: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}

export interface ResolvedApiKey {
  id: string
  tenantId: string
  scopes: Set<string>
}

// guid:apikeys-sha256hex
// guid:fdb70a06-585f-42eb-ae77-14dfa5875a05
function bytesToHex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

// guid:apikeys-hash
// guid:9b079ee8-e14c-4c19-9d26-3d27539d45b7
export async function hashKey(key: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key))
  return bytesToHex(new Uint8Array(digest))
}

/** Mint a new key. Returns the plaintext (shown once) + the storable row bits. */
// guid:apikeys-generate
// guid:6b207133-5e97-413b-8051-32d9b62a85f4
export async function generateApiKey(): Promise<{ plaintext: string; prefix: string; hash: string }> {
  const raw = crypto.getRandomValues(new Uint8Array(32))
  let b64 = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const plaintext = `tk_${b64}`
  const prefix = plaintext.slice(0, 11) // tk_ + 8 chars — enough to identify, not to use
  return { plaintext, prefix, hash: await hashKey(plaintext) }
}

/** Resolve a presented key to its tenant + scopes, or null. Updates last_used. */
// guid:apikeys-resolve
// guid:21d49e4a-1636-40b9-9c02-186af276b01a
export async function resolveApiKey(db: D1Database, presented: string): Promise<ResolvedApiKey | null> {
  if (!presented.startsWith('tk_')) return null
  const hash = await hashKey(presented)
  const row = await dbFirst<{ id: string; tenant_id: string; scopes: string; revoked_at: string | null }>(
    db,
    'SELECT id, tenant_id, scopes, revoked_at FROM api_keys WHERE key_hash = ?',
    hash,
  )
  if (!row || row.revoked_at) return null
  // Best-effort last-used stamp (don't block the request on it).
  try { await db.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").bind(row.id).run() } catch { /* */ }
  return {
    id: row.id,
    tenantId: row.tenant_id,
    scopes: new Set(row.scopes.split(',').map((s) => s.trim()).filter(Boolean)),
  }
}

// guid:apikeys-normalizeScopes
// guid:5468f965-37d0-4038-9603-3400bed60599
export function normalizeScopes(input: unknown): Scope[] {
  const arr = Array.isArray(input) ? input : typeof input === 'string' ? input.split(',') : []
  return arr.map((s) => String(s).trim()).filter((s): s is Scope => (ALL_SCOPES as string[]).includes(s))
}
