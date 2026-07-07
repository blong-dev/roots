/**
 * grants.ts — per-read consent enforcement.
 *
 * A read of (wallet, reader, data_type, purpose) is authorized IFF a live grant
 * covers it. Grants are standing + scoped + revocable; enforcement is per-read;
 * every access is logged. Revocation lands on the next read because activeGrant
 * is evaluated on every request — there is no cached session to grind.
 */
import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst, dbRun } from './db'

export interface Grant {
  id: string
  wallet_id: string
  reader: string
  data_type: string | null
  purpose: string
  granted_at: string
  revoked_at: string | null
  granted_by: string | null
}

// guid:roots-grants-active
/** The live grant covering this exact read, or null. Prefers a type-specific
 *  grant over an all-types (data_type IS NULL) one. Revoked grants never match. */
export async function activeGrant(
  db: D1Database,
  walletId: string,
  reader: string,
  dataType: string,
  purpose: string,
): Promise<Grant | null> {
  return await dbFirst<Grant>(
    db,
    `SELECT * FROM grants
      WHERE wallet_id = ? AND reader = ? AND purpose = ?
        AND (data_type = ? OR data_type IS NULL)
        AND revoked_at IS NULL
      ORDER BY (data_type IS NULL)   -- 0 (specific) sorts before 1 (all-types)
      LIMIT 1`,
    walletId,
    reader,
    purpose,
    dataType,
  )
}

// guid:roots-grants-logAccess
/** Append one access_log row. Denied attempts are logged too, so the owner sees
 *  a consumer probing without a grant — not just successful reads. */
export async function logAccess(
  db: D1Database,
  a: { walletId: string; reader: string; dataType: string | null; purpose: string; outcome: 'allowed' | 'denied' },
): Promise<void> {
  await dbRun(
    db,
    `INSERT INTO access_log (id, wallet_id, reader, data_type, purpose, outcome)
     VALUES (?, ?, ?, ?, ?, ?)`,
    crypto.randomUUID(),
    a.walletId,
    a.reader,
    a.dataType,
    a.purpose,
    a.outcome,
  )
}
