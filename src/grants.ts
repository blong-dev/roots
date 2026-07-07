/**
 * grants.ts — per-action consent enforcement (reads AND writes).
 *
 * One primitive, two capabilities. A read needs a live read-grant; a write needs
 * a live write-grant. Grants are standing, scoped, and revocable; enforcement is
 * per-request (revocation lands on the next request — no cached session). Reads
 * are logged to access_log; the record audit chain (record_events.actor) logs
 * writes. The wallet holder controls who reads AND who contributes.
 */
import type { D1Database } from '@cloudflare/workers-types'
import { dbFirst, dbRun } from './db'

export interface Grant {
  id: string
  wallet_id: string
  grantee: string
  capability: 'read' | 'write'
  scope: 'own' | 'all'
  data_type: string | null
  purpose: string | null
  granted_at: string
  revoked_at: string | null
  granted_by: string | null
}

// guid:roots-grants-activeRead
/** The live READ grant covering this read, or null. A NULL-purpose grant is
 *  purpose-agnostic (used by 'own' grants — reading your own contributions isn't
 *  purpose-gated); an 'all' grant carries a specific purpose. Prefers a
 *  type-specific + purpose-specific grant. Revoked grants never match. */
export async function activeReadGrant(
  db: D1Database, walletId: string, grantee: string, dataType: string, purpose: string,
): Promise<Grant | null> {
  return await dbFirst<Grant>(
    db,
    `SELECT * FROM grants
      WHERE wallet_id = ? AND grantee = ? AND capability = 'read'
        AND (purpose = ? OR purpose IS NULL)
        AND (data_type = ? OR data_type IS NULL)
        AND revoked_at IS NULL
      ORDER BY (purpose IS NULL), (data_type IS NULL)   -- most specific first
      LIMIT 1`,
    walletId, grantee, purpose, dataType,
  )
}

// guid:roots-grants-activeWrite
/** The live WRITE grant letting this party contribute a record of this data_type
 *  to this wallet, or null. Writes have no purpose. All-types (NULL) covers any. */
export async function activeWriteGrant(
  db: D1Database, walletId: string, grantee: string, dataType: string,
): Promise<Grant | null> {
  return await dbFirst<Grant>(
    db,
    `SELECT * FROM grants
      WHERE wallet_id = ? AND grantee = ? AND capability = 'write'
        AND (data_type = ? OR data_type IS NULL)
        AND revoked_at IS NULL
      ORDER BY (data_type IS NULL)
      LIMIT 1`,
    walletId, grantee, dataType,
  )
}

// guid:roots-grants-logAccess
/** Append one access_log row. Denied reads are logged too, so the owner sees a
 *  consumer probing without a grant — not just successful reads. */
export async function logAccess(
  db: D1Database,
  a: { walletId: string; reader: string; dataType: string | null; purpose: string; outcome: 'allowed' | 'denied' },
): Promise<void> {
  await dbRun(
    db,
    `INSERT INTO access_log (id, wallet_id, reader, data_type, purpose, outcome)
     VALUES (?, ?, ?, ?, ?, ?)`,
    crypto.randomUUID(), a.walletId, a.reader, a.dataType, a.purpose, a.outcome,
  )
}
