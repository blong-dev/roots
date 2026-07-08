// Anchoring: commit each record's fingerprint to the dreamtree chain.
//
// roots holds the bodies; the chain holds only a commitment (a sha256 over the
// record's immutable stored bytes). We POST that commitment to anchord — the
// HTTP anchor seam co-located with the chain — which signs and broadcasts a
// MsgCommitSeed and returns the assigned seed id. See dreamtree/docs/anchoring.md.
//
// The wallet never holds a chain key; anchord does. This module only makes an
// authenticated HTTP call and records the result back on the row.
import type { D1Database } from '@cloudflare/workers-types'

export interface AnchorEnv {
  ANCHOR_URL?: string // e.g. https://anchor.dreamtree.org
  ANCHOR_TOKEN?: string // Bearer for anchord
}

/** The public DID for a wallet — the anchoring subject. */
export function walletDid(walletId: string): string {
  return `did:web:id.dreamtree.org:w:${walletId}`
}

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * The record commitment: sha256 over a canonical join of the fields that make
 * the stored record what it is. Deterministic and recomputable — anyone with
 * the record bytes can verify the on-chain commitment matches.
 */
export async function recordCommitment(id: string, dataType: string, stored: string): Promise<string> {
  const canonical = `${id}\n${dataType}\n${stored}`
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)))
}

interface AnchorResult {
  id: number
  txhash: string
  height: number
}

/**
 * Anchor a single record by id: read its stored bytes, compute the commitment,
 * POST to anchord, and write the seed id / tx / height back. Idempotent enough
 * for a sweep — a record already 'anchored' is skipped. Failures are recorded
 * as 'failed' (never throws to the caller; meant for ctx.waitUntil).
 */
export async function anchorRecord(env: AnchorEnv, db: D1Database, recordId: string): Promise<void> {
  if (!env.ANCHOR_URL) return // anchoring not configured — leave the row pending

  const row = await db
    .prepare(`SELECT id, wallet_id, data_type, payload, anchor_state FROM records WHERE id = ? AND state = 'active'`)
    .bind(recordId)
    .first<{ id: string; wallet_id: string; data_type: string; payload: string; anchor_state: string }>()
  if (!row || row.anchor_state === 'anchored') return

  try {
    const commitment = await recordCommitment(row.id, row.data_type, row.payload)
    const res = await fetch(`${env.ANCHOR_URL.replace(/\/$/, '')}/anchor`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${env.ANCHOR_TOKEN ?? ''}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        subject: walletDid(row.wallet_id),
        commitment,
        kind: 'record',
        source_ref: `roots:record:${row.id}`,
      }),
    })
    if (!res.ok) throw new Error(`anchord ${res.status}: ${await res.text()}`)
    const out = (await res.json()) as AnchorResult
    await db
      .prepare(`UPDATE records SET seed_id = ?, anchor_tx = ?, anchor_height = ?, anchor_state = 'anchored' WHERE id = ?`)
      .bind(out.id, out.txhash, out.height, row.id)
      .run()
  } catch (e) {
    await db.prepare(`UPDATE records SET anchor_state = 'failed' WHERE id = ?`).bind(row.id).run()
    console.error(`anchor failed for record ${row.id}:`, e instanceof Error ? e.message : e)
  }
}

/**
 * Sweep un-anchored active records (pending or previously failed) and anchor
 * them. Returns how many were attempted. Bounded per call so a sweep can't run
 * away; call repeatedly until it returns 0.
 */
export async function anchorSweep(env: AnchorEnv, db: D1Database, limit = 25): Promise<number> {
  if (!env.ANCHOR_URL) return 0
  const { results } = await db
    .prepare(
      `SELECT id FROM records WHERE state = 'active' AND anchor_state IN ('pending', 'failed') ORDER BY created_at LIMIT ?`,
    )
    .bind(limit)
    .all<{ id: string }>()
  for (const r of results) {
    await anchorRecord(env, db, r.id)
  }
  return results.length
}
