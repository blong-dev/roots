/**
 * d1-shim.ts — a real (in-memory SQLite) D1Database stand-in for headless tests.
 *
 * Backed by node:sqlite so the tests exercise the ACTUAL SQL the routes run
 * (RETURNING, ON CONFLICT, datetime('now'), the status counters, the audit chain)
 * — not a hand-rolled mock that can drift from D1's behaviour. Implements only the
 * slice of the D1 surface roots uses: prepare().bind().first()/all()/run() and
 * batch().
 */
import { DatabaseSync } from 'node:sqlite'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

type Row = Record<string, unknown>

function normalizeRow(r: Row | undefined): Row | null {
  if (r === undefined || r === null) return null
  const o: Row = {}
  for (const k of Object.keys(r)) {
    const v = r[k]
    o[k] = typeof v === 'bigint' ? Number(v) : v
  }
  return o
}

function clean(params: unknown[]): unknown[] {
  return params.map((x) => (x === undefined ? null : x))
}

export interface ShimStatement {
  bind: (...p: unknown[]) => ShimStatement
  first: <T = Row>() => Promise<T | null>
  all: <T = Row>() => Promise<{ results: T[]; success: boolean; meta: Record<string, unknown> }>
  run: () => Promise<{ success: boolean; meta: { changes: number; last_row_id: number } }>
}

export interface ShimD1 {
  prepare: (sql: string) => ShimStatement
  batch: (stmts: ShimStatement[]) => Promise<unknown[]>
  exec: (sql: string) => Promise<{ count: number; duration: number }>
}

function makeStatement(sqlite: DatabaseSync, sql: string, params: unknown[]): ShimStatement {
  const p = clean(params)
  return {
    bind: (...np: unknown[]) => makeStatement(sqlite, sql, np),
    first: async <T = Row>() => {
      const stmt = sqlite.prepare(sql)
      const r = stmt.get(...(p as never[])) as Row | undefined
      return normalizeRow(r) as T | null
    },
    all: async <T = Row>() => {
      const stmt = sqlite.prepare(sql)
      const rows = stmt.all(...(p as never[])) as Row[]
      return { results: rows.map((r) => normalizeRow(r)) as T[], success: true, meta: {} }
    },
    run: async () => {
      const stmt = sqlite.prepare(sql)
      const info = stmt.run(...(p as never[]))
      return { success: true, meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) } }
    },
  }
}

/** A fresh in-memory D1 with all roots migrations applied. */
export function freshDb(migrationsDir: string): ShimD1 {
  const sqlite = new DatabaseSync(':memory:')
  const files = readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()
  for (const f of files) sqlite.exec(readFileSync(join(migrationsDir, f), 'utf8'))
  return {
    prepare: (sql: string) => makeStatement(sqlite, sql, []),
    batch: async (stmts: ShimStatement[]) => {
      const out: unknown[] = []
      for (const st of stmts) out.push(await st.run())
      return out
    },
    exec: async (sql: string) => {
      sqlite.exec(sql)
      return { count: 0, duration: 0 }
    },
  }
}
