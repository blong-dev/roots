/**
 * db.ts — D1 query helpers.
 *
 * Thin wrappers around D1Database for the four common patterns:
 *   dbFirst  — return first row or null
 *   dbAll    — return all rows
 *   dbRun    — execute a mutation, return D1Result
 *   dbBatch  — batch multiple prepared statements in one round-trip
 */

export async function dbFirst<T = Record<string, unknown>>(
  db: D1Database,
  sql: string,
  ...params: unknown[]
): Promise<T | null> {
  const stmt = db.prepare(sql)
  const bound = params.length ? stmt.bind(...params) : stmt
  return bound.first<T>() as Promise<T | null>
}

export async function dbAll<T = Record<string, unknown>>(
  db: D1Database,
  sql: string,
  ...params: unknown[]
): Promise<T[]> {
  const stmt = db.prepare(sql)
  const bound = params.length ? stmt.bind(...params) : stmt
  const { results } = await bound.all<T>()
  return results
}

export async function dbRun(
  db: D1Database,
  sql: string,
  ...params: unknown[]
): Promise<D1Result> {
  const stmt = db.prepare(sql)
  const bound = params.length ? stmt.bind(...params) : stmt
  return bound.run()
}

export async function dbBatch(
  db: D1Database,
  statements: D1PreparedStatement[],
): Promise<D1Result[]> {
  return db.batch(statements)
}
