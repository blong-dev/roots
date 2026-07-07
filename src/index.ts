/**
 * roots — the user-owned wallet on the dreamtree protocol.
 *
 * Standalone Cloudflare Workers + a dedicated D1. Telekora is the first consumer:
 * a *client* (silent wallet on signup) and an *issuer* (course completion → a
 * credential written into roots). The chain (dreamtree) is a later serialization
 * roots does not need at v0.
 *
 * Sequencing: dual-run alongside Telekora, then staged extract. See docs/roots.md.
 */
import { Hono } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import wallet from './routes/wallet'
import records, { contributions } from './routes/records'
import issuers from './routes/issuers'
import exportRoutes from './routes/export'
import mcp from './routes/mcp'
import identity from './routes/identity'
import admin from './routes/admin'
import { LANDING_HTML } from './landing'
import { DATA_TYPES } from './data-types'

export interface Bindings {
  DB: D1Database
  ROOTS_KEK?: { get(): Promise<string> } | string // Secrets Store (prod) or plain string (dev): KEK for privkeys + data keys
  ROOTS_KEK_NEXT?: { get(): Promise<string> } | string // the incoming KEK during a rotation (see POST /admin/kek/rotate)
  ROOTS_OPS_TOKEN?: string // operator bearer — owner break-glass for holder routes
  ROOTS_DELEGATION_ISSUERS?: string // CSV of DIDs allowed to vouch for holders (e.g. did:web:telekora.com)
  ROOTS_REQUIRE_MTLS?: string // when set (non-empty), authenticated routes require a valid client cert (Cloudflare API Shield)
  ROOTS_MTLS_FINGERPRINTS?: string // optional CSV of allowed client-cert SHA-256 fingerprints (pin specific consumers)
}

const app = new Hono<{ Bindings: Bindings }>()

app.get('/health', (c) => c.json({ status: 'ok', service: 'roots' }))

// The human face of the DID anchor domain.
app.get('/', (c) => c.html(LANDING_HTML))

// Public network stats — the living proof for the marketing surfaces. Counts
// only; nothing identifying. Edge-cached to keep reads free.
app.get('/stats', async (c) => {
  const row = await c.env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM wallets) AS wallets,
            (SELECT COUNT(*) FROM records WHERE state = 'active') AS records,
            (SELECT COUNT(*) FROM issuers) AS issuers`,
  ).first<{ wallets: number; records: number; issuers: number }>()
  return c.json(
    { wallets: row?.wallets ?? 0, records: row?.records ?? 0, issuers: row?.issuers ?? 0 },
    200,
    { 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*' },
  )
})

// The data_type registry (public catalog): the authoritative set of writable
// types, their PII-derived encryption, and record-vs-credential kind.
app.get('/data-types', (c) => c.json({
  data_types: Object.entries(DATA_TYPES).map(([key, e]) => ({ key, ...e })),
}))

// Identity: wallet creation (silent wallet on signup) + DID doc / history serving.
app.route('/', identity)

// The consent surface: consumer read (grant-gated + logged) + owner grant/audit.
app.route('/w', wallet)
// Writes + credential intake + lifecycle (retract/reinstate/history/verify).
app.route('/w', records)
// The trust registry.
app.route('/issuers', issuers)
// Contributor-addressed access to one's own contributions (Stage-4 lifecycle).
app.route('/contributions', contributions)
// Sovereignty: the holder leaves with a signed bundle of everything.
app.route('/w', exportRoutes)
// Agent surface: JSON-RPC MCP over the same scoped API keys + consent gate.
app.route('/mcp', mcp)
// Operator-only key management (KEK rotation).
app.route('/admin', admin)

export default app
