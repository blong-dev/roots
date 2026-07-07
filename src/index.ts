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
import records from './routes/records'
import issuers from './routes/issuers'
import exportRoutes from './routes/export'
import mcp from './routes/mcp'

export interface Bindings {
  DB: D1Database
  ROOTS_KEK?: { get(): Promise<string> } | string // Secrets Store (prod) or plain string (dev): KEK for privkeys + data keys
  ROOTS_OPS_TOKEN?: string // operator bearer — owner break-glass for holder routes
  ROOTS_DELEGATION_ISSUERS?: string // CSV of DIDs allowed to vouch for holders (e.g. did:web:telekora.com)
}

const app = new Hono<{ Bindings: Bindings }>()

app.get('/health', (c) => c.json({ status: 'ok', service: 'roots' }))

// The consent surface: consumer read (grant-gated + logged) + owner grant/audit.
app.route('/w', wallet)
// Writes + credential intake + lifecycle (retract/reinstate/history/verify).
app.route('/w', records)
// The trust registry.
app.route('/issuers', issuers)
// Sovereignty: the holder leaves with a signed bundle of everything.
app.route('/w', exportRoutes)
// Agent surface: JSON-RPC MCP over the same scoped API keys + consent gate.
app.route('/mcp', mcp)

// TODO (roots P1) — remaining lifted surface:
//   app.route('/w', wallets)              // POST /w (create + bind IdP), GET /w/:id/did.json(l)

export default app
