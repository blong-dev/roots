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

export interface Bindings {
  DB: D1Database
  ROOTS_KEK?: { get(): Promise<string> } // Secrets Store: KEK for issuer/receiver privkeys + per-wallet data keys
  ROOTS_OPS_TOKEN?: string // operator bearer (lifted pattern) for headless management
}

const app = new Hono<{ Bindings: Bindings }>()

app.get('/health', (c) => c.json({ status: 'ok', service: 'roots' }))

// The consent surface: consumer read (grant-gated + logged) + owner grant/audit.
app.route('/w', wallet)
// Writes + credential intake + lifecycle (retract/reinstate/history/verify).
app.route('/w', records)
// The trust registry.
app.route('/issuers', issuers)

// TODO (roots P1) — remaining lifted surface:
//   app.route('/w', wallets)              // POST /w (create + bind IdP), GET /w/:id/did.json(l)
//   app.route('/w', exportRoutes)         // GET /w/:id/export (sovereignty)
//   app.route('/mcp', mcp)                // agent surface (lifted)

export default app
