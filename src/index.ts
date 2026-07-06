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

export interface Bindings {
  DB: D1Database
  ROOTS_KEK?: { get(): Promise<string> } // Secrets Store: KEK for issuer/receiver privkeys + per-wallet data keys
  ROOTS_OPS_TOKEN?: string // operator bearer (lifted pattern) for headless management
}

const app = new Hono<{ Bindings: Bindings }>()

app.get('/health', (c) => c.json({ status: 'ok', service: 'roots' }))

// TODO (roots P1) — mount the lifted surface:
//   app.route('/w', wallets)              // POST /w (create + bind IdP), GET /w/:id/did.json(l)
//   app.route('/w', records)              // typed records: write, consent-gated read, retract/reinstate/history
//   app.route('/credentials', credentials)// POST /w/:id/credentials (issuer write), GET /:id/verify
//   app.route('/issuers', issuers)        // trust registry
//   app.route('/w', exportRoutes)         // GET /w/:id/export (sovereignty)
//   app.route('/mcp', mcp)                // agent surface (lifted)

export default app
