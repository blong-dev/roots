/**
 * routes/status.ts — the public BitstringStatusList surface, mounted at /status.
 *
 *   GET /status/:tenantId/:purpose   the signed BitstringStatusListCredential for
 *                                    one issuer scope × purpose (revocation |
 *                                    suspension). Public: a status list is meant
 *                                    to be fetched by any verifier (see
 *                                    verify-external.ts statusFlagged).
 *
 * The list is generated on demand from credential_status rows and signed with the
 * SAME eddsa-jcs-2022 path the rest of roots uses (getOrCreateIssuerKey +
 * createDataIntegrityProof, via buildStatusListCredential). Operator-gated
 * revoke/suspend/reinstate live under /admin (routes/admin.ts).
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { resolveKek } from '../wallet-crypto'
import { buildStatusListCredential, type StatusPurpose } from '../credentials/status'
import { DID_WEB_DOMAIN } from '../credentials/keys'

const status = new Hono<Env>()

// guid:roots-status-serve
status.get('/:tenantId/:purpose', async (c) => {
  const tenantId = c.req.param('tenantId')!
  const purpose = c.req.param('purpose')!
  if (purpose !== 'revocation' && purpose !== 'suspension') {
    return c.json({ error: 'purpose must be revocation | suspension' }, 400)
  }
  const kek = await resolveKek(c.env)
  if (!kek) return c.json({ error: 'status signing unavailable (ROOTS_KEK not provisioned)' }, 503)
  // Canonical public origin — the URL embedded in every issued credentialStatus.
  const vc = await buildStatusListCredential(c.env.DB, kek, `https://${DID_WEB_DOMAIN}`, tenantId, purpose as StatusPurpose)
  return c.json(vc, 200, {
    'content-type': 'application/vc+ld+json',
    'cache-control': 'public, max-age=60',
    'access-control-allow-origin': '*',
  })
})

export default status
