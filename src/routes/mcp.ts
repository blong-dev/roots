/**
 * routes/mcp.ts — the agent surface for roots, mounted at /mcp.
 *
 * JSON-RPC 2.0 over Streamable HTTP (single POST /mcp). Auth is a scoped API key
 * (`Authorization: Bearer tk_…`); each tool is gated by the key's scopes.
 *
 * This is a re-expression on roots' model, NOT a verbatim lift of Telekora's MCP:
 *  - reads go through the SAME per-read consent gate as the HTTP read route
 *    (a live grant for wallet+data_type+purpose, logged to access_log) — an
 *    agent cannot read a wallet it has no grant for.
 *  - there is NO retract tool: retract is a HOLDER action (delegatedHolderAuth),
 *    and an API key is a consumer, not the holder.
 *  - there is NO team/tenant-holdings tool: roots is wallet-scoped, not a tenant
 *    compliance dashboard.
 * Writes reuse records-core, so MCP and HTTP writes cannot diverge.
 */
import { Hono } from 'hono'
import type { Env } from '../auth'
import { resolveApiKey, type ResolvedApiKey } from '../apikeys'
import { verifyExternal, type ExternalInput } from '../credentials/verify-external'
import { activeReadGrant, activeWriteGrant, logAccess } from '../grants'
import { writeSelfRecord, writeCredentialRecord, walletExists } from '../records-core'
import { resolveKek, getWalletDataKey, decryptRecords } from '../wallet-crypto'
import { lookupDataType } from '../data-types'

type Bindings = Env['Bindings']

const PROTOCOL_VERSION = '2025-06-18'
const SERVER_INFO = { name: 'roots-wallet', version: '1.0.0' }

const mcp = new Hono<Env>()

interface Tool {
  name: string
  scope: string
  description: string
  inputSchema: Record<string, unknown>
  run: (env: Bindings, key: ResolvedApiKey, args: Record<string, unknown>) => Promise<unknown>
}

// guid:roots-mcp-inputFrom
function inputFrom(args: Record<string, unknown>): ExternalInput | null {
  if (typeof args.jwt === 'string') return { kind: 'jwt', token: args.jwt.trim() }
  if (args.manual && typeof args.manual === 'object') return { kind: 'manual', meta: args.manual as Record<string, string> }
  if (args.credential && typeof args.credential === 'object') return { kind: 'json', doc: args.credential as Record<string, unknown> }
  if (typeof args.credential === 'string') {
    const s = args.credential.trim()
    if (/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(s)) return { kind: 'jwt', token: s }
    try { return { kind: 'json', doc: JSON.parse(s) } } catch { return null }
  }
  return null
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)

const TOOLS: Tool[] = [
  {
    name: 'verify_credential',
    scope: 'credentials:verify',
    description: 'Verify a credential (W3C Verifiable Credential JSON, Open Badge, or a JWT) and return an honest verification tier (verified / valid-signature / self-reported) with the per-check breakdown. Stores nothing.',
    inputSchema: {
      type: 'object',
      properties: {
        credential: { description: 'The credential as JSON (object or string), or a compact JWT.' },
        jwt: { type: 'string', description: 'Alternatively, a compact JWS credential.' },
      },
    },
    run: async (env, _key, args) => {
      const input = inputFrom(args)
      if (!input) throw new Error('provide `credential` (VC/Open Badge JSON) or `jwt`')
      return await verifyExternal(input, env.DB)
    },
  },
  {
    name: 'read_records',
    scope: 'credentials:read',
    description: "Read a wallet's records of one data_type for a declared purpose. Consent-gated: the wallet owner must have granted this consumer a live grant for (wallet, data_type, purpose). Every read — allowed or denied — is logged to the owner's access log.",
    inputSchema: {
      type: 'object',
      required: ['wallet_id', 'data_type', 'purpose'],
      properties: {
        wallet_id: { type: 'string' },
        data_type: { type: 'string', description: 'e.g. profile.certification, credential' },
        purpose: { type: 'string', description: 'the declared purpose, matched against the grant' },
      },
    },
    run: async (env, key, args) => {
      const walletId = str(args.wallet_id), dataType = str(args.data_type), purpose = str(args.purpose)
      if (!walletId || !dataType || !purpose) throw new Error('wallet_id, data_type and purpose are required — reads are scoped, not blanket')
      const reader = key.tenantId
      const grant = await activeReadGrant(env.DB, walletId, reader, dataType, purpose)
      if (!grant) {
        await logAccess(env.DB, { walletId, reader, dataType, purpose, outcome: 'denied' })
        return { error: 'no live grant for this wallet + data_type + purpose', records: [] }
      }
      const ownFilter = grant.scope === 'own' ? 'AND contributor = ?' : ''
      const stmt = env.DB.prepare(
        `SELECT id, data_type, payload, encrypted, source_type, source_ref, issuer_id, alignment_json, created_at, updated_at
           FROM records WHERE wallet_id = ? AND data_type = ? AND state = 'active' ${ownFilter} ORDER BY created_at DESC`,
      )
      const { results } = await (grant.scope === 'own' ? stmt.bind(walletId, dataType, reader) : stmt.bind(walletId, dataType))
        .all<Record<string, unknown>>()
      const records = await decryptRecords(env, walletId, results)
      if (records === null) return { error: 'record decryption unavailable (ROOTS_KEK not provisioned)', records: [] }
      await logAccess(env.DB, { walletId, reader, dataType, purpose, outcome: 'allowed' })
      return { wallet_id: walletId, data_type: dataType, purpose, records }
    },
  },
  {
    name: 'write_record',
    scope: 'credentials:import',
    description: 'Write a self/tool record into a wallet (typed data, no signature). Returns the new record id.',
    inputSchema: {
      type: 'object',
      required: ['wallet_id', 'data_type', 'payload'],
      properties: {
        wallet_id: { type: 'string' },
        data_type: { type: 'string' },
        payload: { description: 'JSON object or string' },
        source_type: { type: 'string', enum: ['self', 'tool'], description: "defaults to 'self'" },
      },
    },
    run: async (env, key, args) => {
      const walletId = str(args.wallet_id), dataType = str(args.data_type)
      if (!walletId || !dataType) throw new Error('wallet_id and data_type are required')
      const entry = lookupDataType(dataType)
      if (!entry || entry.kind !== 'record') throw new Error(`unknown or non-record data_type '${dataType}' (see the data-types catalog)`)
      if (args.payload === undefined || args.payload === null) throw new Error('payload is required')
      if (!(await walletExists(env.DB, walletId))) throw new Error('wallet not found')
      if (!(await activeWriteGrant(env.DB, walletId, key.tenantId, dataType))) throw new Error('no live write grant for this consumer + wallet + data_type')
      let dataKeyB64: string | undefined
      if (entry.encrypted) {
        const kek = await resolveKek(env)
        if (!kek) throw new Error('record encryption unavailable (ROOTS_KEK not provisioned)')
        dataKeyB64 = await getWalletDataKey(env.DB, kek, walletId)
      }
      const sourceType = args.source_type === 'tool' ? 'tool' : 'self'
      const { id } = await writeSelfRecord(env.DB, { walletId, dataType, payload: args.payload, sourceType, actor: key.tenantId, encrypt: entry.encrypted, dataKeyB64 })
      return { ok: true, id, data_type: dataType, source_type: sourceType, encrypted: entry.encrypted }
    },
  },
  {
    name: 'import_credential',
    scope: 'credentials:import',
    description: 'Verify a credential and store it in a wallet. Returns the record id and the honest tier. The issuer auto-registers as known (which caps the tier at valid-signature until an operator promotes it to trusted).',
    inputSchema: {
      type: 'object',
      required: ['wallet_id'],
      properties: {
        wallet_id: { type: 'string' },
        credential: { description: 'The credential as JSON (object or string).' },
        jwt: { type: 'string', description: 'Alternatively, a compact JWS credential.' },
        manual: { type: 'object', description: 'Alternatively, manual metadata {issuerName, credentialName, issuedAt, expiresAt}.' },
        data_type: { type: 'string', description: "a dt.credential.* / dt.attestation / dt.outcome.* / dt.identity.* key; defaults to 'dt.attestation@1'" },
        source_type: { type: 'string', enum: ['issued', 'imported'], description: "defaults to 'imported'" },
      },
    },
    run: async (env, key, args) => {
      const walletId = str(args.wallet_id)
      if (!walletId) throw new Error('wallet_id is required')
      const dataType = str(args.data_type) ?? 'dt.attestation@1'
      const entry = lookupDataType(dataType)
      if (!entry || entry.kind !== 'credential') throw new Error(`unknown or non-credential data_type '${dataType}' (see the data-types catalog)`)
      if (!(await walletExists(env.DB, walletId))) throw new Error('wallet not found')
      if (!(await activeWriteGrant(env.DB, walletId, key.tenantId, dataType))) throw new Error('no live write grant for this consumer + wallet')
      const input = inputFrom(args)
      if (!input) throw new Error('provide `credential`, `jwt`, or `manual` metadata')
      const kek = await resolveKek(env)
      if (!kek) throw new Error('record encryption unavailable (ROOTS_KEK not provisioned)')
      const dataKeyB64 = await getWalletDataKey(env.DB, kek, walletId)
      const sourceType = args.source_type === 'issued' ? 'issued' : 'imported'
      const { id, report } = await writeCredentialRecord(env.DB, { walletId, dataType, input, sourceType, actor: key.tenantId, dataKeyB64 })
      return { ok: true, id, tier: report.tier, issuer: report.issuer ?? null, alignments: report.alignments ?? [] }
    },
  },
  {
    name: 'list_trusted_issuers',
    scope: 'registry:read',
    description: 'List the trust registry — issuers roots knows, with their status (trusted / known / revoked). A credential can only reach the "verified" tier if its issuer is trusted here.',
    inputSchema: { type: 'object', properties: {} },
    run: async (env) => {
      const { results } = await env.DB.prepare(
        `SELECT did_or_iss, name, method, status FROM issuers ORDER BY status, name`,
      ).all()
      return { issuers: results }
    },
  },
]

// ------------------------------------------------------------- JSON-RPC
function rpcResult(id: unknown, result: unknown) { return { jsonrpc: '2.0', id, result } }
function rpcError(id: unknown, code: number, message: string) { return { jsonrpc: '2.0', id, error: { code, message } } }
function toText(data: unknown, isError = false) {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }], isError }
}

// guid:roots-mcp-route
mcp.post('/', async (c) => {
  const authz = c.req.header('authorization') ?? ''
  const presented = authz.startsWith('Bearer ') ? authz.slice(7).trim() : ''
  const key = presented ? await resolveApiKey(c.env.DB, presented) : null
  if (!key) {
    return c.json({ error: 'unauthorized: supply a valid roots API key as a Bearer token' }, 401, {
      'www-authenticate': 'Bearer realm="roots-mcp"',
    })
  }

  const msg = await c.req.json<{ jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> }>().catch(() => null)
  if (!msg || msg.method === undefined) return c.json(rpcError(null, -32700, 'parse error'), 400)
  const { id, method, params } = msg
  if (id === undefined) return c.body(null, 202) // notification (e.g. notifications/initialized)

  switch (method) {
    case 'initialize':
      return c.json(rpcResult(id, {
        protocolVersion: typeof params?.protocolVersion === 'string' ? params.protocolVersion : PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions: 'roots wallet tools. Verify credentials, read a wallet (consent-gated), and write records/credentials. Every tool is scoped to your API key; reads require a live grant from the wallet owner.',
      }))

    case 'ping':
      return c.json(rpcResult(id, {}))

    case 'tools/list': {
      const visible = TOOLS.filter((t) => key.scopes.has(t.scope)).map((t) => ({
        name: t.name, description: t.description, inputSchema: t.inputSchema,
      }))
      return c.json(rpcResult(id, { tools: visible }))
    }

    case 'tools/call': {
      const name = params?.name as string | undefined
      const args = (params?.arguments as Record<string, unknown>) ?? {}
      const tool = TOOLS.find((t) => t.name === name)
      if (!tool) return c.json(rpcError(id, -32602, `unknown tool: ${name}`))
      if (!key.scopes.has(tool.scope)) {
        return c.json(rpcResult(id, toText({ error: `this API key lacks the required scope: ${tool.scope}` }, true)))
      }
      try {
        const out = await tool.run(c.env, key, args)
        return c.json(rpcResult(id, toText(out)))
      } catch (e) {
        return c.json(rpcResult(id, toText({ error: e instanceof Error ? e.message : 'tool error' }, true)))
      }
    }

    default:
      return c.json(rpcError(id, -32601, `method not found: ${method}`))
  }
})

// A tiny discovery GET so a human hitting /mcp sees what it is.
mcp.get('/', (c) => c.json({
  server: SERVER_INFO, protocol: 'mcp', transport: 'streamable-http',
  auth: 'Bearer <roots API key>', tools: TOOLS.map((t) => ({ name: t.name, scope: t.scope })),
}))

export default mcp
