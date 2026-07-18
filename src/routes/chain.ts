/**
 * The public chain pulse (share-and-verify §3): stats PUSHED outbound from m3
 * on a timer land here; /chain renders them. No inbound path to m3, no chain
 * RPC exposure — the page can only ever be as fresh as the last push, and
 * says so.
 */
import { Hono } from 'hono'
import type { Bindings } from '../index'

type Env = { Bindings: Bindings }

export const chain = new Hono<Env>()

function pushAuthed(auth: string | undefined, expected?: string): boolean {
  const t = (auth || '').replace(/^Bearer\s+/i, '')
  if (!expected || t.length !== expected.length) return false
  let diff = 0
  for (let i = 0; i < t.length; i++) diff |= t.charCodeAt(i) ^ expected.charCodeAt(i)
  return diff === 0
}

chain.post('/push', async (c) => {
  if (!pushAuthed(c.req.header('authorization'), c.env.CHAIN_STATS_TOKEN))
    return c.json({ error: 'unauthorized' }, 401)
  const body = await c.req.text()
  if (body.length > 32_768) return c.json({ error: 'too large' }, 413)
  try { JSON.parse(body) } catch { return c.json({ error: 'not json' }, 400) }
  await c.env.DB.prepare(
    `INSERT INTO chain_stats (id, stats, updated_at) VALUES (1, ?, datetime('now'))
     ON CONFLICT(id) DO UPDATE SET stats = excluded.stats, updated_at = excluded.updated_at`,
  ).bind(body).run()
  return c.json({ ok: true })
})

async function load(c: { env: Bindings }): Promise<{ stats: Record<string, unknown> | null; updated_at: string | null }> {
  const row = await c.env.DB.prepare('SELECT stats, updated_at FROM chain_stats WHERE id = 1')
    .first<{ stats: string; updated_at: string }>()
  if (!row) return { stats: null, updated_at: null }
  try { return { stats: JSON.parse(row.stats), updated_at: row.updated_at } } catch { return { stats: null, updated_at: row.updated_at } }
}

chain.get('/json', async (c) => {
  const d = await load(c)
  return c.json(d, 200, { 'cache-control': 'public, max-age=60', 'access-control-allow-origin': '*' })
})

chain.get('/', async (c) => {
  const { stats, updated_at } = await load(c)
  const esc = (x: unknown) => String(x ?? '—').replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`)
  const s = (stats ?? {}) as Record<string, unknown>
  const props = Array.isArray(s.proposals) ? s.proposals as { id: string; status: string }[] : []
  const stale = updated_at ? (Date.now() - Date.parse(updated_at + 'Z')) / 60000 : null
  const cell = (k: string, v: string, sub = '') =>
    `<div style="border:1px solid var(--line);border-radius:10px;padding: .8rem 1rem;min-width:10rem">
       <div style="color:var(--mut);font-size:.78rem">${k}</div>
       <div style="font-size:1.35rem;font-family:ui-monospace,monospace">${v}</div>
       ${sub ? `<div style="color:var(--mut);font-size:.75rem">${sub}</div>` : ''}</div>`
  return c.html(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dreamtree — chain pulse</title>
<style>:root{--bg:#fbfcfb;--ink:#182028;--mut:#66707a;--line:#dde4e0}
@media (prefers-color-scheme:dark){:root{--bg:#0f1512;--ink:#e6ece8;--mut:#8a958f;--line:#26302a}}
body{font:15px/1.55 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
main{max-width:760px;margin:0 auto;padding:1.4rem}</style></head><body><main>
<p style="letter-spacing:.14em;color:var(--mut);font-size:.75rem">DREAMTREE · CHAIN PULSE</p>
<h1 style="font-size:1.35rem">What the chain is doing</h1>
<p style="color:var(--mut)">chain-id <code>dreamtree</code> · photons are pegged 1:1 to distinct observations — supply IS the corpus. Updated ${stale == null ? 'never (awaiting first push)' : esc(Math.round(stale)) + ' min ago'}, pushed outbound from the node (the chain has no public door).</p>
<div style="display:flex;gap: .7rem;flex-wrap:wrap;margin:1rem 0">
${cell('block height', esc(s.height))}
${cell('photons minted', esc(typeof s.photons_minted === 'number' ? Number(s.photons_minted).toLocaleString('en-US') : s.photons_minted), '= distinct observations')}
${cell('block time', esc(String(s.block_time ?? '').slice(0, 19)).replace('T', ' '))}
</div>
<h2 style="font-size:1rem;border-bottom:1px solid var(--line);padding-bottom:.3rem">Governance</h2>
${props.length ? '<ul>' + props.map((p) => `<li>proposal ${esc(p.id)} — ${esc(p.status).replace('PROPOSAL_STATUS_', '').toLowerCase()}</li>`).join('') + '</ul>' : '<p style="color:var(--mut)">no proposals in view</p>'}
<h2 style="font-size:1rem;border-bottom:1px solid var(--line);padding-bottom:.3rem">Wallet network</h2>
<div id="roots" style="color:var(--mut)">loading…</div>
<p style="color:var(--mut);font-size:.8rem;margin-top:1.6rem">machine-readable: <a href="/chain/json">/chain/json</a> · verify anything: <a href="https://verify.dreamtree.org">verify.dreamtree.org</a> · <a href="https://dreamtree.org">dreamtree.org</a></p>
<script>fetch('/stats').then(r=>r.json()).then(s=>{document.getElementById('roots').textContent =
  s.wallets+' wallets · '+s.records+' records ('+s.anchored+' anchored) · '+s.issuers+' issuers'})</script>
</main></body></html>`)
})
