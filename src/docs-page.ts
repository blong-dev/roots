/**
 * /docs — how to use all of this (share-and-verify §4). Two audiences on one
 * page: humans (what a wallet is, what sharing does) and developers/agents
 * (the API surfaces). Honesty framings are copy requirements: hosted custody
 * stated, share-mode disclosures stated, device-vault trade stated.
 */
export const DOCS_HTML = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>roots — how it works</title>
<style>:root{--bg:#fbfcfb;--ink:#182028;--mut:#66707a;--line:#dde4e0;--ok:#1d7a55}
@media (prefers-color-scheme:dark){:root{--bg:#0f1512;--ink:#e6ece8;--mut:#8a958f;--line:#26302a;--ok:#7fc8a9}}
body{font:16px/1.6 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
main{max-width:720px;margin:0 auto;padding:1.4rem}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
h3{font-size:.95rem;margin:1.2rem 0 .3rem}
code,pre{font-family:ui-monospace,monospace;font-size:.85em}
pre{background:rgba(127,127,127,.08);border:1px solid var(--line);border-radius:8px;padding:.7rem .9rem;overflow-x:auto}
.mut{color:var(--mut)} a{color:var(--ok)}</style></head><body><main>
<p class="mut" style="letter-spacing:.14em;font-size:.75rem">ROOTS · DREAMTREE · DOCS</p>
<h1>How this works</h1>

<h2>For people</h2>
<h3>What a wallet is</h3>
<p>Your wallet holds your records and credentials — course completions, work
documents, attestations. Each one is fingerprinted (a cryptographic hash) and
that fingerprint is <strong>anchored on the dreamtree chain</strong>: a public,
append-only ledger that holds <em>hashes, never content</em>. Anchoring means
anyone you choose can later confirm a record existed, unaltered, at a point in
time — without seeing what's inside it.</p>
<h3>Sharing without exposing</h3>
<p>From <a href="/dashboard">your dashboard</a> you can mint a share link for
any record, in one of two modes — and the link's page always says plainly
which one it is:</p>
<p><strong>Validity</strong> — the viewer learns the record exists, its type,
who issued it, when, whether it's been retracted, and its on-chain anchor.
<em>Never the content.</em> This is how an employer checks a credential is
real without you handing anything over.</p>
<p><strong>Read</strong> — the viewer also sees the content. You chose to show
it; you can revoke the link at any time, and revocation takes effect on the
next open.</p>
<p>Every open of any share is written to your wallet's audit trail.</p>
<h3>Documents stay on your device</h3>
<p>Files you add in the dashboard are encrypted <em>on your device</em> and
stay there — only the fingerprint and the name reach us. The honest trade:
lose the device, lose the file. The record and its anchor survive, so
re-adding the original file verifies it again instantly. Install the app
(Add to Home Screen) so your browser doesn't clean the vault away.</p>
<h3>The honest part</h3>
<p>Hosted records (credentials issued to you by tools) are held by roots with
encryption at rest; roots can read them during an authorized session. That is
hosted custody, not zero-knowledge — we say so because it's true. Your
device-vault files, roots can never read.</p>

<h2>For developers &amp; agents</h2>
<h3>Verify anything (zero-auth)</h3>
<pre>GET https://verify.dreamtree.org/verify/{sha256}
→ { status: observed | converged | not_found, proof, anchor, standing, … }

POST https://verify.dreamtree.org/verify/url   {"url": "…"}
→ C2PA Content Credentials verdict: trusted | valid_untrusted | invalid |
  no_credentials | fetch_failed (+ the observation verdict if the bytes are known)</pre>
<p>MCP server (agents): <code>POST https://verify.dreamtree.org/mcp</code> —
tools <code>verify_observation</code> and <code>verify_c2pa_url</code>,
structured verdicts, no auth for reads. First calls may return
<code>pending</code> — retry in a few seconds; results are then cached.</p>
<h3>Shares</h3>
<pre>POST   /w/{wallet}/shares            {record_id, mode: validity|read,
                                       expires_in_s?, max_uses?}   (holder auth)
GET    /s/{token}                     verdict page (?format=json)
GET    /s/{token}/badge.svg           live status badge (embed anywhere)
DELETE /w/{wallet}/shares/{token}     revoke (lands on next open)</pre>
<h3>Wallets &amp; records</h3>
<pre>GET  /w/{wallet}/holder/records       your records (metadata)   (holder auth)
POST /w/{wallet}/documents            register a device-vault file by sha256
GET  /w/{id}/did.json                 the wallet's DID document (public)
GET  /stats · /chain · /chain/json    network + chain pulse (public)</pre>
<p class="mut">Issuer &amp; consumer APIs (writing credentials, grant-gated
reads): see the <a href="https://github.com/blong-dev/roots">repository</a>.
Chain protocol &amp; specs: <a href="https://github.com/blong-dev/dreamtree">blong-dev/dreamtree</a>.</p>
<p class="mut" style="margin-top:2rem"><a href="/">id.dreamtree.org</a> ·
<a href="/dashboard">dashboard</a> · <a href="/chain">chain pulse</a> ·
<a href="https://dreamtree.org">dreamtree.org</a></p>
</main></body></html>`
