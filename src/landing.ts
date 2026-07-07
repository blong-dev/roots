/**
 * landing.ts — the human-facing page at GET /.
 *
 * Most traffic here is machines resolving DIDs. But people follow DID URLs too,
 * and the domain that anchors identities should say plainly what it is.
 * Self-contained HTML, no external requests.
 */
export const LANDING_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>roots · the wallet on the dreamtree network</title>
<meta name="description" content="roots is a credential wallet service. Every wallet here has a public identity anyone can verify.">
<style>
  :root { --bg:#101410; --ink:#e8e6dd; --dim:#9aa294; --moss:#7fb069; --line:#2a322a; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--ink); font:17px/1.65 Georgia, 'Times New Roman', serif;
         min-height:100vh; display:flex; flex-direction:column; align-items:center; padding:9vh 24px 6vh; }
  main { max-width:34rem; width:100%; }
  h1 { font-size:2.6rem; font-weight:normal; letter-spacing:.02em; color:var(--moss); }
  .tag { color:var(--dim); margin:.35rem 0 2.8rem; font-style:italic; }
  p { margin:0 0 1.15rem; }
  .did { font:13px/1.6 ui-monospace, 'Cascadia Code', Menlo, monospace; color:var(--moss);
         background:#161c16; border:1px solid var(--line); border-radius:6px;
         padding:.7rem .9rem; margin:1.4rem 0 2rem; overflow-x:auto; white-space:nowrap; }
  ul { list-style:none; margin:0 0 2rem; }
  li { padding:.55rem 0 .55rem 1.4rem; position:relative; border-top:1px solid var(--line); }
  li:last-child { border-bottom:1px solid var(--line); }
  li::before { content:'·'; position:absolute; left:.3rem; color:var(--moss); }
  .custody { color:var(--dim); font-size:.92rem; }
  nav { margin-top:2.6rem; display:flex; gap:1.6rem; flex-wrap:wrap; }
  a { color:var(--moss); text-decoration:none; border-bottom:1px solid var(--line); padding-bottom:1px; }
  a:hover { border-bottom-color:var(--moss); }
  footer { margin-top:auto; padding-top:4rem; color:var(--dim); font-size:.85rem; }
</style>
</head>
<body>
<main>
  <h1>roots</h1>
  <p class="tag">the wallet on the dreamtree network</p>

  <p>This is a wallet service. It holds credentials and records that belong to the people
  who earned them. Every wallet here is anchored to a public identity that anyone can
  check, without asking us:</p>

  <div class="did">did:web:id.dreamtree.org:w:&lt;wallet&gt; &nbsp;→&nbsp; /w/&lt;wallet&gt;/did.json</div>

  <ul>
    <li>Reading a wallet takes the owner's permission, checked on every single read and
        written to a log the owner can see.</li>
    <li>A service that writes into a wallet can read back what it wrote. Reading anything
        more takes an explicit grant from the owner.</li>
    <li>Verification happens live. When a credential is shown as verified, that means the
        cryptography was checked at that moment, not copied from a stored label.</li>
    <li>Nothing is deleted. Corrections are recorded as retractions, with the reason kept
        in the record's history.</li>
    <li>Owners can export their entire wallet as a signed bundle that verifies offline.</li>
  </ul>

  <p class="custody">Wallets are hosted, and sensitive contents are encrypted at rest.
  We can say that honestly because the export path means you are never stuck here.</p>

  <nav>
    <a href="https://github.com/blong-dev/roots">source</a>
    <a href="https://github.com/blong-dev/dreamtree">design &amp; protocol</a>
    <a href="https://telekora.com">telekora, the first issuer</a>
  </nav>
</main>
<footer>roots · AGPL-3.0 · lowercase, always</footer>
</body>
</html>`
