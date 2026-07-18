/**
 * The holder dashboard PWA (share-and-verify S2, docs/share-and-verify.md §2).
 *
 * One self-contained page served by the worker at /dashboard. Five verbs:
 * view, add, verify, remove, share. Sensitive documents live in the DEVICE
 * VAULT (OPFS, encrypted client-side with a locally held key) — only their
 * sha256 + metadata reach roots (owner ruling 2026-07-18). Auth is the
 * pluggable front door: an operator/delegation token pasted for now, a real
 * holder login when the owner rules on user management.
 */

export const MANIFEST_JSON = JSON.stringify({
  name: 'roots — your dreamtree wallet',
  short_name: 'roots',
  start_url: '/dashboard',
  display: 'standalone',
  background_color: '#0f1512',
  theme_color: '#0f1512',
  description: 'Your documents and credentials: held by you, anchored on dreamtree, shareable without exposure.',
  icons: [{
    src: 'data:image/svg+xml,' + encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="18" fill="#0f1512"/><text x="50" y="66" font-size="52" text-anchor="middle" fill="#7fc8a9" font-family="serif">r</text></svg>'),
    sizes: 'any', type: 'image/svg+xml',
  }],
})

export const SW_JS = `
// roots dashboard service worker: cache the shell so view/verify work offline.
const SHELL = ['/dashboard'];
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open('roots-shell-v1').then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => { e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method === 'GET' && u.pathname === '/dashboard') {
    e.respondWith(fetch(e.request).then((r) => {
      const copy = r.clone(); caches.open('roots-shell-v1').then((c) => c.put(e.request, copy)); return r;
    }).catch(() => caches.match(e.request)));
  }
});
`

export const DASHBOARD_HTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0f1512">
<link rel="manifest" href="/dashboard/manifest.webmanifest">
<title>roots — your wallet</title>
<style>
  :root{--bg:#fbfcfb;--ink:#182028;--mut:#66707a;--line:#dde4e0;--ok:#1d7a55;--bad:#a33}
  @media (prefers-color-scheme:dark){:root{--bg:#0f1512;--ink:#e6ece8;--mut:#8a958f;--line:#26302a;--ok:#7fc8a9;--bad:#e08585}}
  body{font:15px/1.55 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
  main{max-width:760px;margin:0 auto;padding:1.2rem}
  h1{font-size:1.3rem;margin:.4rem 0}
  h2{font-size:1.02rem;margin:1.6rem 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.3rem}
  .mut{color:var(--mut)} .ok{color:var(--ok)} .bad{color:var(--bad)}
  .card{border:1px solid var(--line);border-radius:10px;padding:.7rem .9rem;margin:.5rem 0}
  .row{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;justify-content:space-between}
  button{font:inherit;padding:.35rem .8rem;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--ink);cursor:pointer}
  button.primary{background:var(--ok);border-color:var(--ok);color:#fff}
  input[type=text],input[type=password]{font:inherit;padding:.4rem .6rem;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--ink);min-width:16rem}
  code{font-family:ui-monospace,monospace;font-size:.85em;word-break:break-all}
  .pill{font-size:.75rem;padding:.1rem .55rem;border-radius:99px;border:1px solid var(--line)}
  #toast{position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);padding:.5rem 1rem;border-radius:9px;opacity:0;transition:opacity .3s}
</style></head><body><main>
<p class="mut" style="letter-spacing:.14em;font-size:.75rem">ROOTS · DREAMTREE</p>
<h1>Your wallet</h1>
<p class="mut" id="tagline">Documents and credentials: held by you, anchored on the dreamtree chain, shareable without exposure. Sensitive files never leave this device.</p>

<section id="connect" class="card">
  <h2 style="border:0;margin:.1rem 0">Connect</h2>
  <div class="row" style="justify-content:flex-start">
    <input type="text" id="wallet" placeholder="wallet id (uuid)">
    <input type="password" id="token" placeholder="access token">
    <button class="primary" onclick="connect()">Open wallet</button>
  </div>
  <p class="mut" style="font-size:.8rem">Access uses your delegation or an operator token for now — holder login arrives with the identity release. Hosted custody, honestly: roots can read hosted records during your session; your vault files it can never read.</p>
</section>

<section id="app" style="display:none">
  <h2>Add a document <span class="mut" style="font-weight:normal">— stays on this device</span></h2>
  <div class="card">
    <input type="file" id="file">
    <button class="primary" onclick="addDoc()">Encrypt, vault &amp; anchor</button>
    <p class="mut" style="font-size:.8rem">The file is encrypted here (WebCrypto) into this browser's private storage. Only its fingerprint (sha256) and name are recorded and anchored. Lose the device, lose the file — the record and anchor survive, and re-adding the same file re-verifies. Install this app to protect the vault from browser cleanup.</p>
  </div>
  <h2>Records</h2>
  <div id="list"><p class="mut">…</p></div>
</section>
<div id="toast"></div>

<script>
const $=(s)=>document.querySelector(s);
let W=null,T=null;
const hdr=()=>({'authorization':'Bearer '+T,'content-type':'application/json'});
function toast(m){const t=$('#toast');t.textContent=m;t.style.opacity=1;setTimeout(()=>t.style.opacity=0,2600)}
const hex=(b)=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');

// ---- device vault (OPFS + per-wallet AES-GCM key in localStorage) ----------
async function vaultKey(){
  let k=localStorage.getItem('vault:'+W);
  if(!k){k=hex(crypto.getRandomValues(new Uint8Array(32)));localStorage.setItem('vault:'+W,k)}
  return crypto.subtle.importKey('raw',Uint8Array.from(k.match(/../g).map(h=>parseInt(h,16))),'AES-GCM',false,['encrypt','decrypt']);
}
async function vaultDir(){const r=await navigator.storage.getDirectory();return r.getDirectoryHandle('roots-vault-'+W,{create:true})}
async function vaultPut(id,buf){
  const key=await vaultKey(),iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,buf);
  const f=await (await vaultDir()).getFileHandle(id+'.bin',{create:true});
  const w=await f.createWritable();await w.write(new Blob([iv,new Uint8Array(ct)]));await w.close();
}
async function vaultGet(id){
  try{
    const f=await (await vaultDir()).getFileHandle(id+'.bin');const b=await (await f.getFile()).arrayBuffer();
    const iv=new Uint8Array(b.slice(0,12)),ct=b.slice(12);
    return await crypto.subtle.decrypt({name:'AES-GCM',iv},await vaultKey(),ct);
  }catch(e){return null}
}

// ---- verbs -----------------------------------------------------------------
async function connect(){
  W=$('#wallet').value.trim();T=$('#token').value.trim();
  if(!W||!T)return toast('wallet id and token required');
  const r=await fetch('/w/'+W+'/holder/records',{headers:hdr()});
  if(!r.ok)return toast('access denied ('+r.status+')');
  localStorage.setItem('last-wallet',W);
  $('#connect').style.display='none';$('#app').style.display='block';
  render((await r.json()).records);
}
async function refresh(){const r=await fetch('/w/'+W+'/holder/records',{headers:hdr()});if(r.ok)render((await r.json()).records)}

async function addDoc(){
  const f=$('#file').files[0];if(!f)return toast('choose a file');
  const buf=await f.arrayBuffer();
  const sha=hex(await crypto.subtle.digest('SHA-256',buf));
  const res=await fetch('/w/'+W+'/documents',{method:'POST',headers:hdr(),
    body:JSON.stringify({filename:f.name,size:f.size,mime:f.type,sha256:sha})});
  if(!res.ok)return toast('record failed ('+res.status+')');
  const {id}=await res.json();
  await vaultPut(id,buf);
  toast('vaulted on-device · fingerprint anchoring (~2 min)');
  $('#file').value='';refresh();
}

async function verifyDoc(id,expected){
  let buf=await vaultGet(id);
  if(!buf){
    toast('not in this device\\'s vault — pick the original file to verify');
    const inp=document.createElement('input');inp.type='file';
    inp.onchange=async()=>{const b=await inp.files[0].arrayBuffer();finishVerify(id,expected,b)};
    inp.click();return;
  }
  finishVerify(id,expected,buf);
}
async function finishVerify(id,expected,buf){
  const sha=hex(await crypto.subtle.digest('SHA-256',buf));
  document.getElementById('v-'+id).innerHTML = sha===expected
    ? '<span class="ok">✓ file matches the anchored fingerprint</span>'
    : '<span class="bad">✗ MISMATCH — this is not the anchored file</span>';
}

async function lifecycle(id,action){
  const r=await fetch('/w/'+W+'/records/'+id+'/'+action,{method:'POST',headers:hdr()});
  toast(r.ok?action+'ed':action+' failed');refresh();
}
async function share(id){
  const r=await fetch('/w/'+W+'/shares',{method:'POST',headers:hdr(),
    body:JSON.stringify({record_id:id,mode:'validity'})});
  if(!r.ok)return toast('share failed');
  const s=await r.json();
  await navigator.clipboard.writeText(s.url).catch(()=>{});
  document.getElementById('s-'+id).innerHTML =
    'share link (copied): <a href="'+s.url+'" target="_blank"><code>'+s.url+'</code></a>'+
    ' <button onclick="revoke(\\''+s.token+'\\',\\''+id+'\\')">revoke</button>'+
    '<div class="mut" style="font-size:.78rem">Shows validity only — never the content. Expires '+s.expires_at.slice(0,10)+'; every open is logged to your audit trail.</div>';
}
async function revoke(tok,id){
  await fetch('/w/'+W+'/shares/'+tok,{method:'DELETE',headers:hdr()});
  document.getElementById('s-'+id).innerHTML='<span class="mut">share revoked</span>';
}

function render(records){
  const el=$('#list');
  if(!records.length){el.innerHTML='<p class="mut">No records yet — add a document above.</p>';return}
  el.innerHTML=records.map(r=>{
    let meta=null;try{meta=JSON.parse(r.payload||'null')}catch(e){}
    const isDoc=r.data_type.startsWith('dt.document.');
    const anchor=r.anchor_tx
      ? 'anchored · height '+r.anchor_height+' · seed '+r.seed_id
      : (r.anchor_state||'pending')+' (anchor in ~2 min)';
    const sha=(r.source_ref||'').startsWith('sha256:')?(r.source_ref||'').slice(7):null;
    return '<div class="card">'+
      '<div class="row"><div><strong>'+r.data_type+'</strong> '+
        (r.state==='retracted'?'<span class="pill bad">retracted</span>':'<span class="pill">active</span>')+
        (r.issuer_name?' <span class="mut">· '+r.issuer_name+' ('+r.issuer_trust+')</span>':'')+
      '</div><div class="mut" style="font-size:.8rem">'+r.created_at.slice(0,10)+'</div></div>'+
      '<div class="mut" style="font-size:.82rem">'+anchor+'</div>'+
      '<div class="row" style="justify-content:flex-start;margin-top:.45rem">'+
        (isDoc&&sha?'<button onclick="verifyDoc(\\''+r.id+'\\',\\''+sha+'\\')">verify file</button>':'')+
        '<button onclick="share(\\''+r.id+'\\')">share validity</button>'+
        (r.state==='active'
          ?'<button onclick="lifecycle(\\''+r.id+'\\',\\'retract\\')">retract</button>'
          :'<button onclick="lifecycle(\\''+r.id+'\\',\\'reinstate\\')">reinstate</button>')+
      '</div>'+
      '<div id="v-'+r.id+'" style="font-size:.85rem"></div><div id="s-'+r.id+'" style="font-size:.85rem"></div>'+
    '</div>';
  }).join('');
}

if('serviceWorker' in navigator)navigator.serviceWorker.register('/dashboard/sw.js');
const lw=localStorage.getItem('last-wallet');if(lw)$('#wallet').value=lw;
</script></main></body></html>`
