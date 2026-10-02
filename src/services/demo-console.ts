import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { ENTITY, WALLET_UI_URL } from '../config.js'
import { esc } from '../common/html.js'
import { type DemoEvent, clearEvents, emit, eventsAfter } from '../common/events.js'

type Box = {
  key: string
  label: string
  sub?: string
  url?: string
  x: number
  y: number
  w?: number
  h?: number
  disabled?: boolean
  doc?: string
}

const W = 240
const H = 86

/** Entities laid out like the IHV diagram. */
const boxes = (): Box[] => [
  { key: 'nii', label: 'Intermediate', sub: 'Authority (NII)', url: ENTITY.nii, x: 370, y: 28 },
  { key: 'trustAnchor', label: 'Trust Anchor', sub: '(eduGAIN)', url: ENTITY.trustAnchor, x: 715, y: 28 },
  { key: 'i2', label: 'Intermediate', sub: 'Authority (I2)', url: ENTITY.i2, x: 1060, y: 28 },
  { key: 'idp', label: '機関IdP', url: ENTITY.idp, x: 130, y: 178, doc: 'metadata' },
  { key: 'attributeProvider', label: '属性Provider', url: ENTITY.attributeProvider, x: 130, y: 322, doc: 'metadata' },
  { key: 'normalSp', label: '通常のSP', sub: '(未実装)', x: 610, y: 178, disabled: true },
  { key: 'issuer', label: '学認Issuer', url: ENTITY.issuer, x: 610, y: 322, doc: 'metadata' },
  { key: 'walletProvider', label: 'Wallet Provider', url: ENTITY.walletProvider, x: 610, y: 478, doc: 'metadata' },
  { key: 'trustList', label: 'Trust List', sub: 'ETSI TS 119 602', url: ENTITY.trustList, x: 610, y: 622, doc: 'metadata' },
  { key: 'statusList', label: 'Status List', sub: 'Token Status List', url: ENTITY.statusList, x: 610, y: 766, doc: 'metadata' },
  { key: 'wallet', label: 'Wallet Instance', sub: 'Web Wallet', url: WALLET_UI_URL, x: 965, y: 478, doc: 'Attestation' },
  { key: 'verifier', label: 'Verifiers', url: ENTITY.verifier, x: 965, y: 622 },
  { key: 'incommonSp', label: 'InCommon SP', sub: 'Trust Chain Explorer', url: ENTITY.incommonSp, x: 1060, y: 178, doc: 'metadata' },
]

const healthUrl = (key: string, url: string) => (key === 'wallet' ? `${url}/api/summary` : `${url}/`)

const diagramSvg = () => {
  const b = Object.fromEntries(boxes().map((x) => [x.key, x]))
  const cx = (k: string) => b[k].x + W / 2
  const line = (x1: number, y1: number, x2: number, y2: number, red = false) =>
    `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="${red ? 'reg' : 'tc'}" marker-end="url(#${red ? 'ar' : 'ab'})"/>`
  const nb = { x: cx('nii'), y: b.nii.y + H }
  const lines = [
    line(b.nii.x + W, 71, b.trustAnchor.x - 4, 71),
    line(b.i2.x, 71, b.trustAnchor.x + W + 4, 71),
    line(cx('idp'), b.idp.y, nb.x - 6, nb.y + 4),
    line(b.attributeProvider.x + W, b.attributeProvider.y + H / 2, nb.x - 4, nb.y + 4),
    line(cx('normalSp'), b.normalSp.y, nb.x + 6, nb.y + 4),
    line(b.issuer.x, b.issuer.y + H / 2, nb.x, nb.y + 4),
    line(b.walletProvider.x, b.walletProvider.y + H / 2, nb.x - 2, nb.y + 4),
    line(b.trustList.x, b.trustList.y + H / 2, nb.x - 2, nb.y + 4),
    line(b.statusList.x, b.statusList.y + H / 2, nb.x - 2, nb.y + 4),
    line(cx('incommonSp'), b.incommonSp.y, cx('i2'), b.i2.y + H + 4),
    line(b.wallet.x, b.wallet.y + H / 2, b.walletProvider.x + W + 4, b.walletProvider.y + H / 2, true),
    line(b.verifier.x, b.verifier.y + H / 2, b.trustList.x + W + 4, b.trustList.y + H / 2, true),
  ].join('')
  const groups = [
    { x: 75, y: 158, w: 350, h: 296, label: '学認IdPとして構成' },
    { x: 555, y: 158, w: 350, h: 300, label: '学認SPとして構成' },
    { x: 555, y: 464, w: 350, h: 410, label: 'OpenID Federation で Trust Chain確認' },
  ]
    .map(
      (g) =>
        `<rect x="${g.x}" y="${g.y}" width="${g.w}" height="${g.h}" class="grp"/><text x="${g.x + 6}" y="${g.y - 6}" class="gl">${g.label}</text>`
    )
    .join('')
  const nodes = boxes()
    .map((n) => {
      const body = `<rect x="${n.x}" y="${n.y}" width="${W}" height="${H}" class="box${n.disabled ? ' off' : ''}"/>
        <text x="${n.x + W / 2}" y="${n.y + (n.sub ? 38 : 51)}" class="bl">${esc(n.label)}</text>
        ${n.sub ? `<text x="${n.x + W / 2}" y="${n.y + 64}" class="bs">${esc(n.sub)}</text>` : ''}
        ${n.doc ? `<path d="M${n.x - 24} ${n.y + H - 22} h96 v34 q-24 -10 -48 0 t-48 0 z" class="doc"/><text x="${n.x + 24}" y="${n.y + H}" class="dl">${n.doc}</text>` : ''}
        ${n.url ? `<circle cx="${n.x + W - 14}" cy="${n.y + 14}" r="7" class="dot" id="dot-${n.key}"/>` : ''}`
      return n.url ? `<a href="${esc(n.url)}/" target="_blank"><g class="node">${body}</g></a>` : `<g>${body}</g>`
    })
    .join('')
  return `<svg viewBox="40 0 1290 890" class="diagram" role="img" aria-label="IHV architecture">
    <defs>
      <marker id="ab" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#155e86"/></marker>
      <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#e5383b"/></marker>
    </defs>
    ${groups}${lines}${nodes}
    <g transform="translate(60 20)"><line x1="0" y1="8" x2="50" y2="8" class="tc" marker-end="url(#ab)"/><text x="60" y="13" class="lg">Trust Chain</text>
    <line x1="0" y1="36" x2="50" y2="36" class="reg" marker-end="url(#ar)"/><text x="60" y="41" class="lg">Registration</text></g>
  </svg>`
}

const scenario = () => {
  const btn = (href: string, label: string) => `<a class="btn" href="${esc(href)}" target="_blank">${esc(label)}</a>`
  const steps = [
    {
      t: 'ウォレットを準備する',
      d: 'Web Wallet を開き「Wallet Provider に登録」。Wallet Provider を OpenID Federation で確認し、Wallet Instance 登録と Wallet Attestation 取得を行います。',
      b: [btn(WALLET_UI_URL, 'Web Wallet を開く')],
    },
    {
      t: '学生証明書を発行してもらう',
      d: '学認Issuer で「機関IdPでログイン」(taro / password)。属性Provider の属性も合わせて表示されたら「Credential Offer を作成」→「Web Wallet で開く」→ ウォレットで Issuer の信頼チェーンを確認して「受け取る」。',
      b: [btn(ENTITY.issuer, '学認Issuer を開く')],
    },
    {
      t: 'Verifier に提示する',
      d: 'Verifier で「提示リクエストを作成」→「Web Wallet で開く」。ウォレットが Trust List (LoTE) とアクセス証明書で Verifier を認証します。開示する属性を選んで「提示する」。Verifier 側で Wallet Attestation / VP / Issuer / Status List の 4 つの検証結果が表示されます。',
      b: [btn(ENTITY.verifier, 'Verifier を開く')],
    },
    {
      t: 'クレデンシャルを一時停止・失効させる',
      d: '学認Issuer の管理画面で「一時停止」や「失効」。Status List Token の ttl (10 秒) 経過後に再提示すると Verifier が拒否します。ウォレットのカードの状態表示も変わります。',
      b: [btn(`${ENTITY.issuer}/admin`, 'Issuer 管理画面'), btn(ENTITY.statusList, 'Status List')],
    },
    {
      t: 'Verifier の登録を停止する',
      d: 'Trust List (Registrar) で Verifier を「一時停止」。アクセス証明書が CRL で失効し、ウォレットが提示を拒否します。「再開」で元に戻ります。',
      b: [btn(ENTITY.trustList, 'Trust List を開く')],
    },
    {
      t: 'Wallet Instance を失効させる',
      d: 'Wallet Provider で Wallet Instance を「失効」。Wallet Attestation が参照する Status List のエントリが INVALID になり、約 10 秒 (ttl) 後から Issuer は発行を、Verifier は提示を拒否します (ウォレットが保持している発行済み Attestation も無効)。Attestation の再取得も拒否されます。',
      b: [btn(ENTITY.walletProvider, 'Wallet Provider を開く')],
    },
    {
      t: '信頼チェーンを調べる',
      d: 'I2 (InCommon) 配下の InCommon SP から、学認側エンティティの Trust Chain・metadata_policy 適用後のメタデータを確認できます (eduGAIN 経由のフェデレーション間信頼)。',
      b: [btn(ENTITY.incommonSp, 'Trust Chain Explorer')],
    },
  ]
  return steps
    .map(
      (s, i) =>
        `<li><div class="num">${i + 1}</div><div><div class="st">${esc(s.t)}</div><div class="sd">${esc(s.d)}</div><div class="sb">${s.b.join('')}</div></div></li>`
    )
    .join('')
}

const pageHtml = () => `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>IHV デモコンソール</title>
<style>
:root{--c:#155e86;--bg:#f3f5f8;--fg:#1f2328;--mut:#5b6670;--ok:#1a7f37;--ng:#cf222e;--line:#d0d7de}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}
header{background:var(--c);color:#fff;padding:12px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header h1{margin:0;font-size:19px}header .mut{color:#cfe3ef;font-size:13px}
.wrap{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,1fr);gap:16px;padding:16px;max-width:1700px;margin:0 auto}
@media (max-width:1000px){.wrap{grid-template-columns:1fr}}
.panel{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.panel h2{font-size:15px;margin:0 0 10px}
.diagram{width:100%;height:auto;display:block}
.box{fill:var(--c);stroke:#0d3d58;stroke-width:2}.box.off{fill:#9aa7b1;stroke:#7d8a94}
.node:hover .box{fill:#1b77aa;cursor:pointer}
.bl{fill:#fff;font-size:24px;text-anchor:middle}.bs{fill:#dbe9f2;font-size:15px;text-anchor:middle}
.grp{fill:none;stroke:#e5383b;stroke-width:2.5}.gl{fill:#e5383b;font-size:16px}
.tc{stroke:#155e86;stroke-width:2.5;stroke-dasharray:8 6}.reg{stroke:#e5383b;stroke-width:2.5;stroke-dasharray:8 6}
.doc{fill:var(--c);stroke:#0d3d58;stroke-width:1.5}.dl{fill:#fff;font-size:14px;text-anchor:middle}
.lg{font-size:17px;fill:var(--fg)}
.dot{fill:#9aa7b1;stroke:#fff;stroke-width:2}.dot.up{fill:#2da44e}.dot.down{fill:#cf222e}
ol.sc{list-style:none;margin:0;padding:0}ol.sc li{display:flex;gap:12px;padding:10px 0;border-top:1px solid #eef1f4}
.num{flex:none;width:28px;height:28px;border-radius:50%;background:var(--c);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700}
.st{font-weight:700}.sd{color:var(--mut);font-size:13px;margin:3px 0 6px;line-height:1.55}
.btn{display:inline-block;background:var(--c);color:#fff;text-decoration:none;border-radius:6px;padding:6px 12px;font-size:13px;margin:0 6px 4px 0}
.tl{position:sticky;top:12px;max-height:calc(100vh - 24px);display:flex;flex-direction:column}
.tl .bar{display:flex;gap:8px;align-items:center;margin-bottom:8px}.tl .bar h2{flex:1;margin:0}
.tl select,.tl button{font-size:12px;padding:4px 6px;border:1px solid var(--line);border-radius:6px;background:#fff}
#events{overflow-y:auto;flex:1;margin:0;padding:0;list-style:none}
#events li{padding:7px 2px;border-bottom:1px solid #eef1f4;font-size:13px;animation:fade .6s}
@keyframes fade{from{background:#fff8c5}to{background:transparent}}
.ev-h{display:flex;gap:6px;align-items:baseline}.ev-t{color:var(--mut);font-size:11px;font-variant-numeric:tabular-nums}
.chip{font-size:11px;border-radius:999px;padding:1px 8px;color:#fff;white-space:nowrap}
.lv-ok{color:var(--ok)}.lv-error{color:var(--ng)}.lv-info{color:var(--fg)}
.ev-d{color:var(--mut);font-size:12px;word-break:break-all;margin-left:2px}
.empty{color:var(--mut);font-size:13px}
</style></head><body>
<header><h1>学認 IHV プロトタイプ デモコンソール</h1><span class="mut">OpenID Federation × vcknots (OID4VCI / OID4VP) × ETSI TS 119 602 × Token Status List</span></header>
<div class="wrap">
 <div>
  <div class="panel"><h2>構成 (クリックで各エンティティの画面を開きます / ●は稼働状態)</h2>${diagramSvg()}</div>
  <div class="panel" style="margin-top:16px"><h2>デモシナリオ</h2><ol class="sc">${scenario()}</ol></div>
 </div>
 <div class="panel tl">
  <div class="bar"><h2>タイムライン</h2>
   <select id="filter"><option value="">すべて</option></select>
   <button id="clear">クリア</button></div>
  <ul id="events"><li class="empty" id="empty">操作するとここに各エンティティの処理が流れます</li></ul>
 </div>
</div>
<script>
const colors = {'Wallet Instance':'#8250df','学認Issuer':'#155e86','Verifier':'#bf3989','機関IdP':'#1a7f37','属性Provider':'#2da44e','Wallet Provider':'#9a6700','Trust List':'#cf222e','Status List':'#0969da'}
let last = 0; const seen = new Set()
const list = document.getElementById('events'), filter = document.getElementById('filter')
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))
function render(e) {
  if (!seen.has(e.source)) { seen.add(e.source); const o = document.createElement('option'); o.value = o.textContent = e.source; filter.appendChild(o) }
  const li = document.createElement('li'); li.dataset.source = e.source
  li.hidden = !!filter.value && filter.value !== e.source
  const t = new Date(e.at).toLocaleTimeString('ja-JP')
  const mark = e.level === 'ok' ? '✓' : e.level === 'error' ? '✗' : '→'
  li.innerHTML = '<div class="ev-h"><span class="ev-t">' + t + '</span><span class="chip" style="background:' + (colors[e.source] || '#57606a') + '">' + esc(e.source) + '</span><span class="lv-' + e.level + '">' + mark + ' ' + esc(e.message) + '</span></div>' + (e.detail ? '<div class="ev-d">' + esc(e.detail) + '</div>' : '')
  document.getElementById('empty')?.remove()
  list.prepend(li)
}
async function poll() {
  try { const r = await fetch('/api/events?after=' + last); const evs = await r.json(); for (const e of evs) { render(e); last = e.id } } catch {}
  setTimeout(poll, 1200)
}
async function health() {
  try { const h = await (await fetch('/api/health')).json(); for (const [k, up] of Object.entries(h)) { const d = document.getElementById('dot-' + k); if (d) d.setAttribute('class', 'dot ' + (up ? 'up' : 'down')) } } catch {}
  setTimeout(health, 5000)
}
filter.onchange = () => { for (const li of list.children) if (li.dataset.source) li.hidden = !!filter.value && filter.value !== li.dataset.source }
document.getElementById('clear').onclick = async () => { await fetch('/api/events', { method: 'DELETE' }); list.innerHTML = '' }
poll(); health()
</script></body></html>`

/** Demo console: architecture diagram with live status, guided scenario and event timeline. */
export const createDemoConsole = () => {
  const app = new Hono()
  app.use('/api/*', cors({ origin: '*' }))
  app.get('/', (c) => c.html(pageHtml()))
  app.get('/api/events', (c) => c.json(eventsAfter(Number(c.req.query('after') ?? 0))))
  app.delete('/api/events', (c) => {
    clearEvents()
    return c.json({ ok: true })
  })
  /** Events forwarded by out-of-process components (the Go wallet). */
  app.post('/api/events', async (c) => {
    const e = await c.req.json<Partial<DemoEvent>>().catch(() => ({}) as Partial<DemoEvent>)
    if (!e.message) return c.json({ error: 'message required' }, 400)
    const level = e.level === 'error' || e.level === 'info' ? e.level : 'ok'
    emit(String(e.source ?? 'external').slice(0, 40), level, String(e.message).slice(0, 300), e.detail ? String(e.detail).slice(0, 1000) : undefined)
    return c.json({ ok: true })
  })
  app.get('/api/health', async (c) => {
    const entries = await Promise.all(
      boxes()
        .filter((b) => b.url)
        .map(async (b) => {
          try {
            const res = await fetch(healthUrl(b.key, b.url as string), { signal: AbortSignal.timeout(1500) })
            return [b.key, res.ok] as const
          } catch {
            return [b.key, false] as const
          }
        })
    )
    return c.json(Object.fromEntries(entries))
  })
  return { app }
}
