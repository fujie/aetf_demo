import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { ENTITY, WALLET_UI_URL } from '../config.js'
import { esc, page, escMsg } from '../common/html.js'
import { clearEvents, emit, eventsAfter } from '../common/events.js'
import { currentLang, langSwitcherHtml, t } from '../common/i18n.js'
import { entityLabels } from '../common/names.js'
import type { TrustAnchorConfig } from '../federation/resolver.js'
import { TRUST_CHAIN_VIEW_CSS, resolveWithTrace, trustChainVisualHtml } from '../federation/trust-chain-view.js'
import { TRUST_MAP_CSS, trustMapBody } from './trust-map.js'
import type { createFederationSettings } from './federation-settings.js'

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
  { key: 'idp', label: t('機関IdP', 'Institution IdP'), url: ENTITY.idp, x: 130, y: 178, doc: 'metadata' },
  { key: 'attributeProvider', label: t('属性Provider', 'Attribute Provider'), url: ENTITY.attributeProvider, x: 130, y: 322, doc: 'metadata' },
  { key: 'gakuninSp', label: t('通常のSP', 'Regular SP'), sub: t('電子ジャーナル', 'e-journal'), url: ENTITY.gakuninSp, x: 610, y: 178, doc: 'metadata' },
  { key: 'issuer', label: t('学認Issuer', 'GakuNin Issuer'), url: ENTITY.issuer, x: 610, y: 322, doc: 'metadata' },
  { key: 'walletProvider', label: 'Wallet Provider', url: ENTITY.walletProvider, x: 610, y: 478, doc: 'metadata' },
  { key: 'trustList', label: 'Trust List', sub: 'ETSI TS 119 602', url: ENTITY.trustList, x: 610, y: 622, doc: 'metadata' },
  { key: 'statusList', label: 'Status List', sub: 'Token Status List', url: ENTITY.statusList, x: 610, y: 766, doc: 'metadata' },
  { key: 'wallet', label: 'Wallet Instance', sub: 'Web Wallet', url: WALLET_UI_URL, x: 965, y: 478, doc: 'Attestation' },
  { key: 'verifier', label: 'Verifiers', url: ENTITY.verifier, x: 965, y: 622 },
  { key: 'incommonSp', label: 'InCommon SP', sub: t('学認IdPでログイン可', 'login with GakuNin IdP'), url: ENTITY.incommonSp, x: 1060, y: 178, doc: 'metadata' },
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
    line(cx('gakuninSp'), b.gakuninSp.y, nb.x + 6, nb.y + 4),
    line(b.issuer.x, b.issuer.y + H / 2, nb.x, nb.y + 4),
    line(b.walletProvider.x, b.walletProvider.y + H / 2, nb.x - 2, nb.y + 4),
    line(b.trustList.x, b.trustList.y + H / 2, nb.x - 2, nb.y + 4),
    line(b.statusList.x, b.statusList.y + H / 2, nb.x - 2, nb.y + 4),
    line(cx('incommonSp'), b.incommonSp.y, cx('i2'), b.i2.y + H + 4),
    line(b.wallet.x, b.wallet.y + H / 2, b.walletProvider.x + W + 4, b.walletProvider.y + H / 2, true),
    line(b.verifier.x, b.verifier.y + H / 2, b.trustList.x + W + 4, b.trustList.y + H / 2, true),
  ].join('')
  const groups = [
    { x: 75, y: 158, w: 350, h: 296, label: t('学認IdPとして構成', 'Configured as GakuNin IdP') },
    { x: 555, y: 158, w: 350, h: 300, label: t('学認SPとして構成', 'Configured as GakuNin SP') },
    { x: 555, y: 464, w: 350, h: 410, label: t('OpenID Federation で Trust Chain確認', 'Trust Chain checked with OpenID Federation') },
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
      t: t('ウォレットを準備する', 'Set up the wallet'),
      d: t(
        'Web Wallet を開き「Wallet Provider に登録」。Wallet Provider を OpenID Federation で確認し、Wallet Instance 登録と Wallet Attestation 取得を行います。',
        'Open the Web Wallet and press "Register with the Wallet Provider". The wallet checks the Wallet Provider through OpenID Federation, registers the Wallet Instance and obtains a Wallet Attestation.'
      ),
      b: [btn(WALLET_UI_URL, t('Web Wallet を開く', 'Open the Web Wallet'))],
    },
    {
      t: t('学生証明書を発行してもらう', 'Get a student credential issued'),
      d: t(
        '学認Issuer で「機関IdPでログイン」(taro / password)。属性Provider の属性も合わせて表示されたら「Credential Offer を作成」→「Web Wallet で開く」→ ウォレットで Issuer の信頼チェーンを確認して「受け取る」。',
        'At the GakuNin Issuer, "Log in with the Institution IdP" (taro / password). When the attributes (including those from the Attribute Provider) are shown, "Create Credential Offer" → "Open in Web Wallet" → check the Issuer\'s trust chain in the wallet and "Accept".'
      ),
      b: [btn(ENTITY.issuer, t('学認Issuer を開く', 'Open the GakuNin Issuer'))],
    },
    {
      t: t('Verifier に提示する', 'Present to the Verifier'),
      d: t(
        'Verifier で「提示リクエストを作成」→「Web Wallet で開く」。ウォレットが Trust List (LoTE) とアクセス証明書で Verifier を認証します。開示する属性を選んで「提示する」。Verifier 側で Wallet Attestation / VP / Issuer / Status List の 4 つの検証結果が表示されます。',
        'At the Verifier, "Create presentation request" → "Open in Web Wallet". The wallet authenticates the Verifier with the Trust List (LoTE) and its access certificate. Choose the attributes to disclose and "Present". The Verifier shows the four checks: Wallet Attestation / VP / Issuer / Status List.'
      ),
      b: [btn(ENTITY.verifier, t('Verifier を開く', 'Open the Verifier'))],
    },
    {
      t: t('クレデンシャルを一時停止・失効させる', 'Suspend or revoke the credential'),
      d: t(
        '学認Issuer の管理画面で「一時停止」や「失効」。Status List Token の ttl (10 秒) 経過後に再提示すると Verifier が拒否します。ウォレットのカードの状態表示も変わります。',
        '"Suspend" or "Revoke" on the GakuNin Issuer admin page. Presenting again after the Status List Token ttl (10 s) is rejected by the Verifier. The status shown on the wallet card changes too.'
      ),
      b: [btn(`${ENTITY.issuer}/admin`, t('Issuer 管理画面', 'Issuer admin')), btn(ENTITY.statusList, 'Status List')],
    },
    {
      t: t('Verifier の登録を停止する', 'Suspend the Verifier\'s registration'),
      d: t(
        'Trust List (Registrar) で Verifier を「一時停止」。アクセス証明書が CRL で失効し、ウォレットが提示を拒否します。「再開」で元に戻ります。',
        '"Suspend" the Verifier at the Trust List (Registrar). Its access certificate is revoked via the CRL and the wallet refuses to present. "Resume" restores it.'
      ),
      b: [btn(ENTITY.trustList, t('Trust List を開く', 'Open the Trust List'))],
    },
    {
      t: t('Wallet Instance を停止・失効・再有効化する', 'Suspend, revoke and reactivate the Wallet Instance'),
      d: t(
        'Wallet Provider で「一時停止」(Status List: SUSPENDED) または「失効」(INVALID)。約 10 秒 (ttl) 後から Issuer・Verifier が Wallet Attestation を拒否し、ウォレットも Attestation を再取得できなくなります。「再有効化」で元に戻ります (一時停止からは同じエントリを VALID に、失効からは新しいエントリを割り当て。ウォレットは保持中の Attestation の状態を確認して自動で再取得します)。',
        '"Suspend" (Status List: SUSPENDED) or "Revoke" (INVALID) at the Wallet Provider. After about 10 s (ttl) the Issuer and the Verifier reject the Wallet Attestation, and the wallet can no longer obtain one. "Reactivate" restores it (from suspended the same entry becomes VALID again; from revoked a new entry is allocated. The wallet checks the status of its attestation and fetches a new one automatically).'
      ),
      b: [btn(ENTITY.walletProvider, t('Wallet Provider を開く', 'Open the Wallet Provider'))],
    },
    {
      t: t('学認SP / InCommon SP に機関IdPでログインする', 'Log in to the GakuNin SP / InCommon SP with the Institution IdP'),
      d: t(
        '通常の学認SP (NII 配下) と InCommon SP (I2 配下) で「学認の機関IdPでログイン」。どちらも機関IdPに事前登録されておらず、IdP は SP の Trust Chain を解決して受け入れます (InCommon SP は eduGAIN 経由のフェデレーション間連携)。IdP は Trust Chain に応じて属性リリースを変え、学認SP には全属性、InCommon SP には最小限の属性を送ります。',
        '"Log in with your GakuNin institution IdP" at the regular GakuNin SP (under NII) and at the InCommon SP (under I2). Neither is pre-registered at the IdP: the IdP accepts them by resolving their Trust Chains (the InCommon SP via inter-federation through eduGAIN). The IdP adapts attribute release to the Trust Chain: all attributes to the GakuNin SP, a minimal set to the InCommon SP.'
      ),
      b: [btn(ENTITY.gakuninSp, t('学認SP を開く', 'Open the GakuNin SP')), btn(ENTITY.incommonSp, t('InCommon SP を開く', 'Open the InCommon SP'))],
    },
    {
      t: t('信頼チェーンを調べる', 'Explore the trust chains'),
      d: t(
        '信頼検証マップで「どのエンティティがどのエンティティを、どの方法 (Federation / Trust List / Wallet Attestation) で検証しているか」を一覧できます。Trust Chain Visualizer では、任意のエンティティについて Entity Configuration / Subordinate Statement の取得と署名検証の流れ、Trust Chain 配列、metadata_policy の適用結果を図で確認できます。Verifier はフェデレーション外なので解決に失敗する例になります。',
        'The Trust Map lists which entity verifies which entity and how (Federation / Trust List / Wallet Attestation). The Trust Chain Visualizer draws, for any entity, how Entity Configurations and Subordinate Statements are fetched and verified, the Trust Chain array and the result of metadata_policy. The Verifier is outside the federation, so resolving it fails.'
      ),
      b: [btn('/trust-map', t('信頼検証マップ', 'Trust Map')), btn('/trust-chain', 'Trust Chain Visualizer')],
    },
    {
      t: t('Trust Chain を壊してみる', 'Break a Trust Chain'),
      d: t(
        'フェデレーション設定で、登録の停止・Subordinate Statement の誤った鍵や期限切れ・metadata_policy の変更・authority_hints の変更・鍵ローテーションを行い、発行・提示・ログインが拒否されることを確認します (プリセットあり)。「すべて初期状態に戻す」で復旧します。',
        'In Federation settings, suspend registrations, put a wrong key in or expire Subordinate Statements, change metadata_policy or authority_hints, or rotate keys, and see issuance, presentation and login being rejected (presets available). "Restore everything" recovers.'
      ),
      b: [btn('/federation', t('フェデレーション設定', 'Federation settings'))],
    },
  ]
  return steps
    .map(
      (s, i) =>
        `<li><div class="num">${i + 1}</div><div><div class="st">${esc(s.t)}</div><div class="sd">${esc(s.d)}</div><div class="sb">${s.b.join('')}</div></div></li>`
    )
    .join('')
}

const pageHtml = () => `<!doctype html><html lang="${currentLang()}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${t('IHV デモコンソール', 'IHV demo console')}</title>
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
header .hn{margin-left:auto;display:flex;gap:14px;align-items:center;flex-wrap:wrap}header .hn a{color:#fff;font-size:13px;white-space:nowrap}
header .lang,header .lang a{color:#cfe3ef;font-size:13px}
header .reset{background:#fff;color:#cf222e;border:0;border-radius:6px;padding:5px 10px;font-size:13px;font-weight:700;cursor:pointer}
</style></head><body>
<header><h1>${t('学認 IHV プロトタイプ デモコンソール', 'GakuNin IHV prototype demo console')}</h1><span class="mut">OpenID Federation × vcknots (OID4VCI / OID4VP) × ETSI TS 119 602 × Token Status List</span><nav class="hn"><span class="lang">${langSwitcherHtml()}</span><a href="/federation" target="_blank">⚙ ${t('フェデレーション設定', 'Federation settings')}</a><a href="/trust-map" target="_blank">🧭 ${t('信頼検証マップ', 'Trust Map')}</a><a href="/trust-chain" target="_blank">🔗 Trust Chain Visualizer</a><form method="post" action="/reset-all" style="margin:0" onsubmit="return confirm(${esc(JSON.stringify(t('.data/ の内容 (全ての鍵・Status List・登録情報・発行履歴・Web Wallet のデータ) を削除し、全てを初期状態に戻します。よろしいですか？', 'This deletes the contents of .data/ (all keys, Status Lists, registrations, issuance history and Web Wallet data) and resets everything. Continue?')))})"><button class="reset">⟲ ${t('全て初期化', 'Reset all')}</button></form></nav></header>
<div class="wrap">
 <div>
  <div class="panel"><h2>${t('構成 (クリックで各エンティティの画面を開きます / ●は稼働状態)', 'Architecture (click an entity to open it / ● shows whether it is up)')}</h2>${diagramSvg()}</div>
  <div class="panel" style="margin-top:16px"><h2>${t('デモシナリオ', 'Demo scenario')}</h2><ol class="sc">${scenario()}</ol></div>
 </div>
 <div class="panel tl">
  <div class="bar"><h2>${t('タイムライン', 'Timeline')}</h2>
   <select id="filter"><option value="">${t('すべて', 'All')}</option></select>
   <button id="clear">${t('クリア', 'Clear')}</button></div>
  <ul id="events"><li class="empty" id="empty">${t('操作するとここに各エンティティの処理が流れます', 'What each entity does appears here as you use the demo')}</li></ul>
 </div>
</div>
<script>
const colors = {'学認SP':'#116329','InCommon SP':'#953800','Wallet Instance':'#8250df','学認Issuer':'#155e86','Verifier':'#bf3989','機関IdP':'#1a7f37','属性Provider':'#2da44e','Wallet Provider':'#9a6700','Trust List':'#cf222e','Status List':'#0969da','Federation 設定':'#6e7781','デモコンソール':'#24292f'}
let last = 0; const seen = new Set()
const list = document.getElementById('events'), filter = document.getElementById('filter')
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))
function render(e) {
  if (!seen.has(e.source)) { seen.add(e.source); const o = document.createElement('option'); o.value = e.source; o.textContent = e.sourceLabel; filter.appendChild(o) }
  const li = document.createElement('li'); li.dataset.source = e.source
  li.hidden = !!filter.value && filter.value !== e.source
  const t = new Date(e.at).toLocaleTimeString('${t('ja-JP', 'en-GB')}')
  const mark = e.level === 'ok' ? '✓' : e.level === 'error' ? '✗' : '→'
  li.innerHTML = '<div class="ev-h"><span class="ev-t">' + t + '</span><span class="chip" style="background:' + (colors[e.source] || '#57606a') + '">' + esc(e.sourceLabel) + '</span><span class="lv-' + e.level + '">' + mark + ' ' + esc(e.message) + '</span></div>' + (e.detail ? '<div class="ev-d">' + esc(e.detail) + '</div>' : '')
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
export const createDemoConsole = (opts: {
  anchors: TrustAnchorConfig[]
  federationSettings: ReturnType<typeof createFederationSettings>
  /** Deletes .data/ and restarts every entity (closes this console too). */
  onResetAll: () => Promise<void>
}) => {
  const app = new Hono()
  let resetting = false
  /** Reset all: answer first (this server is closed and recreated by the reset), then reset. */
  app.post('/reset-all', (c) => {
    if (!resetting) {
      resetting = true
      setTimeout(() => void opts.onResetAll(), 200)
    }
    return c.html(
      page(
        t('初期化中', 'Resetting'),
        `<section><h3>${t('全てを初期状態に戻しています…', 'Resetting everything…')}</h3>
        <p>${t('<code>.data/</code> を削除し、新しい鍵で全エンティティと Web Wallet を起動し直しています。完了するとデモコンソールに戻ります。', 'Deleting <code>.data/</code> and restarting every entity and the Web Wallet with new keys. You will be taken back to the demo console when done.')}</p>
        <p class="mut" id="st">${t('停止中…', 'Stopping…')}</p></section>
        <script>
        const st = document.getElementById('st'); let n = 0
        async function wait() {
          n++
          try { const r = await fetch('/api/ready', { cache: 'no-store' }); if (r.ok) { st.textContent = ${JSON.stringify(t('起動しました', 'Started'))}; location.href = '/'; return } } catch {}
          st.textContent = ${JSON.stringify(t('起動中… (', 'Starting… ('))} + n + ${JSON.stringify(t(' 秒)', ' s)'))}; setTimeout(wait, 1000)
        }
        setTimeout(wait, 1500)
        </script>`
      )
    )
  })
  /** 503 while this (old) console instance is being reset; the new instance answers 200. */
  app.get('/api/ready', (c) => (resetting ? c.json({ ready: false }, 503) : c.json({ ready: true })))
  opts.federationSettings.mount(app, (c, body) => c.html(page(t('フェデレーション設定', 'Federation settings'), body)))
  app.use('/api/*', cors({ origin: '*' }))
  app.get('/', (c) => c.html(pageHtml()))
  /** Trust map: who verifies whom, and how. */
  app.get('/trust-map', (c) =>
    c.html(page(t('信頼検証マップ', 'Trust Map'), `<style>${TRUST_MAP_CSS}</style>${trustMapBody()}`))
  )
  /** Trust Chain Visualizer: resolves a trust chain with tracing and draws it. */
  app.get('/trust-chain', async (c) => {
    const target = c.req.query('entity') ?? ENTITY.issuer
    const anchorId = opts.anchors[0]?.entityId
    const options = Object.entries(entityLabels())
      .filter(([id]) => id !== anchorId)
      .map(([id, name]) => `<option value="${esc(id)}" ${id === target ? 'selected' : ''}>${esc(name)}</option>`)
      .join('')
    const traced = await resolveWithTrace(target, opts.anchors)
    return c.html(
      page(
        'Trust Chain Visualizer',
        `<style>main{max-width:1280px}${TRUST_CHAIN_VIEW_CSS}</style>
        <section><form method="get">${t('解決するエンティティ', 'Entity to resolve')}: <select name="entity">${options}</select> <button>${t('Trust Chain を解決', 'Resolve Trust Chain')}</button></form>
        <p class="mut">${t(
          `Trust Anchor: ${escMsg(anchorId)} (公開鍵は事前設定)。OpenID Federation 1.0 の手順でボトムアップに Trust Chain を構築・検証し、その過程をトレースして描画します (キャッシュは使いません)。`,
          `Trust Anchor: ${escMsg(anchorId)} (public key configured in advance). The Trust Chain is built and validated bottom-up following OpenID Federation 1.0, and every step is traced and drawn (no cache).`
        )}</p></section>
        ${trustChainVisualHtml(target, traced, entityLabels())}`
      )
    )
  })
  /** Display names of entity identifiers in both languages (used by the Go web wallet). */
  app.get('/api/entity-names', (c) => c.json({ ja: entityLabels('ja'), en: entityLabels('en') }))
  app.get('/api/events', (c) => c.json(eventsAfter(Number(c.req.query('after') ?? 0))))
  app.delete('/api/events', (c) => {
    clearEvents()
    return c.json({ ok: true })
  })
  /** Events forwarded by out-of-process components (the Go wallet), optionally in both languages. */
  app.post('/api/events', async (c) => {
    type Posted = { source?: string; level?: string; message?: string; message_en?: string; detail?: string; detail_en?: string }
    const e = await c.req.json<Posted>().catch(() => ({}) as Posted)
    if (!e.message) return c.json({ error: 'message required' }, 400)
    const level = e.level === 'error' || e.level === 'info' ? e.level : 'ok'
    const text = (ja: string, en: string | undefined, max: number) => ({ ja: ja.slice(0, max), en: (en || ja).slice(0, max) })
    emit(
      String(e.source ?? 'external').slice(0, 40),
      level,
      text(String(e.message), e.message_en, 300),
      e.detail ? text(String(e.detail), e.detail_en, 1000) : undefined
    )
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
