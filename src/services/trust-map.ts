import { ENTITY, WALLET_UI_URL } from '../config.js'
import { esc } from '../common/html.js'

/**
 * "Who verifies whom, and how": every trust decision made in the prototype, drawn as arrows from
 * the verifying entity to the verified entity. Federation edges resolve a Trust Chain up to the
 * eduGAIN Trust Anchor and use the resolved metadata of the stated entity type.
 */

type Method = 'federation' | 'trustlist' | 'attestation'
type NodeKey =
  | 'wallet' | 'walletProvider' | 'issuer' | 'idp' | 'attributeProvider' | 'gakuninSp' | 'incommonSp'
  | 'verifier' | 'trustList' | 'statusList'

type Edge = {
  from: NodeKey
  to: NodeKey
  method: Method
  /** entity type whose resolved metadata is used (federation edges) */
  entityType?: string
  /** when it happens */
  when: string
  /** what is checked with the result */
  what: string
  code: string
  /** curvature (px, to the left of travel); default 34 */
  bend?: number
}

const NODES: Record<NodeKey, { label: string; sub?: string; url: string; x: number; y: number }> = {
  gakuninSp: { label: '学認SP', sub: '通常のSP', url: ENTITY.gakuninSp, x: 20, y: 40 },
  idp: { label: '機関IdP', url: ENTITY.idp, x: 330, y: 40 },
  incommonSp: { label: 'InCommon SP', sub: 'I2 配下', url: ENTITY.incommonSp, x: 640, y: 40 },
  trustList: { label: 'Trust List', sub: 'LoTE / Access CA', url: ENTITY.trustList, x: 1030, y: 40 },
  attributeProvider: { label: '属性Provider', url: ENTITY.attributeProvider, x: 20, y: 330 },
  issuer: { label: '学認Issuer', url: ENTITY.issuer, x: 330, y: 330 },
  wallet: { label: 'Wallet Instance', sub: 'Holder', url: WALLET_UI_URL, x: 680, y: 330 },
  verifier: { label: 'Verifier', sub: 'フェデレーション外', url: ENTITY.verifier, x: 1030, y: 330 },
  walletProvider: { label: 'Wallet Provider', url: ENTITY.walletProvider, x: 500, y: 610 },
  statusList: { label: 'Status List', url: ENTITY.statusList, x: 860, y: 610 },
}
const BW = 210
const BH = 74

export const TRUST_EDGES: Edge[] = [
  // Wallet Instance
  { from: 'wallet', to: 'walletProvider', method: 'federation', entityType: 'wallet_provider', when: '登録 / Wallet Attestation 取得時', what: '登録エンドポイントと jwks を取得し、受け取った Wallet Attestation の署名を検証', code: 'wallet-instance/attestation.go' },
  { from: 'wallet', to: 'issuer', method: 'federation', entityType: 'openid_credential_issuer', when: 'Credential Offer 受信時', what: 'credential_issuer がフェデレーションに属する Issuer であることを確認してから受け取る', code: 'wallet-instance/flows.go' },
  { from: 'wallet', to: 'trustList', method: 'federation', entityType: 'trust_list_provider', when: '提示リクエスト受信時 (LoTE 取得)', what: 'LoTE の所在 (lote_locations) と署名鍵 (jwks) を取得し、LoTE の JAdES 署名を検証', code: 'wallet-instance/trustlist.go' },
  { from: 'wallet', to: 'statusList', method: 'federation', entityType: 'status_list_provider', when: '保持中のクレデンシャル / Attestation の状態確認時', what: 'Status List Token の iss (Status Issuer) を確認し、その jwks で署名を検証', code: 'wallet-instance/statuslist.go' },
  { from: 'wallet', to: 'verifier', method: 'trustlist', when: '提示リクエスト受信時', what: 'Request Object の x5c のアクセス証明書 (ETSI TS 119 411-8) を、LoTE (ETSI TS 119 602) から得た Access CA をトラストアンカーにパス検証・CRL 確認 (vcknots X509TrustChainRoots)。Trust List 自体は Federation で確認済み', code: 'wallet-instance/trustlist.go' },
  // 学認Issuer
  { from: 'issuer', to: 'idp', method: 'federation', entityType: 'openid_provider', when: 'ログイン時', what: 'authorization / token エンドポイントと jwks を取得し、ID Token の署名を検証', code: 'src/common/oidc-rp.ts' },
  { from: 'issuer', to: 'attributeProvider', method: 'federation', entityType: 'attribute_provider', when: '属性取得時', what: 'attribute_endpoint と jwks を取得し、属性応答の署名を検証', code: 'src/services/issuer.ts' },
  { from: 'issuer', to: 'wallet', method: 'attestation', when: 'Token リクエスト時 (OID4VCI)', what: 'OAuth-Client-Attestation (Wallet Provider 署名) と PoP (Wallet Instance の鍵) を検証し、Wallet Instance の状態 (Status List) を確認', code: 'src/common/wallet-attestation.ts' },
  { from: 'issuer', to: 'walletProvider', method: 'federation', entityType: 'wallet_provider', when: 'Wallet Attestation 検証時', what: 'Attestation の iss の Trust Chain を解決し、wallet_provider.jwks で Attestation の署名を検証', code: 'src/common/wallet-attestation.ts' },
  { from: 'issuer', to: 'statusList', method: 'federation', entityType: 'status_list_provider', when: 'Wallet Attestation 検証時', what: 'Attestation が参照する Status List Token の署名を status_list_provider.jwks で検証', code: 'src/status-list/federation-key-resolver.ts' },
  // 機関IdP
  { from: 'idp', to: 'issuer', method: 'federation', entityType: 'openid_relying_party', when: '認可リクエスト時 (自動登録)', what: 'redirect_uris と jwks を取得 (事前登録なし)、private_key_jwt を検証。Trust Chain の経路で属性リリースを決定 (NII 経由 = 全属性)', code: 'src/services/idp.ts' },
  { from: 'idp', to: 'gakuninSp', method: 'federation', entityType: 'openid_relying_party', when: '認可リクエスト時 (自動登録)', what: '同上。NII 経由なので学認の全属性をリリース', code: 'src/services/idp.ts' },
  { from: 'idp', to: 'incommonSp', method: 'federation', entityType: 'openid_relying_party', when: '認可リクエスト時 (自動登録)', what: '同上。I2 → eduGAIN 経由 (他フェデレーション) なので最小限の属性のみリリース', code: 'src/services/idp.ts' },
  // 属性Provider
  { from: 'attributeProvider', to: 'issuer', method: 'federation', entityType: 'openid_relying_party', when: '属性要求受信時', what: '要求者の jwks で属性要求 JWT の署名を検証', code: 'src/services/attribute-provider.ts' },
  // SPs
  { from: 'gakuninSp', to: 'idp', method: 'federation', entityType: 'openid_provider', when: 'ログイン時', what: 'エンドポイントと jwks を取得し、ID Token の署名を検証', code: 'src/common/oidc-rp.ts' },
  { from: 'incommonSp', to: 'idp', method: 'federation', entityType: 'openid_provider', when: 'ログイン時', what: '同上 (I2 側から NII 配下の IdP を eduGAIN 経由で確認)', code: 'src/common/oidc-rp.ts' },
  // Verifier
  { from: 'verifier', to: 'trustList', method: 'federation', entityType: 'trust_list_provider', when: '起動時 (Registrar への登録)', what: 'registration_endpoint を取得して登録し、アクセス証明書を受け取る', code: 'src/services/verifier.ts' },
  { from: 'verifier', to: 'wallet', method: 'attestation', when: 'VP 受信時 (OID4VP direct_post)', what: 'Wallet Attestation + PoP を検証し、Wallet Instance の状態 (Status List) を確認', code: 'src/common/wallet-attestation.ts' },
  { from: 'verifier', to: 'walletProvider', method: 'federation', entityType: 'wallet_provider', when: 'Wallet Attestation 検証時', what: 'wallet_provider.jwks で Attestation の署名を検証', code: 'src/common/wallet-attestation.ts', bend: 70 },
  { from: 'verifier', to: 'issuer', method: 'federation', entityType: 'openid_credential_issuer', when: 'VP 受信時', what: 'SD-JWT VC の iss の Trust Chain を解決し、openid_credential_issuer.jwks で署名を検証', code: 'src/services/verifier.ts', bend: 175 },
  { from: 'verifier', to: 'statusList', method: 'federation', entityType: 'status_list_provider', when: 'VP 受信時 (失効確認)', what: 'クレデンシャルの Status List Token の署名を status_list_provider.jwks で検証し、VALID / SUSPENDED / INVALID を判定', code: 'src/status-list/federation-key-resolver.ts' },
]

const METHODS: Record<Method, { label: string; color: string; desc: string }> = {
  federation: {
    label: 'OpenID Federation (Trust Chain 解決)',
    color: '#155e86',
    desc: '相手の Entity ID から eduGAIN TA まで Trust Chain を解決・検証し、metadata_policy 適用後のメタデータ (矢印の entity type) の鍵やエンドポイントを使う',
  },
  trustlist: {
    label: 'Trust List (ETSI LoTE + アクセス証明書)',
    color: '#cf222e',
    desc: 'Verifier はフェデレーション外。Trust List の LoTE から Access CA を得て、Verifier のアクセス証明書 (X.509) を検証',
  },
  attestation: {
    label: 'Wallet Attestation',
    color: '#8250df',
    desc: 'Wallet Provider が発行した Attestation と PoP で Wallet Instance を検証 (Wallet Provider 自体は Federation で確認)',
  },
}

type Pt = { x: number; y: number }
const center = (k: NodeKey): Pt => ({ x: NODES[k].x + BW / 2, y: NODES[k].y + BH / 2 })
/** Point where the ray from the box centre towards `toward` leaves the box (plus margin). */
const clip = (k: NodeKey, toward: Pt, margin = 6): Pt => {
  const c = center(k)
  const dx = toward.x - c.x
  const dy = toward.y - c.y
  const s = Math.min((BW / 2 + margin) / Math.abs(dx || 1e-9), (BH / 2 + margin) / Math.abs(dy || 1e-9))
  return { x: c.x + dx * s, y: c.y + dy * s }
}

const diagram = () => {
  const edges = TRUST_EDGES.map((e, i) => {
    const n = i + 1
    const a = center(e.from)
    const b = center(e.to)
    const len = Math.hypot(b.x - a.x, b.y - a.y)
    // curve to the left of the direction of travel, so A->B and B->A are drawn apart
    const off = e.bend ?? 34
    const ctrl = { x: (a.x + b.x) / 2 + (-(b.y - a.y) / len) * off, y: (a.y + b.y) / 2 + ((b.x - a.x) / len) * off }
    const p1 = clip(e.from, ctrl)
    const p2 = clip(e.to, ctrl, 8)
    const mid = { x: 0.25 * p1.x + 0.5 * ctrl.x + 0.25 * p2.x, y: 0.25 * p1.y + 0.5 * ctrl.y + 0.25 * p2.y }
    const m = METHODS[e.method]
    return `<g class="edge" data-n="${n}" data-from="${e.from}" data-to="${e.to}" data-method="${e.method}">
      <path d="M${p1.x.toFixed(1)} ${p1.y.toFixed(1)} Q${ctrl.x.toFixed(1)} ${ctrl.y.toFixed(1)} ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}" stroke="${m.color}" marker-end="url(#tm-${e.method})"/>
      <circle cx="${mid.x.toFixed(1)}" cy="${mid.y.toFixed(1)}" r="12" fill="#fff" stroke="${m.color}" stroke-width="2"/>
      <text x="${mid.x.toFixed(1)}" y="${(mid.y + 4.5).toFixed(1)}" fill="${m.color}">${n}</text>
      <title>${esc(`${n}. ${NODES[e.from].label} → ${NODES[e.to].label}: ${m.label}${e.entityType ? ` (${e.entityType})` : ''}`)}</title></g>`
  }).join('')
  const nodes = (Object.entries(NODES) as [NodeKey, (typeof NODES)[NodeKey]][])
    .map(
      ([k, n]) => `<g class="node" data-key="${k}"><rect x="${n.x}" y="${n.y}" width="${BW}" height="${BH}" rx="10"/>
      <text x="${n.x + BW / 2}" y="${n.y + (n.sub ? 32 : 43)}" class="nl">${esc(n.label)}</text>
      ${n.sub ? `<text x="${n.x + BW / 2}" y="${n.y + 54}" class="ns">${esc(n.sub)}</text>` : ''}</g>`
    )
    .join('')
  const markers = (Object.entries(METHODS) as [Method, (typeof METHODS)[Method]][])
    .map(
      ([k, m]) =>
        `<marker id="tm-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${m.color}"/></marker>`
    )
    .join('')
  return `<svg class="tm" viewBox="0 0 1260 700" xmlns="http://www.w3.org/2000/svg"><defs>${markers}</defs>
    <g class="ta"><rect x="20" y="168" width="250" height="60" rx="8"/><text x="145" y="192" class="tat">🔑 eduGAIN Trust Anchor 公開鍵</text>
    <text x="145" y="212" class="tas">全エンティティに事前設定 (Federation の起点)</text></g>
    ${edges}${nodes}</svg>`
}

const table = () =>
  `<table class="tmt"><thead><tr><th>#</th><th>検証する側 → 検証される側</th><th>方法</th><th>いつ</th><th>何を確認するか</th><th>実装</th></tr></thead><tbody>${TRUST_EDGES.map(
    (e, i) => {
      const m = METHODS[e.method]
      const how = e.entityType
        ? `<span class="mtag" style="background:${m.color}">Federation</span> <code>${esc(e.entityType)}</code><br><a href="/trust-chain?entity=${encodeURIComponent(NODES[e.to].url)}" target="_blank">Trust Chain を図で見る</a>`
        : `<span class="mtag" style="background:${m.color}">${esc(e.method === 'trustlist' ? 'Trust List' : 'Wallet Attestation')}</span>`
      return `<tr data-n="${i + 1}" data-from="${e.from}" data-to="${e.to}"><td><span class="tn" style="border-color:${m.color};color:${m.color}">${i + 1}</span></td>
      <td><b>${esc(NODES[e.from].label)}</b> → <b>${esc(NODES[e.to].label)}</b></td><td>${how}</td><td>${esc(e.when)}</td><td>${esc(e.what)}</td><td><code>${esc(e.code)}</code></td></tr>`
    }
  ).join('')}</tbody></table>`

export const TRUST_MAP_CSS = `
main{max-width:1320px}
.tm{width:100%;height:auto;display:block;font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;user-select:none}
.tm .node rect{fill:#155e86;stroke:#0d3d58;stroke-width:2;cursor:pointer}.tm .node:hover rect{fill:#1b77aa}
.tm .node.sel rect{fill:#bf8700;stroke:#7d4e00}
.tm .nl{fill:#fff;font-size:19px;font-weight:700;text-anchor:middle;pointer-events:none}.tm .ns{fill:#dbe9f2;font-size:13px;text-anchor:middle;pointer-events:none}
.tm .edge path{fill:none;stroke-width:2.6}.tm .edge text{font-size:13px;font-weight:700;text-anchor:middle}
.tm .edge{transition:opacity .2s}.tm.filtered .edge{opacity:.08}.tm.filtered .edge.out,.tm.filtered .edge.in,.tm .edge.hl{opacity:1}
.tm .edge.in path{stroke-dasharray:7 5}.tm .edge.hl path{stroke-width:5}
.tm .ta rect{fill:#fff4d6;stroke:#bf8700}.tm .tat{font-size:14px;text-anchor:middle;fill:#7d4e00;font-weight:700}.tm .tas{font-size:11px;text-anchor:middle;fill:#7d4e00}
.tmbar{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}.tmbar button{background:#fff;color:#155e86;border:1px solid #155e86;padding:4px 10px;font-size:13px}
.tmbar button.on{background:#155e86;color:#fff}
.legend{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:12.5px;margin:6px 0}.legend div{max-width:390px}.legend b{display:inline-block;width:26px;height:4px;vertical-align:middle;margin-right:6px}
.mtag{color:#fff;font-size:11px;border-radius:999px;padding:1px 8px;white-space:nowrap}
.tn{display:inline-flex;width:24px;height:24px;border-radius:50%;border:2px solid;align-items:center;justify-content:center;font-weight:700;font-size:12px}
table.tmt{font-size:13px}table.tmt tr.hl td{background:#fff8c5}table.tmt tr.dim{opacity:.35}
`

export const trustMapBody = () => `
<section><h3>誰が誰を、どうやって検証しているか</h3>
<p class="mut">矢印は「検証する側 → 検証される側」。エンティティをクリックすると、そのエンティティが<b>検証する</b>矢印 (実線) と<b>検証される</b>矢印 (破線) だけを表示します。番号や表の行にマウスを乗せると対応する矢印が強調されます。</p>
<div class="tmbar" id="tmbar"><button class="on" data-key="">すべて</button>${(Object.entries(NODES) as [NodeKey, (typeof NODES)[NodeKey]][])
  .map(([k, n]) => `<button data-key="${k}">${esc(n.label)}</button>`)
  .join('')}</div>
${diagram()}
<div class="legend">${Object.values(METHODS)
  .map((m) => `<div><b style="background:${m.color}"></b><strong>${esc(m.label)}</strong><br><span class="mut">${esc(m.desc)}</span></div>`)
  .join('')}</div>
<p class="mut" id="tmsum"></p></section>
<section><h3>検証の一覧</h3>${table()}</section>
<script>
(() => {
  const svg = document.querySelector('.tm'), rows = [...document.querySelectorAll('table.tmt tbody tr')]
  const edges = [...svg.querySelectorAll('.edge')], nodes = [...svg.querySelectorAll('.node')]
  const buttons = [...document.querySelectorAll('#tmbar button')], sum = document.getElementById('tmsum')
  const names = ${JSON.stringify(Object.fromEntries(Object.entries(NODES).map(([k, n]) => [k, n.label])))}
  function select(key) {
    svg.classList.toggle('filtered', !!key)
    for (const b of buttons) b.classList.toggle('on', b.dataset.key === key)
    for (const n of nodes) n.classList.toggle('sel', n.dataset.key === key)
    for (const e of edges) { e.classList.toggle('out', e.dataset.from === key); e.classList.toggle('in', e.dataset.to === key) }
    let o = 0, i = 0
    for (const r of rows) { const rel = !key || r.dataset.from === key || r.dataset.to === key; r.classList.toggle('dim', !rel); if (key && r.dataset.from === key) o++; if (key && r.dataset.to === key) i++ }
    sum.textContent = key ? names[key] + ' が検証する相手: ' + o + ' 件 (実線) / ' + names[key] + ' を検証する相手: ' + i + ' 件 (破線)' : ''
  }
  function hl(n, on) { for (const e of edges) if (e.dataset.n === n) e.classList.toggle('hl', on); for (const r of rows) if (r.dataset.n === n) r.classList.toggle('hl', on) }
  for (const b of buttons) b.onclick = () => select(b.dataset.key)
  for (const n of nodes) n.onclick = () => select(n.classList.contains('sel') ? '' : n.dataset.key)
  for (const el of [...edges, ...rows]) { el.onmouseenter = () => hl(el.dataset.n, true); el.onmouseleave = () => hl(el.dataset.n, false) }
  const q = new URLSearchParams(location.search).get('entity'); if (q) select(q)
})()
</script>`
