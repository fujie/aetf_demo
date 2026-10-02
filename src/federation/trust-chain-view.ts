import * as jose from 'jose'
import { esc, escMsg } from '../common/html.js'
import { humanize } from '../common/names.js'
import type { FederationMetadata, MetadataPolicy } from './entity.js'
import {
  type ResolvedTrustChain,
  type Trace,
  type TraceEvent,
  type TrustAnchorConfig,
  resolveTrustChain,
} from './resolver.js'

/**
 * Visualises an OpenID Federation 1.0 Trust Chain resolution (from a resolver trace):
 *  (A) the federation tree: Entity Configurations, Subordinate Statements, authority_hints and
 *      which key verifies which statement,
 *  (B) the resulting Trust Chain array and how each statement's key is vouched for by the next,
 *  (C) the resolution steps (HTTP fetches / signature checks) in order,
 *  (D) metadata policy application.
 */

type Verify = Extract<TraceEvent, { type: 'verify' }>
type Fetch = Extract<TraceEvent, { type: 'fetch' }>
type MetadataStage = Extract<TraceEvent, { type: 'metadata' }>
type Claims = jose.JWTPayload & {
  jwks?: { keys: jose.JWK[] }
  metadata?: FederationMetadata
  metadata_policy?: MetadataPolicy
  authority_hints?: string[]
}

export type TraceResult = { trace: Trace; result?: ResolvedTrustChain; error?: string }

/** Resolves a trust chain (never from cache) while recording every step. */
export const resolveWithTrace = async (entityId: string, anchors: TrustAnchorConfig[]): Promise<TraceResult> => {
  const trace: Trace = []
  try {
    return { trace, result: await resolveTrustChain(entityId, anchors, { trace }) }
  } catch (e) {
    return { trace, error: (e as Error).message }
  }
}

const decode = (jwt?: string) => {
  if (!jwt) return {}
  try {
    return { header: jose.decodeProtectedHeader(jwt), payload: jose.decodeJwt(jwt) as Claims }
  } catch {
    return {}
  }
}

const shortKid = (kid?: string) => (kid ? (kid.length > 12 ? `${kid.slice(0, 10)}…` : kid) : '-')
const kidsOf = (claims?: Claims) => (claims?.jwks?.keys ?? []).map((k) => shortKid(k.kid)).join(', ') || '-'
const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

type EcNode = {
  id: string
  jwt?: string
  claims?: Claims
  kid?: string
  fetch?: Fetch
  selfVerify?: Verify
  ssVerify?: Verify
  taVerify?: Verify
}
type SsNode = { issuer: string; entity: string; jwt?: string; claims?: Claims; kid?: string; fetch?: Fetch; verify?: Verify }

const buildModel = (leafId: string, trace: Trace) => {
  const ecs = new Map<string, EcNode>()
  const sss = new Map<string, SsNode>()
  const hints = new Map<string, string[]>()
  const steps = new Map<TraceEvent, number>()
  const ec = (id: string) => {
    if (!ecs.has(id)) ecs.set(id, { id })
    return ecs.get(id) as EcNode
  }
  const ss = (issuer: string, entity: string) => {
    const k = `${issuer}|${entity}`
    if (!sss.has(k)) sss.set(k, { issuer, entity })
    return sss.get(k) as SsNode
  }
  ec(leafId)
  let n = 0
  for (const e of trace) {
    if (e.type !== 'statement') steps.set(e, ++n)
    switch (e.type) {
      case 'fetch':
        if (e.kind === 'ec') ec(e.entity).fetch = e
        else ss(e.issuer as string, e.entity).fetch = e
        break
      case 'statement': {
        const node = e.kind === 'ec' ? ec(e.entity) : ss(e.issuer, e.entity)
        const d = decode(e.jwt)
        node.jwt = e.jwt
        node.claims = d.payload
        node.kid = d.header?.kid
        break
      }
      case 'authority_hints':
        hints.set(e.entity, e.hints)
        for (const h of e.hints) ec(h)
        break
      case 'verify':
        if (e.kind === 'ss') ss(e.issuer as string, e.entity).verify = e
        else if (e.keySource === 'self') ec(e.entity).selfVerify = e
        else if (e.keySource === 'subordinate_statement') ec(e.entity).ssVerify = e
        else ec(e.entity).taVerify = e
        break
    }
  }
  // level 0 = leaf, +1 per authority_hints hop
  const level = new Map<string, number>([[leafId, 0]])
  const queue = [leafId]
  while (queue.length) {
    const cur = queue.shift() as string
    for (const h of hints.get(cur) ?? []) {
      if (!level.has(h)) {
        level.set(h, (level.get(cur) as number) + 1)
        queue.push(h)
      }
    }
  }
  return { ecs, sss, hints, steps, level }
}

type Model = ReturnType<typeof buildModel>

const status = (v?: { ok: boolean }) => (v ? (v.ok ? 'ok' : 'ng') : 'na')
const COLORS = { ok: '#1a7f37', ng: '#cf222e', na: '#8c959f' } as const

// ---- (A) federation tree diagram -------------------------------------------------------------
const EC_W = 300
const EC_H = 168
const SS_W = 320
const ROW_H = 260
const LABEL_W = 200

const diagramSvg = (model: Model, leafId: string, path: Set<string>, label: (id: string) => string) => {
  const { ecs, sss, hints, steps, level } = model
  const maxLevel = Math.max(...level.values())
  const byLevel = new Map<number, string[]>()
  for (const id of ecs.keys()) {
    const l = level.get(id) ?? 0
    byLevel.set(l, [...(byLevel.get(l) ?? []), id])
  }
  const subsOf = (id: string) => [...sss.values()].filter((s) => s.issuer === id)
  const maxSubs = Math.max(1, ...[...ecs.keys()].map((id) => subsOf(id).length))
  const groupW = LABEL_W + 40 + EC_W + 80 + maxSubs * (SS_W + 30)
  const pos = new Map<string, { x: number; y: number }>() // EC card position
  for (const [l, ids] of byLevel) {
    ids.forEach((id, i) => pos.set(id, { x: i * groupW + LABEL_W + 40, y: 30 + (maxLevel - l) * ROW_H }))
  }
  const ssPos = (s: SsNode) => {
    const p = pos.get(s.issuer) as { x: number; y: number }
    const k = subsOf(s.issuer).indexOf(s)
    return { x: p.x + EC_W + 80 + k * (SS_W + 30), y: p.y }
  }
  const width = Math.max(...[...byLevel.values()].map((ids) => ids.length)) * groupW
  const height = (maxLevel + 1) * ROW_H + 20

  /** Status pill; with `ev` it is prefixed by the step number of that trace event. */
  const badge = (x: number, y: number, text: string, st: 'ok' | 'ng' | 'na', ev?: TraceEvent) => {
    const n = ev && steps.get(ev)
    const pad = n ? 22 : 10
    return `<g><rect x="${x}" y="${y}" width="${text.length * 11 + 10 + pad}" height="20" rx="10" fill="${COLORS[st]}"/>${
      n ? `<circle cx="${x + 10}" cy="${y + 10}" r="10" class="sn" stroke="#fff" stroke-width="1.5"/><text x="${x + 10}" y="${y + 14}" class="snt">${n}</text>` : ''
    }<text x="${x + pad}" y="${y + 14}" class="bd">${esc(text)}</text></g>`
  }
  const lines = (x: number, y: number, rows: [string, string?][]) =>
    rows
      .map(
        ([t, cls], i) => `<text x="${x}" y="${y + i * 17}" class="${cls ?? 'tx'}">${esc(t)}</text>`
      )
      .join('')

  const stepNo = (e: TraceEvent | undefined, x: number, y: number) => {
    const n = e && steps.get(e)
    return n ? `<g><circle cx="${x}" cy="${y}" r="11" class="sn"/><text x="${x}" y="${y + 4}" class="snt">${n}</text></g>` : ''
  }
  const arrow = (
    x1: number, y1: number, x2: number, y2: number, st: 'ok' | 'ng' | 'na', text: string, ev?: TraceEvent, dashed = false
  ) => {
    const mx = (x1 + x2) / 2
    const my = (y1 + y2) / 2
    const w = text.length * 12 + 12
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${COLORS[st]}" stroke-width="2.5" ${dashed ? 'stroke-dasharray="7 5"' : ''} marker-end="url(#tcv-${st})"/>
      <rect x="${mx - w / 2}" y="${my - 11}" width="${w}" height="20" rx="4" fill="#fff" stroke="${COLORS[st]}"/>
      <text x="${mx}" y="${my + 4}" class="al" fill="${COLORS[st]}">${esc(text)}</text>${stepNo(ev, mx - w / 2 - 14, my)}`
  }

  const parts: string[] = []
  // entity label + EC card per entity
  for (const node of ecs.values()) {
    const p = pos.get(node.id) as { x: number; y: number }
    const isTa = !!node.taVerify
    const isLeaf = node.id === leafId
    const onPath = path.has(node.id)
    const role = isTa ? 'Trust Anchor' : isLeaf ? 'Leaf Entity (解決対象)' : 'Intermediate Entity'
    const lx = p.x - LABEL_W - 40
    parts.push(`<g><rect x="${lx}" y="${p.y + 30}" width="${LABEL_W}" height="96" rx="10" class="ent ${onPath ? 'onp' : ''} ${isTa ? 'ta' : ''}"/>
      <text x="${lx + LABEL_W / 2}" y="${p.y + 58}" class="er">${esc(role)}</text>
      <text x="${lx + LABEL_W / 2}" y="${p.y + 84}" class="en">${esc(trunc(label(node.id), 16))}</text>
      <text x="${lx + LABEL_W / 2}" y="${p.y + 106}" class="ei">${esc(trunc(node.id.replace(/^https?:\/\//, ''), 26))}</text></g>`)
    // EC card
    const st = node.fetch && !node.fetch.ok ? 'ng' : node.claims ? 'ok' : 'na'
    const rows: [string, string?][] = node.claims
      ? [
          [`iss = sub = ${trunc(label(node.id), 22)}`],
          [`jwks: kid ${kidsOf(node.claims)}`],
          [
            node.claims.authority_hints?.length
              ? `authority_hints: ${trunc(node.claims.authority_hints.map(label).join(', '), 24)}`
              : 'authority_hints: なし (最上位)',
          ],
          [`metadata: ${trunc(Object.keys(node.claims.metadata ?? {}).join(', ') || '-', 30)}`],
        ]
      : node.fetch && !node.fetch.ok
        ? [['取得失敗', 'tng'], [trunc(humanize(node.fetch.error ?? ''), 40), 'tng']]
        : [['(未取得)', 'tmut']]
    parts.push(`<g><rect x="${p.x}" y="${p.y}" width="${EC_W}" height="${EC_H}" rx="8" class="card ${onPath ? 'onp' : ''}" ${st === 'ng' ? `style="stroke:${COLORS.ng};stroke-width:2.5"` : ''}/>
      <path d="M${p.x} ${p.y + 8}a8 8 0 0 1 8 -8h${EC_W - 16}a8 8 0 0 1 8 8v20h-${EC_W}z" class="ech"/>
      <text x="${p.x + 10}" y="${p.y + 19}" class="ht">Entity Configuration</text>
      ${lines(p.x + 10, p.y + 46, rows)}
      ${node.selfVerify ? badge(p.x + 10, p.y + EC_H - 28, `自己署名 ${node.selfVerify.ok ? '✓' : '✗'}`, status(node.selfVerify), node.selfVerify) : ''}
      ${node.ssVerify ? badge(p.x + 135, p.y + EC_H - 28, `上位SSの鍵 ${node.ssVerify.ok ? '✓' : '✗'}`, status(node.ssVerify)) : ''}
      ${node.taVerify ? badge(p.x + 135, p.y + EC_H - 28, `TA鍵 ${node.taVerify.ok ? '✓' : '✗'}`, status(node.taVerify)) : ''}
      ${stepNo(node.fetch, p.x + EC_W - 4, p.y + 4)}</g>`)
    if (isTa) {
      const ky = p.y + 134
      parts.push(`<g><rect x="${lx}" y="${ky}" width="${LABEL_W}" height="30" rx="6" class="key"/>
        <text x="${lx + LABEL_W / 2}" y="${ky + 20}" class="kt">🔑 事前設定の TA 公開鍵</text></g>`)
      parts.push(arrow(lx + LABEL_W, ky + 15, p.x - 2, ky + 15, status(node.taVerify), '検証', node.taVerify))
    }
    // authority_hints arrows (subordinate EC -> superior)
    for (const h of hints.get(node.id) ?? []) {
      const q = pos.get(h)
      if (!q) continue
      const ev = [...steps.keys()].find((e) => e.type === 'authority_hints' && e.entity === node.id)
      parts.push(
        arrow(p.x + 50, p.y - 2, q.x + 50, q.y + EC_H + 2, path.has(node.id) && path.has(h) ? 'ok' : 'na', 'authority_hints', ev, true)
      )
    }
  }
  // Subordinate Statements (drawn in the issuer's row)
  for (const s of sss.values()) {
    if (!pos.has(s.issuer)) continue
    const p = ssPos(s)
    const sup = pos.get(s.issuer) as { x: number; y: number }
    const sub = pos.get(s.entity)
    const st = s.fetch && !s.fetch.ok ? 'ng' : s.claims ? 'ok' : 'na'
    const rows: [string, string?][] = s.claims
      ? [
          [`iss: ${trunc(label(s.issuer), 26)}`],
          [`sub: ${trunc(label(s.entity), 26)}`],
          [`jwks (sub の鍵): kid ${kidsOf(s.claims)}`],
          [
            `metadata_policy: ${trunc(Object.keys(s.claims.metadata_policy ?? {}).join(', ') || 'なし', 24)}`,
          ],
        ]
      : [['取得失敗', 'tng'], [trunc(humanize(s.fetch?.error ?? ''), 42), 'tng']]
    parts.push(`<g><rect x="${p.x}" y="${p.y}" width="${SS_W}" height="${EC_H}" rx="8" class="card ${path.has(s.issuer) && path.has(s.entity) ? 'onp' : ''}" ${st === 'ng' ? `style="stroke:${COLORS.ng};stroke-width:2.5"` : ''}/>
      <path d="M${p.x} ${p.y + 8}a8 8 0 0 1 8 -8h${SS_W - 16}a8 8 0 0 1 8 8v20h-${SS_W}z" class="ssh"/>
      <text x="${p.x + 10}" y="${p.y + 19}" class="ht">Subordinate Statement</text>
      ${lines(p.x + 10, p.y + 46, rows)}
      ${s.verify ? badge(p.x + 10, p.y + EC_H - 28, `上位ECの鍵で署名検証 ${s.verify.ok ? '✓' : '✗'}`, status(s.verify)) : ''}
      ${stepNo(s.fetch, p.x + SS_W - 4, p.y + 4)}</g>`)
    // issuer EC jwks -> verifies SS
    parts.push(arrow(sup.x + EC_W + 2, sup.y + 84, p.x - 2, p.y + 84, status(s.verify), 'jwks', s.verify))
    // SS jwks -> verifies subordinate EC
    if (sub) {
      const ev = ecs.get(s.entity)?.ssVerify
      parts.push(arrow(p.x + 60, p.y + EC_H + 2, sub.x + EC_W - 40, sub.y - 2, status(ev), 'jwks で EC を検証', ev))
    }
  }

  // final step (metadata policy application, or the resolution error): drawn in the leaf's row
  const final = [...steps.keys()].find((e) => e.type === 'metadata' || e.type === 'error')
  const leafPos = pos.get(leafId)
  if (final && leafPos) {
    const x = leafPos.x + EC_W + 80
    const y = leafPos.y + 20
    const ok = final.type === 'metadata'
    const rows: [string, string?][] = ok
      ? [
          [`metadata_policy: ${trunc(final.policies.map((p) => label(p.issuer)).join(' → ') || 'なし', 26)}`],
          ['(TA から順にマージして Leaf に適用)'],
          [`entity types: ${trunc(Object.keys(final.resolved).join(', '), 28)}`],
        ]
      : [[trunc(humanize(final.message), 44), 'tng'], [trunc(humanize(final.message).slice(43), 44), 'tng']]
    parts.push(`<g><rect x="${x}" y="${y}" width="${SS_W}" height="${EC_H - 40}" rx="8" class="card" style="stroke:${ok ? COLORS.ok : COLORS.ng};stroke-width:2;stroke-dasharray:6 4"/>
      <text x="${x + 10}" y="${y + 24}" class="ft" fill="${ok ? COLORS.ok : COLORS.ng}">${ok ? 'Resolved Metadata' : 'Trust Chain 構築失敗'}</text>
      ${lines(x + 10, y + 50, rows)}${stepNo(final, x + SS_W - 4, y + 4)}</g>`)
    parts.push(arrow(leafPos.x + EC_W + 2, y + 64, x - 2, y + 64, ok ? 'ok' : 'ng', ok ? '適用' : '失敗', undefined))
  }

  return `<svg class="tcv-svg" viewBox="0 0 ${width} ${height}" style="max-width:${width}px" xmlns="http://www.w3.org/2000/svg">
    <defs>${Object.entries(COLORS)
      .map(
        ([k, c]) =>
          `<marker id="tcv-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${c}"/></marker>`
      )
      .join('')}</defs>
    ${parts.join('')}</svg>`
}

// ---- (B) the Trust Chain array ---------------------------------------------------------------
const chainStrip = (result: ResolvedTrustChain, label: (id: string) => string) => {
  const n = result.chain.length
  const cards = result.chain.map((jwt, i) => {
    const { header, payload } = decode(jwt)
    const kind = i === 0 ? 'Entity Configuration (Leaf)' : i === n - 1 ? 'Entity Configuration (Trust Anchor)' : 'Subordinate Statement'
    const cls = i === 0 || i === n - 1 ? 'ec' : 'ss'
    const exp = payload?.exp ? new Date(payload.exp * 1000).toLocaleString('ja-JP') : '-'
    const card = `<div class="cc ${cls}"><div class="cch"><b>[${i}]</b> ${esc(kind)}</div>
      <div class="ccb"><div><span>iss</span> ${esc(label(String(payload?.iss)))}</div>
      <div><span>sub</span> ${esc(label(String(payload?.sub)))}</div>
      <div><span>署名 kid</span> <code>${esc(shortKid(header?.kid))}</code></div>
      <div><span>jwks</span> <code>${esc(kidsOf(payload))}</code></div>
      <div><span>exp</span> ${esc(exp)}</div>
      <details><summary>デコード</summary><pre>${esc(JSON.stringify({ header, payload }, null, 2))}</pre></details></div></div>`
    const next =
      i < n - 1
        ? `<div class="ca"><div>→</div><div class="cal">[${i}] の署名鍵 <code>${esc(shortKid(header?.kid))}</code><br>∈ [${i + 1}].jwks</div></div>`
        : `<div class="ca"><div>←</div><div class="cal">[${i}] の署名鍵<br>∈ 事前設定の TA 鍵</div></div>`
    return card + next
  })
  return `<div class="strip">${cards.join('')}</div>
    <p class="mut">Trust Chain の有効期限 = 全ステートメントの exp の最小値: ${esc(new Date(result.exp * 1000).toLocaleString('ja-JP'))}</p>`
}

// ---- (C) steps -------------------------------------------------------------------------------
const stepList = (model: Model, rawLabel: (id?: string) => string) => {
  const label = (id?: string) => esc(rawLabel(id))
  const items: string[] = []
  for (const [e, n] of model.steps) {
    let text = ''
    let st: 'ok' | 'ng' | 'na' = 'na'
    switch (e.type) {
      case 'fetch':
        st = e.ok ? 'ok' : 'ng'
        text =
          e.kind === 'ec'
            ? `${label(e.entity)} の Entity Configuration を取得 <code>GET ${escMsg(e.url)}</code>`
            : `${label(e.issuer as string)} から ${label(e.entity)} についての Subordinate Statement を取得 <code>GET ${escMsg(e.url)}</code>`
        break
      case 'authority_hints':
        text = `${label(e.entity)} の authority_hints を確認 → ${e.hints.length ? e.hints.map((h) => label(h)).join(', ') : '(なし)'}`
        break
      case 'verify':
        st = e.ok ? 'ok' : 'ng'
        text = {
          self: `EC(${label(e.entity)}) の自己署名を EC 内の jwks で検証 (kid ${esc(shortKid(e.kid))})`,
          superior_ec: `SS(${label(e.issuer as string)} → ${label(e.entity)}) の署名を ${label(e.issuer as string)} の EC の jwks で検証 (kid ${esc(shortKid(e.kid))})`,
          subordinate_statement: `EC(${label(e.entity)}) の署名鍵が SS(${label(e.keySourceEntity as string)} → ${label(e.entity)}) の jwks に含まれることを検証 (kid ${esc(shortKid(e.kid))})`,
          trust_anchor_config: `Trust Anchor ${label(e.entity)} の EC を事前設定された TA 公開鍵で検証 (kid ${esc(shortKid(e.kid))})`,
        }[e.keySource]
        break
      case 'metadata':
        st = 'ok'
        text = `metadata_policy (${e.policies.map((p) => label(p.issuer)).join(' → ') || 'なし'}) をマージして Leaf のメタデータに適用 → Resolved Metadata`
        break
      case 'error':
        st = 'ng'
        text = `Trust Chain を構築できませんでした: ${escMsg(e.message)}`
        break
    }
    const err = (e.type === 'fetch' || e.type === 'verify') && e.error ? `<div class="se">${escMsg(e.error)}</div>` : ''
    items.push(`<li class="${st}"><span class="sn2">${n}</span><span class="mk">${st === 'ok' ? '✓' : st === 'ng' ? '✗' : '→'}</span><div>${text}${err}</div></li>`)
  }
  return `<ol class="steps">${items.join('')}</ol>`
}

// ---- (D) metadata policy ---------------------------------------------------------------------
const show = (v: unknown) => (v === undefined ? '' : trunc(JSON.stringify(v), 110))
const metadataTable = (m: MetadataStage, label: (id: string) => string) => {
  // policies for entity types the leaf does not have are not applied
  const types = [...new Set([...Object.keys(m.leaf), ...Object.keys(m.resolved)])]
  const rows: string[] = []
  for (const type of types) {
    const leafT = m.leaf[type] ?? {}
    const supT = m.superiorMetadata?.metadata[type] ?? {}
    const resT = m.resolved[type] ?? {}
    const params = [...new Set([...Object.keys(leafT), ...Object.keys(supT), ...Object.keys(resT), ...Object.keys(m.merged[type] ?? {})])]
    rows.push(`<tr class="ty"><th colspan="4">${esc(type)}</th></tr>`)
    for (const p of params) {
      const before = p in supT ? supT[p] : leafT[p]
      const ops = m.policies
        .filter((x) => x.policy[type]?.[p])
        .map((x) => `<div><span class="by">${esc(label(x.issuer))}</span> <code>${esc(show(x.policy[type][p]))}</code></div>`)
        .join('')
      if (before === undefined && resT[p] === undefined) continue
      const changed = JSON.stringify(before) !== JSON.stringify(resT[p])
      const note = p in supT ? '<span class="by">上位SSの metadata で上書き</span><br>' : ''
      rows.push(`<tr class="${changed ? 'chg' : ''}"><td><code>${esc(p)}</code></td>
        <td title="${esc(JSON.stringify(before))}">${note}${esc(show(before))}</td><td>${ops}</td>
        <td title="${esc(JSON.stringify(resT[p]))}">${p in resT ? esc(show(resT[p])) : '<span class="by">(削除)</span>'}${changed ? ' <b class="cm">変更</b>' : ''}</td></tr>`)
    }
  }
  return `<table class="mt"><thead><tr><th>パラメータ</th><th>Leaf の EC (適用前)</th><th>metadata_policy (TA → 下位の順にマージ)</th><th>Resolved Metadata</th></tr></thead><tbody>${rows.join('')}</tbody></table>`
}

export const TRUST_CHAIN_VIEW_CSS = `
.tcv-svg{width:100%;height:auto;display:block;font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}
.tcv-svg .ent{fill:#eef4f8;stroke:#9fb6c6;stroke-width:1.5}.tcv-svg .ent.onp{fill:#dcebf5;stroke:#155e86;stroke-width:2.5}.tcv-svg .ent.ta{fill:#fff4d6;stroke:#bf8700}
.tcv-svg .er{font-size:13px;fill:#57606a;text-anchor:middle}.tcv-svg .en{font-size:18px;font-weight:700;fill:#1f2328;text-anchor:middle}.tcv-svg .ei{font-size:11px;fill:#57606a;text-anchor:middle}
.tcv-svg .card{fill:#fff;stroke:#d0d7de;stroke-width:1.5}.tcv-svg .card.onp{stroke:#155e86;stroke-width:2.5}
.tcv-svg .ech{fill:#155e86}.tcv-svg .ssh{fill:#8250df}.tcv-svg .ht{fill:#fff;font-size:13px;font-weight:700}.tcv-svg .hs{fill:#dbe9f2;font-size:10px;text-anchor:end}
.tcv-svg .tx{font-size:12.5px;fill:#1f2328}.tcv-svg .tng{font-size:12px;fill:#cf222e}.tcv-svg .tmut{font-size:12px;fill:#8c959f}
.tcv-svg .bd{font-size:11.5px;fill:#fff;font-weight:700}.tcv-svg .al{font-size:11.5px;text-anchor:middle;font-weight:700}
.tcv-svg .sn{fill:#1f2328}.tcv-svg .ft{font-size:15px;font-weight:700}.tcv-svg .snt{fill:#fff;font-size:11px;text-anchor:middle;font-weight:700}
.tcv-svg .key{fill:#fff4d6;stroke:#bf8700}.tcv-svg .kt{font-size:12px;text-anchor:middle;fill:#7d4e00}
.tcv-legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:#57606a;margin:6px 0 0}
.tcv-legend i{display:inline-block;width:14px;height:10px;border-radius:2px;margin-right:4px;vertical-align:middle}
.strip{display:flex;align-items:stretch;gap:0;overflow-x:auto;padding:4px 0}
.cc{flex:none;width:205px;border:1.5px solid #d0d7de;border-radius:8px;background:#fff;font-size:12.5px;overflow:hidden}
.cc .cch{color:#fff;padding:6px 8px;font-size:12.5px}.cc.ec .cch{background:#155e86}.cc.ss .cch{background:#8250df}
.cc .ccb{padding:6px 8px;line-height:1.7}.cc .ccb span{display:inline-block;min-width:58px;color:#57606a}
.cc pre{max-height:260px;overflow:auto;font-size:11px}
.ca{flex:none;width:100px;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#57606a;font-size:11px;text-align:center}
.ca>div:first-child{font-size:26px;color:#1a7f37}
ol.steps{list-style:none;margin:0;padding:0}ol.steps li{display:flex;gap:8px;align-items:flex-start;padding:6px 0;border-top:1px solid #eef1f4;font-size:13px}
ol.steps .sn2{flex:none;width:22px;height:22px;border-radius:50%;background:#1f2328;color:#fff;font-size:11px;display:flex;align-items:center;justify-content:center;font-weight:700}
ol.steps .mk{flex:none;width:14px;font-weight:700}ol.steps li.ok .mk{color:#1a7f37}ol.steps li.ng .mk{color:#cf222e}ol.steps li.ng{background:#fff5f5}
ol.steps code{font-size:11px;word-break:break-all}.se{color:#cf222e;font-size:12px}
table.mt{font-size:12.5px}table.mt tr.ty th{background:#eef4f8}table.mt tr.chg td{background:#fff8c5}table.mt .by{color:#57606a;font-size:11px}
table.mt .cm{color:#9a6700;font-size:11px}table.mt code{font-size:11px}
`

/** HTML fragment (sections) visualising a traced trust chain resolution. Include TRUST_CHAIN_VIEW_CSS. */
export const trustChainVisualHtml = (
  entityId: string,
  { trace, result, error }: TraceResult,
  names: Record<string, string> = {}
) => {
  const label = (id?: string) => (id ? (names[id] ?? id.replace(/^https?:\/\//, '')) : '?')
  const model = buildModel(entityId, trace)
  const path = new Set(result?.path ?? [])
  const metadata = trace.find((e): e is MetadataStage => e.type === 'metadata')
  const head = result
    ? `<h3 class="ok">✓ Trust Chain 検証成功</h3><p>${result.path.map((p) => `<code>${esc(label(p))}</code>`).join(' → ')} (Trust Anchor: ${esc(label(result.trustAnchor))})</p>`
    : `<h3 class="ng">✗ Trust Chain 検証失敗</h3><pre>${escMsg(error ?? '')}</pre>`
  return `<section>${head}
    <h4>① フェデレーション上の解決経路</h4>
    <p class="mut">Leaf から authority_hints をたどって上位エンティティの Entity Configuration を取得し、上位の fetch エンドポイントから Subordinate Statement を取得します。
    各ステートメントは「1 つ上の発行者の jwks」で署名検証され、最上位は事前設定された Trust Anchor の公開鍵で検証されます。番号は下の解決ステップに対応します。</p>
    ${diagramSvg(model, entityId, path, label)}
    <div class="tcv-legend"><span><i style="background:#155e86"></i>Entity Configuration (自己署名)</span><span><i style="background:#8250df"></i>Subordinate Statement (上位が発行)</span>
    <span><i style="background:#1a7f37"></i>検証成功</span><span><i style="background:#cf222e"></i>検証失敗</span><span><i style="background:#8c959f"></i>未実施 / 経路外</span><span>破線: authority_hints</span></div></section>
    ${result ? `<section><h4>② Trust Chain (JWT 配列: [Leaf EC, SS…, TA EC])</h4>${chainStrip(result, label)}</section>` : ''}
    <section><h4>③ 解決ステップ</h4>${stepList(model, label)}</section>
    ${metadata ? `<section><h4>④ metadata_policy の適用</h4>${metadataTable(metadata, label)}</section>` : ''}`
}
