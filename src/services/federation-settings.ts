import type { Context, Hono } from 'hono'
import { ENTITY, ENTITY_LABELS } from '../config.js'
import { jwksOf } from '../common/keys.js'
import { emit } from '../common/events.js'
import { esc } from '../common/html.js'
import {
  type FederationEntity,
  type MetadataPolicy,
  type SubordinateRegistration,
  ephemeralKey,
} from '../federation/entity.js'
import { type TrustAnchorConfig, clearTrustChainCache, resolveTrustChain } from '../federation/resolver.js'

/**
 * Federation settings (demo): edit trust relationships at runtime to test broken Trust Chains.
 * Changes are in memory only (a restart restores the initial federation).
 */

type Preset = { id: string; title: string; expect: string; apply: () => Promise<void> }

const label = (id: string) => ENTITY_LABELS[id] ?? id

export const createFederationSettings = (opts: { members: FederationEntity[]; anchors: TrustAnchorConfig[] }) => {
  const byId = new Map(opts.members.map((e) => [e.entityId, e]))
  const authorities = opts.members.filter((e) => e.isAuthority)
  const get = (id: string) => {
    const e = byId.get(id)
    if (!e) throw new Error(`unknown entity ${id}`)
    return e
  }
  const reg = (sup: string, sub: string) => {
    const r = get(sup).subordinates?.get(sub)
    if (!r) throw new Error(`${sub} is not registered at ${sup}`)
    return r
  }

  // ---- initial state (for reset / change highlighting) -----------------------------------------
  const initialHints = new Map(opts.members.map((e) => [e.entityId, [...(e.authorityHints ?? [])]]))
  const initialRegs = new Map(
    authorities.map((a) => [a.entityId, new Map([...(a.subordinates ?? new Map()).entries()].map(([k, v]) => [k, structuredClone(v)]))])
  )
  const isInitialReg = (sup: string, sub: string) => initialRegs.get(sup)?.has(sub) ?? false
  const regChanged = (sup: string, r: SubordinateRegistration) => {
    const init = initialRegs.get(sup)?.get(r.entityId)
    return !init || !!r.disabled || !!r.wrongJwks || !!r.expired || JSON.stringify(init.metadataPolicy) !== JSON.stringify(r.metadataPolicy)
  }
  const hintsChanged = (e: FederationEntity) => JSON.stringify(initialHints.get(e.entityId)) !== JSON.stringify(e.authorityHints ?? [])
  const entityChanged = (e: FederationEntity) => hintsChanged(e) || !!e.faults.ecDisabled || !!e.faults.rotatedKey

  const reset = () => {
    for (const e of opts.members) {
      e.authorityHints = [...(initialHints.get(e.entityId) ?? [])]
      e.faults = {}
    }
    for (const a of authorities) {
      a.subordinates?.clear()
      for (const [k, v] of initialRegs.get(a.entityId) ?? []) a.subordinates?.set(k, structuredClone(v))
    }
  }

  const changed = () => {
    clearTrustChainCache()
  }

  // ---- operations --------------------------------------------------------------------------------
  const ops: Record<string, (f: Record<string, string | string[]>) => Promise<string>> = {
    async toggle_registration(f) {
      const r = reg(String(f.sup), String(f.sub))
      r.disabled = !r.disabled
      return `${label(String(f.sup))} が ${label(r.entityId)} の登録を${r.disabled ? '停止 (fetch が 404)' : '再開'}`
    },
    async toggle_wrong_jwks(f) {
      const r = reg(String(f.sup), String(f.sub))
      r.wrongJwks = !r.wrongJwks
      return `${label(String(f.sup))} → ${label(r.entityId)} の Subordinate Statement の jwks を${r.wrongJwks ? '不正な鍵に変更' : '正しい鍵に戻す'}`
    },
    async toggle_expired(f) {
      const r = reg(String(f.sup), String(f.sub))
      r.expired = !r.expired
      return `${label(String(f.sup))} → ${label(r.entityId)} の Subordinate Statement を${r.expired ? '期限切れにする' : '有効期限内に戻す'}`
    },
    async set_policy(f) {
      const r = reg(String(f.sup), String(f.sub))
      const text = String(f.policy ?? '').trim()
      if (!text) delete r.metadataPolicy
      else {
        const parsed = JSON.parse(text) as MetadataPolicy
        if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) throw new Error('metadata_policy must be a JSON object')
        r.metadataPolicy = parsed
      }
      return `${label(String(f.sup))} → ${label(r.entityId)} の metadata_policy を変更`
    },
    async add_registration(f) {
      const sup = get(String(f.sup))
      const sub = get(String(f.sub))
      if (!sup.isAuthority) throw new Error(`${label(sup.entityId)} is not an authority`)
      if (sup.entityId === sub.entityId) throw new Error('cannot register itself')
      if (sup.subordinates?.has(sub.entityId)) throw new Error('already registered')
      sup.register({ entityId: sub.entityId, jwks: jwksOf(sub.federationKey), entityTypes: Object.keys(sub.metadata) })
      return `${label(sup.entityId)} に ${label(sub.entityId)} を下位として登録`
    },
    async delete_registration(f) {
      const sup = get(String(f.sup))
      sup.subordinates?.delete(String(f.sub))
      return `${label(sup.entityId)} から ${label(String(f.sub))} の登録を削除`
    },
    async set_hints(f) {
      const e = get(String(f.entity))
      const hints = ([] as string[]).concat(f.hints ?? []).filter((h) => byId.get(h)?.isAuthority && h !== e.entityId)
      e.authorityHints = hints
      return `${label(e.entityId)} の authority_hints を [${hints.map(label).join(', ') || 'なし'}] に変更`
    },
    async toggle_ec(f) {
      const e = get(String(f.entity))
      e.faults.ecDisabled = !e.faults.ecDisabled
      return `${label(e.entityId)} の Entity Configuration を${e.faults.ecDisabled ? '非公開に (404)' : '公開に戻す'}`
    },
    async toggle_rotate(f) {
      const e = get(String(f.entity))
      e.faults.rotatedKey = e.faults.rotatedKey ? undefined : await ephemeralKey()
      return e.faults.rotatedKey
        ? `${label(e.entityId)} が Federation Entity Key をローテーション (上位${e.authorityHints?.length ? 'の Subordinate Statement' : ' (Trust Anchor 設定)'} は旧鍵のまま)`
        : `${label(e.entityId)} の Federation Entity Key を元に戻す`
    },
    async reset() {
      reset()
      return 'フェデレーション設定を初期状態に戻しました'
    },
    async preset(f) {
      const p = presets.find((x) => x.id === f.id)
      if (!p) throw new Error('unknown preset')
      await p.apply()
      return `プリセット: ${p.title}`
    },
  }

  const presets: Preset[] = [
    {
      id: 'unregister-issuer',
      title: 'NII が学認Issuer の登録を停止',
      expect: 'NII の fetch が 404 になり、学認Issuer の Trust Chain が切れる。Wallet は Credential Offer を拒否、Verifier は提示されたクレデンシャルの Issuer を信頼できず拒否、機関IdP も Issuer のログインを拒否',
      apply: async () => {
        reg(ENTITY.nii, ENTITY.issuer).disabled = true
      },
    },
    {
      id: 'rotate-wallet-provider',
      title: 'Wallet Provider の鍵ローテーション (NII に未届け)',
      expect: 'Wallet Provider の EC は新しい鍵で署名されるが、NII の Subordinate Statement は旧鍵のまま。Wallet の登録、Issuer の Token 発行、Verifier の Attestation 検証が失敗',
      apply: async () => {
        get(ENTITY.walletProvider).faults.rotatedKey = await ephemeralKey()
      },
    },
    {
      id: 'wrong-jwks-status-list',
      title: 'NII → Status List の Subordinate Statement に誤った鍵',
      expect: 'Status List の EC 署名鍵が上位の Subordinate Statement の jwks に含まれず検証失敗。Verifier の失効確認と Wallet Attestation の状態確認が失敗し、提示・発行が拒否される',
      apply: async () => {
        reg(ENTITY.nii, ENTITY.statusList).wrongJwks = true
      },
    },
    {
      id: 'expire-nii',
      title: 'eduGAIN → NII の Subordinate Statement が期限切れ',
      expect: 'NII 配下 (学認) の全エンティティの Trust Chain が無効になる。I2 配下の InCommon SP 自身の Trust Chain は有効なまま (ただし機関IdP が信頼できないのでログイン不可)',
      apply: async () => {
        reg(ENTITY.trustAnchor, ENTITY.nii).expired = true
      },
    },
    {
      id: 'policy-violation-idp',
      title: 'NII が機関IdP に満たせない metadata_policy を課す',
      expect: 'op_policy_uri を essential にするが機関IdP は宣言していないため、Trust Chain の署名は正しくても metadata_policy の適用で失敗。学認SP / InCommon SP / Issuer のログインが失敗',
      apply: async () => {
        const r = reg(ENTITY.nii, ENTITY.idp)
        r.metadataPolicy = { ...(r.metadataPolicy ?? {}), openid_provider: { op_policy_uri: { essential: true } } }
      },
    },
    {
      id: 'issuer-hints-i2',
      title: '学認Issuer の authority_hints を I2 に変更 (I2 は未登録)',
      expect: 'I2 の fetch が 404 になり Trust Chain が切れる。続けて「I2 に学認Issuer を登録」すると I2 経由で解決できるようになり、機関IdP は他フェデレーション扱い (最小限の属性) で Issuer にログインさせる',
      apply: async () => {
        get(ENTITY.issuer).authorityHints = [ENTITY.i2]
      },
    },
    {
      id: 'rotate-ta',
      title: 'eduGAIN (Trust Anchor) の鍵ローテーション (各エンティティの TA 設定は旧鍵のまま)',
      expect: 'Trust Anchor の EC が事前設定の公開鍵で検証できず、全ての Trust Chain が無効になる',
      apply: async () => {
        get(ENTITY.trustAnchor).faults.rotatedKey = await ephemeralKey()
      },
    },
  ]

  // ---- page ------------------------------------------------------------------------------------
  const btn = (op: string, fields: Record<string, string>, text: string, cls = '') =>
    `<form method="post" action="/federation" class="inl"><input type="hidden" name="op" value="${op}">${Object.entries(fields)
      .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
      .join('')}<button class="${cls}">${esc(text)}</button></form>`
  const vis = (id: string) => `<a href="/trust-chain?entity=${encodeURIComponent(id)}" target="_blank">図</a>`

  const impact = async () => {
    const targets = [...opts.members.filter((e) => !opts.anchors.some((a) => a.entityId === e.entityId)).map((e) => e.entityId)]
    const results = await Promise.all(
      targets.map(async (id) => {
        try {
          const chain = await resolveTrustChain(id, opts.anchors, { noCache: true })
          return { id, ok: true, detail: chain.path.map(label).join(' → ') }
        } catch (e) {
          return { id, ok: false, detail: (e as Error).message.replace(/^no valid trust chain for \S+: /, '') }
        }
      })
    )
    return `<table class="imp">${results
      .map(
        (r) => `<tr class="${r.ok ? '' : 'bad'}"><td><b>${esc(label(r.id))}</b></td><td class="${r.ok ? 'ok' : 'ng'}">${r.ok ? '✓ 有効' : '✗ 無効'}</td>
        <td class="mut">${esc(r.detail)}</td><td>${vis(r.id)}</td></tr>`
      )
      .join('')}</table>`
  }

  const authorityTables = () =>
    authorities
      .map((a) => {
        const rows = [...(a.subordinates?.values() ?? [])]
          .map((r) => {
            const policy = r.metadataPolicy ? JSON.stringify(r.metadataPolicy, null, 2) : ''
            const f = { sup: a.entityId, sub: r.entityId }
            return `<tr class="${regChanged(a.entityId, r) ? 'chg' : ''}"><td><b>${esc(label(r.entityId))}</b><br><span class="mut">${esc(r.entityId)}</span>${
              isInitialReg(a.entityId, r.entityId) ? '' : ' <span class="tag">追加</span>'
            }</td>
            <td>${btn('toggle_registration', f, r.disabled ? '停止中 → 再開' : '登録中 → 停止', r.disabled ? 'bad' : '')}</td>
            <td>${btn('toggle_wrong_jwks', f, r.wrongJwks ? '不正な鍵 → 戻す' : '正しい鍵 → 不正に', r.wrongJwks ? 'bad' : '')}</td>
            <td>${btn('toggle_expired', f, r.expired ? '期限切れ → 戻す' : '有効 → 期限切れに', r.expired ? 'bad' : '')}</td>
            <td><details><summary>${r.metadataPolicy ? esc(Object.keys(r.metadataPolicy).join(', ')) : 'なし'}</summary>
              <form method="post" action="/federation"><input type="hidden" name="op" value="set_policy"><input type="hidden" name="sup" value="${esc(a.entityId)}"><input type="hidden" name="sub" value="${esc(r.entityId)}">
              <textarea name="policy" rows="7" placeholder='{"openid_provider": {"op_policy_uri": {"essential": true}}}'>${esc(policy)}</textarea><br><button>保存</button></form></details></td>
            <td>${isInitialReg(a.entityId, r.entityId) ? '' : btn('delete_registration', f, '削除', 'bad')} ${vis(r.entityId)}</td></tr>`
          })
          .join('')
        const candidates = opts.members.filter((e) => e.entityId !== a.entityId && !a.subordinates?.has(e.entityId))
        return `<section><h3>${esc(label(a.entityId))} が発行する Subordinate Statement</h3>
          <table class="cfg"><thead><tr><th>下位エンティティ</th><th>登録 (fetch)</th><th>jwks</th><th>有効期限</th><th>metadata_policy</th><th></th></tr></thead><tbody>${rows}</tbody></table>
          ${candidates.length ? `<form method="post" action="/federation" class="add"><input type="hidden" name="op" value="add_registration"><input type="hidden" name="sup" value="${esc(a.entityId)}">
          下位を追加: <select name="sub">${candidates.map((c) => `<option value="${esc(c.entityId)}">${esc(label(c.entityId))}</option>`).join('')}</select> <button>登録</button></form>` : ''}</section>`
      })
      .join('')

  const entityTable = () => `<table class="cfg"><thead><tr><th>エンティティ</th><th>authority_hints</th><th>Entity Configuration</th><th>Federation Entity Key</th><th></th></tr></thead><tbody>${opts.members
    .map((e) => {
      const hintBoxes = authorities
        .filter((a) => a.entityId !== e.entityId)
        .map(
          (a) => `<label><input type="checkbox" name="hints" value="${esc(a.entityId)}" ${e.authorityHints?.includes(a.entityId) ? 'checked' : ''}> ${esc(label(a.entityId))}</label>`
        )
        .join(' ')
      return `<tr class="${entityChanged(e) ? 'chg' : ''}"><td><b>${esc(label(e.entityId))}</b><br><span class="mut">${esc(e.entityId)}</span></td>
        <td><form method="post" action="/federation" class="inl"><input type="hidden" name="op" value="set_hints"><input type="hidden" name="entity" value="${esc(e.entityId)}">${hintBoxes} <button>変更</button></form></td>
        <td>${btn('toggle_ec', { entity: e.entityId }, e.faults.ecDisabled ? '非公開 → 公開' : '公開中 → 非公開に', e.faults.ecDisabled ? 'bad' : '')}</td>
        <td>${btn('toggle_rotate', { entity: e.entityId }, e.faults.rotatedKey ? 'ローテーション済 → 戻す' : '鍵をローテーション', e.faults.rotatedKey ? 'bad' : '')}</td>
        <td>${vis(e.entityId)}</td></tr>`
    })
    .join('')}</tbody></table>`

  const css = `main{max-width:1320px}
  form.inl{display:inline}form.inl button,.cfg button{padding:4px 10px;font-size:12.5px}
  button.bad{background:#cf222e}.cfg tr.chg td{background:#fff8c5}.tag{background:#9a6700;color:#fff;border-radius:999px;font-size:11px;padding:1px 6px}
  .cfg textarea{width:100%;min-width:300px;font-family:ui-monospace,monospace;font-size:12px}
  .cfg label{white-space:nowrap;font-size:13px;margin-right:6px}
  .presets{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}
  .preset{border:1px solid #d0d7de;border-radius:8px;padding:10px;display:flex;flex-direction:column;gap:6px}.preset .t{font-weight:700}
  .preset .e{color:#57606a;font-size:12.5px;flex:1}.imp td{padding:4px 6px}.imp tr.bad td{background:#fff5f5}
  .flash{border-left:4px solid #155e86}.flash.err{border-left-color:#cf222e}form.add{margin-top:8px}`

  const pageBody = async (flash?: { ok: boolean; message: string }) => `<style>${css}</style>
    ${flash ? `<section class="flash ${flash.ok ? '' : 'err'}"><b class="${flash.ok ? 'ok' : 'ng'}">${flash.ok ? '✓' : '✗'}</b> ${esc(flash.message)}</section>` : ''}
    <section><h3>フェデレーション設定 (信頼関係の編集)</h3>
    <p class="mut">Trust Anchor / Intermediate が発行する Subordinate Statement と、各エンティティの Entity Configuration を実行中に変更して、Trust Chain が壊れたときの挙動を試せます。
    変更は即時に反映されます (Trust Chain のキャッシュも破棄)。変更はメモリ上のみで、サーバーを再起動すると元に戻ります。黄色の行が初期状態から変更されている箇所です。</p>
    ${btn('reset', {}, 'すべて初期状態に戻す')}</section>
    <section><h3>現在の Trust Chain の状態</h3>${await impact()}</section>
    <section><h3>壊し方のプリセット</h3><p class="mut">プリセットは現在の設定に重ねて適用されます。試した後は「すべて初期状態に戻す」で元に戻してください。</p>
    <div class="presets">${presets
      .map((p) => `<div class="preset"><div class="t">${esc(p.title)}</div><div class="e">${esc(p.expect)}</div><div>${btn('preset', { id: p.id }, '適用')}</div></div>`)
      .join('')}</div></section>
    ${authorityTables()}
    <section><h3>各エンティティの Entity Configuration</h3>
    <p class="mut">authority_hints の変更、Entity Configuration の非公開、Federation Entity Key のローテーション (新しい鍵で署名・公開するが、上位の Subordinate Statement や Trust Anchor の事前設定は旧鍵のまま) ができます。</p>
    ${entityTable()}</section>`

  /** Mounts GET/POST /federation on the demo console. */
  const mount = (app: Hono, render: (c: Context, body: string) => Response | Promise<Response>) => {
    app.get('/federation', async (c) => {
      const msg = c.req.query('msg')
      const flash = msg ? { ok: c.req.query('ok') !== '0', message: msg } : undefined
      return render(c, await pageBody(flash))
    })
    app.post('/federation', async (c) => {
      const form = (await c.req.parseBody({ all: true })) as Record<string, string | string[]>
      const op = ops[String(form.op)]
      let ok = true
      let message: string
      try {
        if (!op) throw new Error(`unknown operation ${String(form.op)}`)
        message = await op(form)
        changed()
        emit('Federation 設定', 'info', message)
      } catch (e) {
        ok = false
        message = (e as Error).message
      }
      return c.redirect(`/federation?ok=${ok ? 1 : 0}&msg=${encodeURIComponent(message)}`, 303)
    })
  }

  return { mount, reset }
}
