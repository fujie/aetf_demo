import type { Context, Hono } from 'hono'
import { ENTITY } from '../config.js'
import { jwksOf } from '../common/keys.js'
import { emit } from '../common/events.js'
import { esc } from '../common/html.js'
import { type Bi, type Lang, pick, t } from '../common/i18n.js'
import { humanize, nameOf } from '../common/names.js'
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

type Preset = { id: string; title: Bi; expect: Bi; apply: () => Promise<void> }

const label = (id: string) => nameOf(id)
/** Builds a message in both languages; `n` gives entity display names in that language. */
const msg = (f: (lang: Lang, n: (id: string) => string) => string): Bi => ({
  ja: f('ja', (id) => nameOf(id, 'ja')),
  en: f('en', (id) => nameOf(id, 'en')),
})

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
  const ops: Record<string, (f: Record<string, string | string[]>) => Promise<Bi>> = {
    async toggle_registration(f) {
      const r = reg(String(f.sup), String(f.sub))
      r.disabled = !r.disabled
      return msg((l, n) =>
        l === 'ja'
          ? `${n(String(f.sup))} が ${n(r.entityId)} の登録を${r.disabled ? '停止 (fetch が 404)' : '再開'}`
          : `${n(String(f.sup))} ${r.disabled ? 'suspended the registration of' : 'resumed the registration of'} ${n(r.entityId)}${r.disabled ? ' (fetch returns 404)' : ''}`
      )
    },
    async toggle_wrong_jwks(f) {
      const r = reg(String(f.sup), String(f.sub))
      r.wrongJwks = !r.wrongJwks
      return msg((l, n) =>
        l === 'ja'
          ? `${n(String(f.sup))} → ${n(r.entityId)} の Subordinate Statement の jwks を${r.wrongJwks ? '不正な鍵に変更' : '正しい鍵に戻す'}`
          : `jwks of the Subordinate Statement ${n(String(f.sup))} → ${n(r.entityId)} ${r.wrongJwks ? 'set to a wrong key' : 'restored to the correct key'}`
      )
    },
    async toggle_expired(f) {
      const r = reg(String(f.sup), String(f.sub))
      r.expired = !r.expired
      return msg((l, n) =>
        l === 'ja'
          ? `${n(String(f.sup))} → ${n(r.entityId)} の Subordinate Statement を${r.expired ? '期限切れにする' : '有効期限内に戻す'}`
          : `Subordinate Statement ${n(String(f.sup))} → ${n(r.entityId)} ${r.expired ? 'made expired' : 'made valid again'}`
      )
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
      return msg((l, n) =>
        l === 'ja'
          ? `${n(String(f.sup))} → ${n(r.entityId)} の metadata_policy を変更`
          : `Changed the metadata_policy ${n(String(f.sup))} → ${n(r.entityId)}`
      )
    },
    async add_registration(f) {
      const sup = get(String(f.sup))
      const sub = get(String(f.sub))
      if (!sup.isAuthority) throw new Error(`${label(sup.entityId)} is not an authority`)
      if (sup.entityId === sub.entityId) throw new Error('cannot register itself')
      if (sup.subordinates?.has(sub.entityId)) throw new Error('already registered')
      sup.register({ entityId: sub.entityId, jwks: jwksOf(sub.federationKey), entityTypes: Object.keys(sub.metadata) })
      return msg((l, n) =>
        l === 'ja' ? `${n(sup.entityId)} に ${n(sub.entityId)} を下位として登録` : `Registered ${n(sub.entityId)} as a subordinate of ${n(sup.entityId)}`
      )
    },
    async delete_registration(f) {
      const sup = get(String(f.sup))
      sup.subordinates?.delete(String(f.sub))
      return msg((l, n) =>
        l === 'ja' ? `${n(sup.entityId)} から ${n(String(f.sub))} の登録を削除` : `Removed ${n(String(f.sub))} from the subordinates of ${n(sup.entityId)}`
      )
    },
    async set_hints(f) {
      const e = get(String(f.entity))
      const hints = ([] as string[]).concat(f.hints ?? []).filter((h) => byId.get(h)?.isAuthority && h !== e.entityId)
      e.authorityHints = hints
      return msg((l, n) =>
        l === 'ja'
          ? `${n(e.entityId)} の authority_hints を [${hints.map(n).join(', ') || 'なし'}] に変更`
          : `Changed the authority_hints of ${n(e.entityId)} to [${hints.map(n).join(', ') || 'none'}]`
      )
    },
    async toggle_ec(f) {
      const e = get(String(f.entity))
      e.faults.ecDisabled = !e.faults.ecDisabled
      return msg((l, n) =>
        l === 'ja'
          ? `${n(e.entityId)} の Entity Configuration を${e.faults.ecDisabled ? '非公開に (404)' : '公開に戻す'}`
          : `Entity Configuration of ${n(e.entityId)} ${e.faults.ecDisabled ? 'unpublished (404)' : 'published again'}`
      )
    },
    async toggle_rotate(f) {
      const e = get(String(f.entity))
      e.faults.rotatedKey = e.faults.rotatedKey ? undefined : await ephemeralKey()
      const rotated = !!e.faults.rotatedKey
      const hasSuperior = !!e.authorityHints?.length
      return msg((l, n) =>
        l === 'ja'
          ? rotated
            ? `${n(e.entityId)} が Federation Entity Key をローテーション (上位${hasSuperior ? 'の Subordinate Statement' : ' (Trust Anchor 設定)'} は旧鍵のまま)`
            : `${n(e.entityId)} の Federation Entity Key を元に戻す`
          : rotated
            ? `${n(e.entityId)} rotated its Federation Entity Key (${hasSuperior ? 'the superior\'s Subordinate Statement' : 'the Trust Anchor configuration'} still has the old key)`
            : `Restored the Federation Entity Key of ${n(e.entityId)}`
      )
    },
    async reset() {
      reset()
      return { ja: 'フェデレーション設定を初期状態に戻しました', en: 'Federation settings restored to the initial state' }
    },
    async preset(f) {
      const p = presets.find((x) => x.id === f.id)
      if (!p) throw new Error('unknown preset')
      await p.apply()
      return { ja: `プリセット: ${p.title.ja}`, en: `Preset: ${p.title.en}` }
    },
  }

  const presets: Preset[] = [
    {
      id: 'unregister-issuer',
      title: { ja: 'NII が学認Issuer の登録を停止', en: 'NII suspends the registration of the GakuNin Issuer' },
      expect: {
        ja: 'NII の fetch が 404 になり、学認Issuer の Trust Chain が切れる。Wallet は Credential Offer を拒否、Verifier は提示されたクレデンシャルの Issuer を信頼できず拒否、機関IdP も Issuer のログインを拒否',
        en: "NII's fetch returns 404 and the GakuNin Issuer's Trust Chain breaks. The wallet rejects the Credential Offer, the Verifier cannot trust the issuer of presented credentials, and the Institution IdP refuses the Issuer's login",
      },
      apply: async () => {
        reg(ENTITY.nii, ENTITY.issuer).disabled = true
      },
    },
    {
      id: 'rotate-wallet-provider',
      title: { ja: 'Wallet Provider の鍵ローテーション (NII に未届け)', en: 'Wallet Provider key rotation (not reported to NII)' },
      expect: {
        ja: 'Wallet Provider の EC は新しい鍵で署名されるが、NII の Subordinate Statement は旧鍵のまま。Wallet の登録、Issuer の Token 発行、Verifier の Attestation 検証が失敗',
        en: "The Wallet Provider's EC is signed with a new key but NII's Subordinate Statement still has the old one. Wallet registration, the Issuer's token issuance and the Verifier's attestation check fail",
      },
      apply: async () => {
        get(ENTITY.walletProvider).faults.rotatedKey = await ephemeralKey()
      },
    },
    {
      id: 'wrong-jwks-status-list',
      title: { ja: 'NII → Status List の Subordinate Statement に誤った鍵', en: 'Wrong key in the Subordinate Statement NII → Status List' },
      expect: {
        ja: 'Status List の EC 署名鍵が上位の Subordinate Statement の jwks に含まれず検証失敗。Verifier の失効確認と Wallet Attestation の状態確認が失敗し、提示・発行が拒否される',
        en: "The Status List's EC signing key is not in the superior's Subordinate Statement jwks, so validation fails. The Verifier's revocation check and the Wallet Attestation status check fail; presentation and issuance are rejected",
      },
      apply: async () => {
        reg(ENTITY.nii, ENTITY.statusList).wrongJwks = true
      },
    },
    {
      id: 'expire-nii',
      title: { ja: 'eduGAIN → NII の Subordinate Statement が期限切れ', en: 'The Subordinate Statement eduGAIN → NII has expired' },
      expect: {
        ja: 'NII 配下 (学認) の全エンティティの Trust Chain が無効になる。I2 配下の InCommon SP 自身の Trust Chain は有効なまま (ただし機関IdP が信頼できないのでログイン不可)',
        en: "The Trust Chains of all entities under NII (GakuNin) become invalid. The InCommon SP's own chain under I2 stays valid (but it cannot log in since the Institution IdP is no longer trusted)",
      },
      apply: async () => {
        reg(ENTITY.trustAnchor, ENTITY.nii).expired = true
      },
    },
    {
      id: 'policy-violation-idp',
      title: { ja: 'NII が機関IdP に満たせない metadata_policy を課す', en: 'NII imposes a metadata_policy the Institution IdP cannot satisfy' },
      expect: {
        ja: 'op_policy_uri を essential にするが機関IdP は宣言していないため、Trust Chain の署名は正しくても metadata_policy の適用で失敗。学認SP / InCommon SP / Issuer のログインが失敗',
        en: 'op_policy_uri is made essential but the Institution IdP does not declare it: the signatures are valid but applying metadata_policy fails. Login at the GakuNin SP / InCommon SP / Issuer fails',
      },
      apply: async () => {
        const r = reg(ENTITY.nii, ENTITY.idp)
        r.metadataPolicy = { ...(r.metadataPolicy ?? {}), openid_provider: { op_policy_uri: { essential: true } } }
      },
    },
    {
      id: 'issuer-hints-i2',
      title: { ja: '学認Issuer の authority_hints を I2 に変更 (I2 は未登録)', en: 'Point the GakuNin Issuer\'s authority_hints to I2 (not registered there)' },
      expect: {
        ja: 'I2 の fetch が 404 になり Trust Chain が切れる。続けて「I2 に学認Issuer を登録」すると I2 経由で解決できるようになり、機関IdP は他フェデレーション扱い (最小限の属性) で Issuer にログインさせる',
        en: "I2's fetch returns 404 and the chain breaks. If you then register the GakuNin Issuer at I2, it resolves via I2 and the Institution IdP treats the Issuer as another federation's RP (minimal attributes)",
      },
      apply: async () => {
        get(ENTITY.issuer).authorityHints = [ENTITY.i2]
      },
    },
    {
      id: 'rotate-ta',
      title: {
        ja: 'eduGAIN (Trust Anchor) の鍵ローテーション (各エンティティの TA 設定は旧鍵のまま)',
        en: "eduGAIN (Trust Anchor) key rotation (every entity's TA configuration keeps the old key)",
      },
      expect: {
        ja: 'Trust Anchor の EC が事前設定の公開鍵で検証できず、全ての Trust Chain が無効になる',
        en: "The Trust Anchor's EC cannot be validated with the pre-configured public key: every Trust Chain becomes invalid",
      },
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
  const vis = (id: string) => `<a href="/trust-chain?entity=${encodeURIComponent(id)}" target="_blank">${t('図', 'diagram')}</a>`

  const impact = async () => {
    const targets = [...opts.members.filter((e) => !opts.anchors.some((a) => a.entityId === e.entityId)).map((e) => e.entityId)]
    const results = await Promise.all(
      targets.map(async (id) => {
        try {
          const chain = await resolveTrustChain(id, opts.anchors, { noCache: true })
          return { id, ok: true, detail: chain.path.map(label).join(' → ') }
        } catch (e) {
          return { id, ok: false, detail: humanize((e as Error).message.replace(/^no valid trust chain for \S+: /, '')) }
        }
      })
    )
    return `<table class="imp">${results
      .map(
        (r) => `<tr class="${r.ok ? '' : 'bad'}"><td><b>${esc(label(r.id))}</b></td><td class="${r.ok ? 'ok' : 'ng'}">${r.ok ? t('✓ 有効', '✓ valid') : t('✗ 無効', '✗ invalid')}</td>
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
            return `<tr class="${regChanged(a.entityId, r) ? 'chg' : ''}"><td><b>${esc(label(r.entityId))}</b>${
              isInitialReg(a.entityId, r.entityId) ? '' : ` <span class="tag">${t('追加', 'added')}</span>`
            }</td>
            <td>${btn('toggle_registration', f, r.disabled ? t('停止中 → 再開', 'suspended → resume') : t('登録中 → 停止', 'registered → suspend'), r.disabled ? 'bad' : '')}</td>
            <td>${btn('toggle_wrong_jwks', f, r.wrongJwks ? t('不正な鍵 → 戻す', 'wrong key → restore') : t('正しい鍵 → 不正に', 'correct key → make wrong'), r.wrongJwks ? 'bad' : '')}</td>
            <td>${btn('toggle_expired', f, r.expired ? t('期限切れ → 戻す', 'expired → restore') : t('有効 → 期限切れに', 'valid → expire'), r.expired ? 'bad' : '')}</td>
            <td><details><summary>${r.metadataPolicy ? esc(Object.keys(r.metadataPolicy).join(', ')) : t('なし', 'none')}</summary>
              <form method="post" action="/federation"><input type="hidden" name="op" value="set_policy"><input type="hidden" name="sup" value="${esc(a.entityId)}"><input type="hidden" name="sub" value="${esc(r.entityId)}">
              <textarea name="policy" rows="7" placeholder='{"openid_provider": {"op_policy_uri": {"essential": true}}}'>${esc(policy)}</textarea><br><button>${t('保存', 'Save')}</button></form></details></td>
            <td>${isInitialReg(a.entityId, r.entityId) ? '' : btn('delete_registration', f, t('削除', 'Remove'), 'bad')} ${vis(r.entityId)}</td></tr>`
          })
          .join('')
        const candidates = opts.members.filter((e) => e.entityId !== a.entityId && !a.subordinates?.has(e.entityId))
        return `<section><h3>${t(`${esc(label(a.entityId))} が発行する Subordinate Statement`, `Subordinate Statements issued by ${esc(label(a.entityId))}`)}</h3>
          <table class="cfg"><thead><tr><th>${t('下位エンティティ', 'Subordinate')}</th><th>${t('登録 (fetch)', 'Registration (fetch)')}</th><th>jwks</th><th>${t('有効期限', 'Expiry')}</th><th>metadata_policy</th><th></th></tr></thead><tbody>${rows}</tbody></table>
          ${candidates.length ? `<form method="post" action="/federation" class="add"><input type="hidden" name="op" value="add_registration"><input type="hidden" name="sup" value="${esc(a.entityId)}">
          ${t('下位を追加', 'Add subordinate')}: <select name="sub">${candidates.map((c) => `<option value="${esc(c.entityId)}">${esc(label(c.entityId))}</option>`).join('')}</select> <button>${t('登録', 'Register')}</button></form>` : ''}</section>`
      })
      .join('')

  const entityTable = () => `<table class="cfg"><thead><tr><th>${t('エンティティ', 'Entity')}</th><th>authority_hints</th><th>Entity Configuration</th><th>Federation Entity Key</th><th></th></tr></thead><tbody>${opts.members
    .map((e) => {
      const hintBoxes = authorities
        .filter((a) => a.entityId !== e.entityId)
        .map(
          (a) => `<label><input type="checkbox" name="hints" value="${esc(a.entityId)}" ${e.authorityHints?.includes(a.entityId) ? 'checked' : ''}> ${esc(label(a.entityId))}</label>`
        )
        .join(' ')
      return `<tr class="${entityChanged(e) ? 'chg' : ''}"><td><b>${esc(label(e.entityId))}</b></td>
        <td><form method="post" action="/federation" class="inl"><input type="hidden" name="op" value="set_hints"><input type="hidden" name="entity" value="${esc(e.entityId)}">${hintBoxes} <button>${t('変更', 'Change')}</button></form></td>
        <td>${btn('toggle_ec', { entity: e.entityId }, e.faults.ecDisabled ? t('非公開 → 公開', 'unpublished → publish') : t('公開中 → 非公開に', 'published → unpublish'), e.faults.ecDisabled ? 'bad' : '')}</td>
        <td>${btn('toggle_rotate', { entity: e.entityId }, e.faults.rotatedKey ? t('ローテーション済 → 戻す', 'rotated → restore') : t('鍵をローテーション', 'Rotate key'), e.faults.rotatedKey ? 'bad' : '')}</td>
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
    <section><h3>${t('フェデレーション設定 (信頼関係の編集)', 'Federation settings (edit trust relationships)')}</h3>
    <p class="mut">${t(
      'Trust Anchor / Intermediate が発行する Subordinate Statement と、各エンティティの Entity Configuration を実行中に変更して、Trust Chain が壊れたときの挙動を試せます。変更は即時に反映されます (Trust Chain のキャッシュも破棄)。変更はメモリ上のみで、サーバーを再起動すると元に戻ります。黄色の行が初期状態から変更されている箇所です。',
      'Change the Subordinate Statements issued by the Trust Anchor / Intermediates and the Entity Configurations of the entities at runtime to see what happens when Trust Chains break. Changes apply immediately (the Trust Chain cache is cleared). They are kept in memory only; a server restart restores the original federation. Yellow rows differ from the initial state.'
    )}</p>
    ${btn('reset', {}, t('すべて初期状態に戻す', 'Restore everything'))}</section>
    <section><h3>${t('現在の Trust Chain の状態', 'Current Trust Chain status')}</h3>${await impact()}</section>
    <section><h3>${t('壊し方のプリセット', 'Presets for breaking trust')}</h3><p class="mut">${t('プリセットは現在の設定に重ねて適用されます。試した後は「すべて初期状態に戻す」で元に戻してください。', 'Presets are applied on top of the current settings. Use "Restore everything" afterwards.')}</p>
    <div class="presets">${presets
      .map((p) => `<div class="preset"><div class="t">${esc(pick(p.title))}</div><div class="e">${esc(pick(p.expect))}</div><div>${btn('preset', { id: p.id }, t('適用', 'Apply'))}</div></div>`)
      .join('')}</div></section>
    ${authorityTables()}
    <section><h3>${t('各エンティティの Entity Configuration', 'Entity Configuration of each entity')}</h3>
    <p class="mut">${t(
      'authority_hints の変更、Entity Configuration の非公開、Federation Entity Key のローテーション (新しい鍵で署名・公開するが、上位の Subordinate Statement や Trust Anchor の事前設定は旧鍵のまま) ができます。',
      "Change authority_hints, unpublish the Entity Configuration, or rotate the Federation Entity Key (signs and publishes with a new key while the superior's Subordinate Statement or the pre-configured Trust Anchor key keeps the old one)."
    )}</p>
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
        const done = await op(form)
        changed()
        emit('Federation 設定', 'info', done)
        message = pick(done) as string
      } catch (e) {
        ok = false
        message = humanize((e as Error).message)
      }
      return c.redirect(`/federation?ok=${ok ? 1 : 0}&msg=${encodeURIComponent(message)}`, 303)
    })
  }

  return { mount, reset }
}
