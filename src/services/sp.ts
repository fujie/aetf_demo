import { randomUUID } from 'node:crypto'
import { type Context, Hono } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import { type SigningKey, jwksOf } from '../common/keys.js'
import { esc, page, trustChainHtml, escMsg } from '../common/html.js'
import { emit } from '../common/events.js'
import { bi, pick, t } from '../common/i18n.js'
import { createOidcRp } from '../common/oidc-rp.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import type { TrustAnchorConfig } from '../federation/resolver.js'

export type SpSession = { claims: Record<string, unknown>; opTrustChain: string[]; loggedInAt: string }

/** Labels of the attributes released by the Institution IdP. */
const CLAIM_LABELS: Record<string, { ja: string; en: string }> = {
  name: { ja: '氏名', en: 'Name' },
  family_name: { ja: '姓', en: 'Family name' },
  given_name: { ja: '名', en: 'Given name' },
  email: { ja: 'メール', en: 'Email' },
  eduPersonPrincipalName: { ja: 'ePPN', en: 'ePPN' },
  eduPersonAffiliation: { ja: '所属種別', en: 'Affiliation' },
  organization: { ja: '所属機関', en: 'Organization' },
}

/**
 * Mounts federated OIDC login (/login, /oidc/callback, /logout) on an SP app: the SP is an
 * `openid_relying_party` federation entity and logs users in at an OP (the Institution IdP) found through
 * OpenID Federation, without pre-registration at the OP.
 */
export const mountFederatedLogin = (
  app: Hono,
  opts: { entityId: string; spName: string; rpKey: SigningKey; anchors: TrustAnchorConfig[]; idpEntityId: string }
) => {
  const oidc = createOidcRp({ entityId: opts.entityId, rpKey: opts.rpKey, anchors: opts.anchors })
  const sessions = new Map<string, SpSession>()
  const cookie = `sp_${new URL(opts.entityId).port}`
  const current = (c: Context) => {
    const sid = getCookie(c, cookie)
    return sid ? sessions.get(sid) : undefined
  }

  app.get('/login', async (c) => {
    try {
      return c.redirect(await oidc.authorizationUrl(opts.idpEntityId), 302)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${escMsg((e as Error).message)}</pre>`), 500)
    }
  })

  app.get('/oidc/callback', async (c) => {
    try {
      const login = await oidc.handleCallback(c.req.query())
      const { iss: _i, aud: _a, iat: _t, exp: _e, nonce: _n, sub, ...claims } = login.idToken
      const sid = randomUUID()
      sessions.set(sid, { claims: { sub, ...claims }, opTrustChain: login.opTrustChain, loggedInAt: new Date().toISOString() })
      setCookie(c, cookie, sid, { httpOnly: true, sameSite: 'Lax', path: '/' })
      emit(
        opts.spName,
        'ok',
        bi(`${String(sub)} が機関IdPでログイン`, `${String(sub)} logged in with the Institution IdP`),
        bi(
          `IdP: ${login.opTrustChain.join(' → ')} / 受け取った属性: ${Object.keys(claims).join(', ')}`,
          `IdP: ${login.opTrustChain.join(' → ')} / received attributes: ${Object.keys(claims).join(', ')}`
        )
      )
      return c.redirect('/', 302)
    } catch (e) {
      emit(opts.spName, 'error', bi('ログインに失敗', 'Login failed'), (e as Error).message)
      return c.html(page('Error', `<pre class="ng">${escMsg((e as Error).message)}</pre>`), 400)
    }
  })

  app.post('/logout', (c) => {
    const sid = getCookie(c, cookie)
    if (sid) sessions.delete(sid)
    return c.redirect('/', 303)
  })

  /** HTML block: login button or the logged-in user's released attributes. */
  const loginPanel = (c: Context, opts2: { idpLabel: string }) => {
    const s = current(c)
    if (!s) {
      return `<section><p>${t(
        `${esc(opts2.idpLabel)} のアカウントでログインできます (デモユーザー: taro / hanako、パスワード password)。`,
        `Log in with your ${esc(opts2.idpLabel)} account (demo users: taro / hanako, password: password).`
      )}</p>
        <p><a class="btn" href="/login">${t('学認の機関IdPでログイン', 'Log in with your GakuNin institution IdP')}</a></p></section>`
    }
    const rows = Object.entries(s.claims)
      .map(([k, v]) => `<tr><th>${esc(pick(CLAIM_LABELS[k]) ?? k)}</th><td><code>${esc(k)}</code></td><td>${esc(typeof v === 'string' ? v : JSON.stringify(v))}</td></tr>`)
      .join('')
    return `<section><h3 class="ok">${t('ログイン中', 'Logged in')}: ${esc(String(s.claims.name ?? s.claims.sub))}</h3>
      <p class="mut">${t('IdP を OpenID Federation で確認', 'IdP verified through OpenID Federation')}: ${trustChainHtml(s.opTrustChain)}</p>
      <h4>${t('IdP から受け取った属性', 'Attributes received from the IdP')}</h4><table>${rows}</table>
      <form method="post" action="/logout" style="margin-top:10px"><button>${t('ログアウト', 'Log out')}</button></form></section>`
  }

  return { current, loginPanel, redirectUri: oidc.redirectUri }
}

/** Regular GakuNin SP: a regular service provider of the GakuNin federation (e.g. an e-journal platform). */
export const createGakuninSp = (opts: {
  entityId: string
  federationKey: SigningKey
  rpKey: SigningKey
  authorityHints: string[]
  anchors: TrustAnchorConfig[]
  idpEntityId: string
}) => {
  const name = 'GakuNin SP (e-journal)'
  const entity = createFederationEntity({
    entityId: opts.entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Example E-Journal Platform (GakuNin SP)' },
      openid_relying_party: {
        client_name: name,
        client_registration_types: ['automatic'],
        redirect_uris: [`${opts.entityId}/oidc/callback`],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: jwksOf(opts.rpKey),
      },
    },
  })
  const app = new Hono()
  mountFederationEndpoints(app, entity)
  const login = mountFederatedLogin(app, { entityId: opts.entityId, spName: '学認SP', rpKey: opts.rpKey, anchors: opts.anchors, idpEntityId: opts.idpEntityId })

  app.get('/', (c) => {
    const s = login.current(c)
    const affiliations = (s?.claims.eduPersonAffiliation as string[] | undefined) ?? []
    const content = s
      ? `<section><h3>${t('論文アクセス', 'Article access')}</h3>
          ${
            affiliations.includes('member') || affiliations.includes('student')
              ? `<p class="ok">${t('所属機関の契約により全文を閲覧できます。', "Full text is available through your institution's subscription.")}</p><ul><li>Journal of Federated Identity, Vol.12 — ${t('全文 PDF', 'full-text PDF')}</li><li>Trust Frameworks for Academia — ${t('全文 PDF', 'full-text PDF')}</li></ul>`
              : `<p class="ng">${t('所属機関の契約がありません。', 'Your institution has no subscription.')}</p>`
          }
          <p class="mut">${t('eduPersonAffiliation に基づくアクセス制御 (学認SP の典型的な利用例)', 'Access control based on eduPersonAffiliation (a typical GakuNin SP use case)')}</p></section>`
      : ''
    return c.html(
      page(
        t('学認SP (電子ジャーナル)', 'GakuNin SP (e-journal)'),
        `${login.loginPanel(c, { idpLabel: t('所属機関 (学認)', 'institution (GakuNin)') })}${content}
        <section class="mut">Entity ID: <code>${esc(opts.entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a>
        — ${t(
          'NII 配下の <code>openid_relying_party</code> として登録 (機関IdPへは事前登録なし、Federation の自動登録で接続)',
          'registered under NII as an <code>openid_relying_party</code> (not pre-registered at the Institution IdP; connects via federation automatic registration)'
        )}</section>`
      )
    )
  })

  return { app, entity }
}
