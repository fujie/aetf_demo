import { emit } from '../common/events.js'
import { type Bi, bi, pick, t } from '../common/i18n.js'
import { randomUUID } from 'node:crypto'
import { Hono } from 'hono'
import * as jose from 'jose'
import { type SigningKey, jwksOf, signJwt, verifyWithJwks } from '../common/keys.js'
import { esc, page, trustChainHtml, escMsg } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'

/** Demo accounts of the institution. */
export const IDP_USERS: Record<
  string,
  { password: string; claims: Record<string, unknown> }
> = {
  taro: {
    password: 'password',
    claims: {
      name: '学認 太郎',
      family_name: '学認',
      given_name: '太郎',
      email: 'taro@example-u.ac.jp',
      eduPersonPrincipalName: 'taro@example-u.ac.jp',
      eduPersonAffiliation: ['student', 'member'],
      organization: 'Example University',
    },
  },
  hanako: {
    password: 'password',
    claims: {
      name: '学認 花子',
      family_name: '学認',
      given_name: '花子',
      email: 'hanako@example-u.ac.jp',
      eduPersonPrincipalName: 'hanako@example-u.ac.jp',
      eduPersonAffiliation: ['student', 'member'],
      organization: 'Example University',
    },
  },
}

type AuthzRequest = {
  clientId: string
  redirectUri: string
  state?: string
  nonce?: string
  scope: string
  trustChainPath: string[]
  clientName?: string
  release: AttributeRelease
}

/**
 * Attribute release policy decided from the RP's Trust Chain:
 *  - RPs of the home federation (GakuNin: chain through NII) get the full attribute set
 *  - RPs of other federations reached through eduGAIN (e.g. InCommon) get a minimal,
 *    Research & Scholarship-like set (inter-federation)
 */
type AttributeRelease = { policy: Bi; claims: string[] }
const FULL_RELEASE = ['name', 'family_name', 'given_name', 'email', 'eduPersonPrincipalName', 'eduPersonAffiliation', 'organization']
const INTERFEDERATION_RELEASE = ['name', 'email', 'eduPersonPrincipalName', 'eduPersonAffiliation', 'organization']

/**
 * Institution IdP: a minimal OpenID Provider. Relying Parties (e.g. the GakuNin Issuer configured as a GakuNin SP)
 * are not pre-registered: they are accepted through OpenID Federation automatic registration,
 * i.e. by resolving a Trust Chain for the `client_id` and using the resolved
 * `openid_relying_party` metadata (redirect_uris, jwks).
 */
export const createIdp = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
  anchors: TrustAnchorConfig[]
  /** Intermediate Authority of the IdP's own federation (GakuNin = NII). */
  homeFederation: string
}) => {
  const releaseFor = (path: string[]): AttributeRelease =>
    path.includes(opts.homeFederation)
      ? { policy: bi('学認 (同一フェデレーション) — 全属性', 'GakuNin (same federation) — all attributes'), claims: FULL_RELEASE }
      : {
          policy: bi('eduGAIN 経由の他フェデレーション — R&S 相当の最小属性', 'Another federation via eduGAIN — minimal R&S-like attributes'),
          claims: INTERFEDERATION_RELEASE,
        }
  const { entityId } = opts
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Example University (Institution IdP)' },
      openid_provider: {
        issuer: entityId,
        authorization_endpoint: `${entityId}/authorize`,
        token_endpoint: `${entityId}/token`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['ES256', 'RS256'],
        token_endpoint_auth_methods_supported: ['private_key_jwt'],
        client_registration_types_supported: ['automatic'],
        scopes_supported: ['openid', 'profile', 'email', 'gakunin'],
        jwks: jwksOf(opts.signingKey),
      },
    },
  })

  const pending = new Map<string, AuthzRequest>()
  const codes = new Map<string, AuthzRequest & { user: string; exp: number }>()

  const resolveRp = async (clientId: string) => {
    const { metadata, chain } = await resolveEntityMetadata<{
      redirect_uris?: string[]
      jwks?: { keys: jose.JWK[] }
      client_name?: string
    }>(clientId, 'openid_relying_party', opts.anchors)
    return { metadata, chain }
  }

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  app.get('/', (c) =>
    c.html(
      page(
        t('機関IdP (Example University)', 'Institution IdP (Example University)'),
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <p>${t('デモアカウント', 'Demo accounts')}: ${Object.keys(IDP_USERS)
          .map((u) => `<code>${u}</code>`)
          .join(', ')} (password: <code>password</code>)</p></section>`
      )
    )
  )

  app.get('/authorize', async (c) => {
    const q = c.req.query()
    const clientId = q.client_id
    const redirectUri = q.redirect_uri
    if (!clientId || !redirectUri || q.response_type !== 'code') {
      return c.html(page('Error', '<p class="ng">invalid_request</p>'), 400)
    }
    let rp: Awaited<ReturnType<typeof resolveRp>>
    try {
      rp = await resolveRp(clientId)
    } catch (e) {
      return c.html(
        page(
          'Error',
          `<p class="ng">${t(`RP ${escMsg(clientId)} をフェデレーションで確認できません`, `RP ${escMsg(clientId)} cannot be verified through the federation`)}</p><pre>${escMsg((e as Error).message)}</pre>`
        ),
        400
      )
    }
    if (!rp.metadata.redirect_uris?.includes(redirectUri)) {
      return c.html(page('Error', '<p class="ng">redirect_uri is not registered</p>'), 400)
    }
    const txn = randomUUID()
    pending.set(txn, {
      clientId,
      redirectUri,
      state: q.state,
      nonce: q.nonce,
      scope: q.scope ?? 'openid',
      trustChainPath: rp.chain.path,
      clientName: rp.metadata.client_name,
      release: releaseFor(rp.chain.path),
    })
    const release = releaseFor(rp.chain.path)
    return c.html(
      page(
        t('機関IdP ログイン', 'Institution IdP login'),
        `<section>
          <p>${t(`<b>${esc(rp.metadata.client_name ?? clientId)}</b> がログインを要求しています。`, `<b>${esc(rp.metadata.client_name ?? clientId)}</b> requests a login.`)}</p>
          <p class="mut">${t('OpenID Federation で RP を確認しました', 'RP verified through OpenID Federation')}: ${trustChainHtml(rp.chain.path)}</p>
          <p>${t('送信する属性', 'Attributes to be released')} (${esc(pick(release.policy))}):<br>${release.claims.map((x) => `<code>${esc(x)}</code>`).join(' ')}</p>
          <form method="post" action="/login">
            <input type="hidden" name="txn" value="${txn}">
            <p>${t('ユーザー名', 'Username')} <input name="username" value="taro"></p>
            <p>${t('パスワード', 'Password')} <input name="password" type="password" value="password"></p>
            <button type="submit">${t('ログイン', 'Log in')}</button>
          </form></section>`
      )
    )
  })

  app.post('/login', async (c) => {
    const form = await c.req.parseBody()
    const txn = pending.get(String(form.txn))
    const username = String(form.username ?? '')
    const user = IDP_USERS[username]
    if (!txn) return c.html(page('Error', '<p class="ng">unknown transaction</p>'), 400)
    if (!user || user.password !== form.password) {
      return c.html(page('Error', `<p class="ng">${t('ユーザー名またはパスワードが違います', 'Wrong username or password')}</p>`), 401)
    }
    pending.delete(String(form.txn))
    const code = randomUUID()
    codes.set(code, { ...txn, user: username, exp: Date.now() + 60_000 })
    const redirect = new URL(txn.redirectUri)
    redirect.searchParams.set('code', code)
    if (txn.state) redirect.searchParams.set('state', txn.state)
    emit(
      '機関IdP',
      'ok',
      bi(
        `ユーザー ${username} を認証し、${txn.clientName ?? txn.clientId} へ認可コードを発行`,
        `Authenticated user ${username} and issued an authorization code to ${txn.clientName ?? txn.clientId}`
      ),
      bi(`RP は OpenID Federation で確認: ${txn.trustChainPath.join(' → ')}`, `RP verified through OpenID Federation: ${txn.trustChainPath.join(' → ')}`)
    )
    return c.redirect(redirect.toString(), 302)
  })

  app.post('/token', async (c) => {
    const form = await c.req.parseBody()
    const code = codes.get(String(form.code))
    if (form.grant_type !== 'authorization_code' || !code || code.exp < Date.now()) {
      return c.json({ error: 'invalid_grant' }, 400)
    }
    codes.delete(String(form.code))
    if (form.client_id !== code.clientId || form.redirect_uri !== code.redirectUri) {
      return c.json({ error: 'invalid_grant', error_description: 'client/redirect mismatch' }, 400)
    }
    // private_key_jwt with the RP key published in its federation metadata
    try {
      const { metadata } = await resolveRp(code.clientId)
      await verifyWithJwks(String(form.client_assertion ?? ''), metadata.jwks, {
        issuer: code.clientId,
        subject: code.clientId,
        audience: [entityId, `${entityId}/token`],
        maxTokenAge: '5m',
      })
    } catch (e) {
      emit('機関IdP', 'error', bi('RP のクライアント認証 (private_key_jwt) に失敗', 'RP client authentication (private_key_jwt) failed'), (e as Error).message)
      return c.json(
        { error: 'invalid_client', error_description: (e as Error).message },
        401
      )
    }
    const user = IDP_USERS[code.user]
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signJwt(
      opts.signingKey,
      {
        iss: entityId,
        sub: String(user.claims.eduPersonPrincipalName),
        aud: code.clientId,
        iat: now,
        exp: now + 300,
        ...(code.nonce ? { nonce: code.nonce } : {}),
        ...Object.fromEntries(Object.entries(user.claims).filter(([k]) => code.release.claims.includes(k))),
      },
      'JWT'
    )
    emit(
      '機関IdP',
      'ok',
      bi(`ID Token を発行 (${code.clientName ?? code.clientId})`, `Issued an ID Token (${code.clientName ?? code.clientId})`),
      bi(
        `属性リリース: ${code.release.policy.ja} [${code.release.claims.join(', ')}] / RP: ${code.trustChainPath.join(' → ')}`,
        `Attribute release: ${code.release.policy.en} [${code.release.claims.join(', ')}] / RP: ${code.trustChainPath.join(' → ')}`
      )
    )
    return c.json({ access_token: randomUUID(), token_type: 'Bearer', id_token: idToken })
  })

  return { app, entity }
}
