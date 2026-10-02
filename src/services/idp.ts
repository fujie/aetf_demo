import { randomUUID } from 'node:crypto'
import { Hono } from 'hono'
import * as jose from 'jose'
import { type SigningKey, jwksOf, signJwt, verifyWithJwks } from '../common/keys.js'
import { esc, page, trustChainHtml } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'

/** Demo accounts of the institution (機関). */
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
}

/**
 * 機関IdP: a minimal OpenID Provider. Relying Parties (e.g. the 学認Issuer configured as a 学認SP)
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
}) => {
  const { entityId } = opts
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Example University (機関IdP)' },
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
        '機関IdP (Example University)',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <p>デモアカウント: ${Object.keys(IDP_USERS)
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
          `<p class="ng">RP ${esc(clientId)} をフェデレーションで確認できません</p><pre>${esc((e as Error).message)}</pre>`
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
    })
    return c.html(
      page(
        '機関IdP ログイン',
        `<section>
          <p><b>${esc(rp.metadata.client_name ?? clientId)}</b> がログインを要求しています。</p>
          <p class="mut">OpenID Federation で RP を確認しました: ${trustChainHtml(rp.chain.path)}</p>
          <form method="post" action="/login">
            <input type="hidden" name="txn" value="${txn}">
            <p>ユーザー名 <input name="username" value="taro"></p>
            <p>パスワード <input name="password" type="password" value="password"></p>
            <button type="submit">ログイン</button>
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
      return c.html(page('Error', '<p class="ng">ユーザー名またはパスワードが違います</p>'), 401)
    }
    pending.delete(String(form.txn))
    const code = randomUUID()
    codes.set(code, { ...txn, user: username, exp: Date.now() + 60_000 })
    const redirect = new URL(txn.redirectUri)
    redirect.searchParams.set('code', code)
    if (txn.state) redirect.searchParams.set('state', txn.state)
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
        ...user.claims,
      },
      'JWT'
    )
    return c.json({ access_token: randomUUID(), token_type: 'Bearer', id_token: idToken })
  })

  return { app, entity }
}
