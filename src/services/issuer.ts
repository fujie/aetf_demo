import { randomUUID } from 'node:crypto'
import { type Context, Hono } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import * as jose from 'jose'
import { initializeContext, parseDpopHeader } from '@trustknots/vcknots'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
  AuthzOAuthPolicy,
  AuthzTokenRequest,
  type CredentialEndpointAuthorizationContext,
  initializeAuthzFlow,
} from '@trustknots/vcknots/authz'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
  CredentialRequest,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import type { IssueCredentialProvider } from '@trustknots/vcknots/providers'
import { type SigningKey, jwksOf, signJwt, verifyWithJwks } from '../common/keys.js'
import { esc, page, qrSvg, trustChainHtml } from '../common/html.js'
import { toErrorResponse } from '../common/vcknots-util.js'
import {
  ATTESTATION_HEADER,
  ATTESTATION_POP_HEADER,
  WalletAttestationError,
  verifyWalletAttestation,
} from '../common/wallet-attestation.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'
import { ATTRIBUTE_REQUEST_TYP, ATTRIBUTE_RESPONSE_TYP } from './attribute-provider.js'

const PRE_CODE_TTL_SEC = 10 * 60
const C_NONCE_TTL_MS = 2 * 60 * 1000
const STATUS_LIST_ID = 'gakunin-issuer-1'

type UserSession = {
  state?: string
  nonce?: string
  claims?: Record<string, unknown>
  idpPath?: string[]
  apPath?: string[]
  offerUri?: string
}

type Issuance = {
  preAuthorizedCode: string
  user: string
  claims: Record<string, unknown>
  createdAt: string
  walletClientId?: string
  walletProviderPath?: string[]
  issuedAt?: string
  status?: { idx: number; uri: string }
  revoked?: boolean
}

/**
 * Wraps the vcknots dc+sd-jwt issuance provider so that the Token Status List reference (`status`)
 * is placed in the issuer-signed payload instead of being made selectively disclosable.
 */
const sdJwtWithStatusProvider = (): IssueCredentialProvider => {
  // The built-in dc+sd-jwt provider is not exported from the package entry points, so take it
  // from a default context's provider registry.
  const base = initializeContext()
    .providers.get('issue-credential-provider')
    .find((p) => p.canHandle('dc+sd-jwt' as Parameters<typeof p.canHandle>[0]))
  if (!base) throw new Error('dc+sd-jwt issue provider not found')
  const wrapped: IssueCredentialProvider = {
    ...base,
    name: 'issue-credential-dc-sd-jwt-with-status-provider',
    createCredential(issuer, configuration, options) {
      return base.createCredential.call(this, issuer, configuration, {
        ...options,
        nonDisclosableClaims: ['status'],
      })
    },
  }
  return wrapped
}

const credentialClaims = [
  ['family_name', '姓'],
  ['given_name', '名'],
  ['name', '氏名'],
  ['eduPersonPrincipalName', 'ePPN'],
  ['eduPersonAffiliation', '所属種別'],
  ['organization', '所属機関'],
  ['student_number', '学籍番号'],
  ['department', '学部・学科'],
  ['enrollment_status', '在籍状況'],
] as const

/**
 * 学認Issuer: OID4VCI Credential Issuer + Authorization Server built with vcknots.
 * Configured as a 学認SP: it authenticates users at the 機関IdP and obtains attributes from the
 * 属性Provider, trusting both through OpenID Federation.
 */
export const createIssuer = async (opts: {
  entityId: string
  federationKey: SigningKey
  /** Key for RP authentication (private_key_jwt to IdP, signed attribute requests). */
  rpKey: SigningKey
  /** Credential (SD-JWT VC) signing key. */
  credentialKey: SigningKey
  authorityHints: string[]
  anchors: TrustAnchorConfig[]
  idpEntityId: string
  attributeProviderEntityId: string
  statusListEntityId: string
  statusListApiKey: string
  credentialConfigurationId: string
  vct: string
}) => {
  const baseUrl = opts.entityId
  const issuerId = CredentialIssuer(baseUrl)
  const authzId = AuthorizationServerIssuer(baseUrl)

  // ---- vcknots initialisation -------------------------------------------------------------
  const context = initializeContext({ debug: true, providers: [sdJwtWithStatusProvider()] })
  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)

  const issuerMetadata = CredentialIssuerMetadata({
    credential_issuer: baseUrl,
    authorization_servers: [baseUrl],
    credential_endpoint: `${baseUrl}/credentials`,
    nonce_endpoint: `${baseUrl}/nonce`,
    display: [
      { name: '学認 Issuer (Example University)', locale: 'ja-JP' },
      { name: 'GakuNin Issuer (Example University)', locale: 'en-US' },
    ],
    credential_configurations_supported: {
      [opts.credentialConfigurationId]: {
        format: 'dc+sd-jwt',
        scope: opts.credentialConfigurationId,
        vct: opts.vct,
        credential_signing_alg_values_supported: ['ES256'],
        cryptographic_binding_methods_supported: ['jwk', 'did:key'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
        credential_metadata: {
          display: [{ name: '学認 学生証明書', locale: 'ja-JP', background_color: '#155e86', text_color: '#FFFFFF' }],
          claims: [
            ...credentialClaims.map(([path, name]) => ({
              path: [path],
              display: [{ name, locale: 'ja-JP' }],
              ...(path === 'eduPersonPrincipalName' ? { mandatory: true } : {}),
            })),
            { path: ['status'] },
          ],
        },
      },
    },
  })
  await issuerFlow.createIssuerMetadata(issuerMetadata)
  // Replace the key vcknots generated with a persisted one so that credentials stay verifiable
  // across restarts.
  const { kid: _kid, use: _use, alg: _alg, ...credentialPrivateJwk } = opts.credentialKey.privateJwk
  const { kid: _pkid, use: _puse, alg: _palg, ...credentialPublicJwk } = opts.credentialKey.publicJwk
  await context.providers.get('issuer-signature-key-store-provider').save(issuerId, 'ES256', {
    format: 'jwk',
    declaredAlg: 'ES256',
    privateKey: credentialPrivateJwk,
    publicKey: credentialPublicJwk,
  } as Parameters<ReturnType<typeof context.providers.get<'issuer-signature-key-store-provider'>>['save']>[2])

  await authzFlow.createAuthzServerMetadata(
    AuthorizationServerMetadata({
      issuer: baseUrl,
      // the authorization code flow is not offered; vcknots requires the field
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      response_types_supported: ['code'],
      'pre-authorized_grant_anonymous_access_supported': true,
      token_endpoint_auth_methods_supported: ['none', 'attest_jwt_client_auth'],
    })
  )
  const dpopOptional = { senderConstrainedAccessToken: { method: 'dpop', dpop: { mode: 'optional' } } }
  await authzFlow.createAuthzOAuthPolicy(
    authzId,
    AuthzOAuthPolicy({ default_client: dpopOptional, anonymous_client: dpopOptional })
  )

  const jwtVcIssuer = await issuerFlow.findJwtVcIssuerMetadata(issuerId)
  const credentialJwks = (jwtVcIssuer as { jwks?: { keys: jose.JWK[] } } | null)?.jwks

  // ---- OpenID Federation ------------------------------------------------------------------
  const entity = createFederationEntity({
    entityId: baseUrl,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: '学認Issuer (Example University)' },
      openid_credential_issuer: {
        ...(issuerMetadata as unknown as Record<string, unknown>),
        ...(credentialJwks ? { jwks: credentialJwks } : {}),
      },
      oauth_authorization_server: {
        issuer: baseUrl,
        token_endpoint: `${baseUrl}/token`,
        token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
      },
      openid_relying_party: {
        client_name: '学認Issuer',
        client_registration_types: ['automatic'],
        redirect_uris: [`${baseUrl}/oidc/callback`],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: jwksOf(opts.rpKey),
      },
    },
  })

  // ---- state ------------------------------------------------------------------------------
  const sessions = new Map<string, UserSession>()
  const issuances = new Map<string, Issuance>() // by pre-authorized code
  const byAccessToken = new Map<string, Issuance>()

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  const session = (c: Context) => {
    let sid = getCookie(c, 'issuer_sid')
    if (!sid || !sessions.has(sid)) {
      sid = randomUUID()
      sessions.set(sid, {})
      setCookie(c, 'issuer_sid', sid, { httpOnly: true, sameSite: 'Lax', path: '/' })
    }
    return sessions.get(sid) as UserSession
  }

  // ---- UI ---------------------------------------------------------------------------------
  app.get('/', (c) => {
    const s = session(c)
    if (!s.claims) {
      return c.html(
        page(
          '学認Issuer',
          `<section><p>学認 学生証明書 (SD-JWT VC) を発行します。まず所属機関の IdP でログインしてください。</p>
          <p><a class="btn" href="/login">機関IdPでログイン</a></p></section>
          <section class="mut">Entity ID: <code>${esc(baseUrl)}</code> /
          <a href="/.well-known/openid-federation">Entity Configuration</a> /
          <a href="/.well-known/openid-credential-issuer">Credential Issuer Metadata</a> /
          <a href="/admin">発行済みクレデンシャル管理</a></section>`
        )
      )
    }
    const rows = credentialClaims
      .map(([k, label]) => `<tr><th>${esc(label)}</th><td><code>${esc(k)}</code></td><td>${esc(JSON.stringify(s.claims?.[k]))}</td></tr>`)
      .join('')
    return c.html(
      page(
        '学認Issuer',
        `<section><h3>取得した属性</h3><table>${rows}</table>
        <p class="mut">機関IdP: ${trustChainHtml(s.idpPath ?? [])}<br>属性Provider: ${trustChainHtml(s.apPath ?? [])}</p></section>
        <section><form method="post" action="/offer"><button>Credential Offer を作成</button></form></section>`
      )
    )
  })

  app.get('/login', async (c) => {
    const s = session(c)
    s.state = randomUUID()
    s.nonce = randomUUID()
    try {
      const { metadata } = await resolveEntityMetadata<{ authorization_endpoint: string }>(
        opts.idpEntityId,
        'openid_provider',
        opts.anchors
      )
      const url = new URL(metadata.authorization_endpoint)
      url.search = new URLSearchParams({
        response_type: 'code',
        client_id: baseUrl,
        redirect_uri: `${baseUrl}/oidc/callback`,
        scope: 'openid profile email gakunin',
        state: s.state,
        nonce: s.nonce,
      }).toString()
      return c.redirect(url.toString(), 302)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${esc((e as Error).message)}</pre>`), 500)
    }
  })

  app.get('/oidc/callback', async (c) => {
    const s = session(c)
    const { code, state } = c.req.query()
    if (!code || !state || state !== s.state) {
      return c.html(page('Error', '<p class="ng">invalid state</p>'), 400)
    }
    try {
      // 1. Trust the 機関IdP via OpenID Federation and redeem the code with private_key_jwt
      const idp = await resolveEntityMetadata<{
        issuer: string
        token_endpoint: string
        jwks: { keys: jose.JWK[] }
      }>(opts.idpEntityId, 'openid_provider', opts.anchors)
      const now = Math.floor(Date.now() / 1000)
      const clientAssertion = await signJwt(
        opts.rpKey,
        { iss: baseUrl, sub: baseUrl, aud: idp.metadata.issuer, jti: randomUUID(), iat: now, exp: now + 60 },
        'JWT'
      )
      const tokenRes = await fetch(idp.metadata.token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          client_id: baseUrl,
          redirect_uri: `${baseUrl}/oidc/callback`,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: clientAssertion,
        }),
      })
      const tokenBody = (await tokenRes.json()) as { id_token?: string; error_description?: string }
      if (!tokenRes.ok || !tokenBody.id_token) {
        throw new Error(`IdP token error: ${tokenBody.error_description ?? tokenRes.status}`)
      }
      const { payload: idToken } = await verifyWithJwks(tokenBody.id_token, idp.metadata.jwks, {
        issuer: idp.metadata.issuer,
        audience: baseUrl,
      })
      if (idToken.nonce !== s.nonce) throw new Error('nonce mismatch')

      // 2. Fetch additional attributes from the 属性Provider (also trusted via federation)
      const ap = await resolveEntityMetadata<{ attribute_endpoint: string; jwks: { keys: jose.JWK[] } }>(
        opts.attributeProviderEntityId,
        'attribute_provider',
        opts.anchors
      )
      const request = await signJwt(
        opts.rpKey,
        { iss: baseUrl, aud: opts.attributeProviderEntityId, sub: idToken.sub, iat: now, exp: now + 60, jti: randomUUID() },
        ATTRIBUTE_REQUEST_TYP
      )
      const apRes = await fetch(ap.metadata.attribute_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ request }),
      })
      if (!apRes.ok) throw new Error(`attribute provider error: ${apRes.status} ${await apRes.text()}`)
      const { payload: apPayload } = await verifyWithJwks(await apRes.text(), ap.metadata.jwks, {
        typ: ATTRIBUTE_RESPONSE_TYP,
        issuer: opts.attributeProviderEntityId,
        audience: baseUrl,
        subject: idToken.sub,
      })

      const claims: Record<string, unknown> = {}
      for (const [k] of credentialClaims) {
        const v = (apPayload.attributes as Record<string, unknown>)?.[k] ?? idToken[k]
        if (v !== undefined) claims[k] = v
      }
      s.claims = claims
      s.idpPath = idp.chain.path
      s.apPath = ap.chain.path
      return c.redirect('/', 302)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${esc((e as Error).message)}</pre>`), 500)
    }
  })

  app.post('/offer', async (c) => {
    const s = session(c)
    if (!s.claims) return c.redirect('/', 302)
    try {
      const { offer } = await issuerFlow.offerCredential(
        issuerId,
        [CredentialConfigurationId(opts.credentialConfigurationId)],
        { usePreAuth: true, ttlSec: PRE_CODE_TTL_SEC }
      )
      const grants = (offer as { grants?: Record<string, { 'pre-authorized_code'?: string }> }).grants
      const preAuthorizedCode =
        grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']
      if (!preAuthorizedCode) throw new Error('pre-authorized_code missing in offer')
      issuances.set(preAuthorizedCode, {
        preAuthorizedCode,
        user: String(s.claims.eduPersonPrincipalName),
        claims: s.claims,
        createdAt: new Date().toISOString(),
      })
      const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`
      return c.html(
        page(
          'Credential Offer',
          `<section><p>Wallet でこの Credential Offer を読み取ってください (有効期限 ${PRE_CODE_TTL_SEC / 60} 分)。</p>
          ${await qrSvg(offerUri)}
          <p>Wallet Instance (CLI) の場合:</p>
          <pre id="cmd">./wallet-instance receive '${esc(offerUri)}'</pre>
          <p class="mut">Offer URI:</p><pre id="offer">${esc(offerUri)}</pre></section>
          <section><a href="/">戻る</a> / <a href="/admin">発行済みクレデンシャル管理</a></section>`
        )
      )
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  app.get('/admin', (c) => {
    const rows = [...issuances.values()]
      .map(
        (i) => `<tr><td>${esc(i.user)}</td><td>${esc(i.createdAt)}</td><td>${esc(i.issuedAt ?? '未受領')}</td>
        <td>${i.walletClientId ? `<code>${esc(i.walletClientId)}</code><br><span class="mut">${trustChainHtml(i.walletProviderPath ?? [])}</span>` : ''}</td>
        <td>${i.status ? `idx=${i.status.idx}` : ''}</td>
        <td>${i.status ? (i.revoked ? '<span class="ng">失効</span>' : `<span class="ok">有効</span> <form style="display:inline" method="post" action="/admin/revoke"><input type="hidden" name="code" value="${esc(i.preAuthorizedCode)}"><button>失効させる</button></form>`) : ''}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        '学認Issuer - 発行済みクレデンシャル',
        `<section><table><tr><th>ユーザー</th><th>Offer作成</th><th>発行</th><th>Wallet Instance</th><th>Status List</th><th>状態</th></tr>${rows}</table></section>
        <section><a href="/">戻る</a></section>`
      )
    )
  })

  app.post('/admin/revoke', async (c) => {
    const form = await c.req.parseBody()
    const issuance = issuances.get(String(form.code))
    if (issuance?.status) {
      const res = await fetch(`${issuance.status.uri}/entries/${issuance.status.idx}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${opts.statusListApiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 1 }),
      })
      if (res.ok) issuance.revoked = true
    }
    return c.redirect('/admin', 303)
  })

  // ---- OID4VCI / OAuth endpoints ----------------------------------------------------------
  app.get('/.well-known/openid-credential-issuer', async (c) =>
    c.json(await issuerFlow.findIssuerMetadata(issuerId))
  )
  app.get('/.well-known/oauth-authorization-server', async (c) =>
    c.json(await authzFlow.findAuthzServerMetadata(authzId))
  )
  app.get('/.well-known/jwt-vc-issuer', async (c) =>
    c.json(await issuerFlow.findJwtVcIssuerMetadata(issuerId))
  )

  app.post('/token', async (c) => {
    // Wallet Attestation (attestation-based client authentication), trusted via OpenID Federation
    let attestation: Awaited<ReturnType<typeof verifyWalletAttestation>>
    try {
      attestation = await verifyWalletAttestation(
        c.req.header(ATTESTATION_HEADER),
        c.req.header(ATTESTATION_POP_HEADER),
        baseUrl,
        opts.anchors
      )
    } catch (e) {
      if (e instanceof WalletAttestationError) {
        console.warn('[issuer] wallet attestation rejected:', e.message)
        return c.json({ error: 'invalid_client', error_description: e.message }, 401)
      }
      throw e
    }
    try {
      const requestData = Object.fromEntries((await c.req.formData()).entries()) as Record<string, string>
      const clientResolution = await authzFlow.resolveTokenRequestClientPolicy(authzId, requestData)
      if (!clientResolution.ok) {
        return c.json({ error: clientResolution.error, error_description: clientResolution.error_description }, 400)
      }
      const dpopProof = parseDpopHeader(c.req.header('DPoP'))
      const tokenRequest = AuthzTokenRequest.schema.parse(requestData)
      const accessToken = (await authzFlow.createAccessToken(authzId, tokenRequest, {
        clientId: clientResolution.clientId,
        ...(clientResolution.dpopMode !== 'off' && dpopProof.ok
          ? { dpopProof: { proofJwt: dpopProof.proofJwt, htm: 'POST', htu: `${baseUrl}/token`, nonceRequired: false } }
          : { ttlSec: 60 * 30 }),
      })) as { access_token: string }
      const issuance = issuances.get(String(requestData['pre-authorized_code']))
      if (issuance) {
        issuance.walletClientId = attestation.clientId
        issuance.walletProviderPath = attestation.trustChainPath
        byAccessToken.set(accessToken.access_token, issuance)
      }
      console.log(`[issuer] access token issued to wallet ${attestation.clientId} (WP chain: ${attestation.trustChainPath.join(' -> ')})`)
      return c.json(accessToken)
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  app.post('/nonce', async (c) => {
    c.header('Cache-Control', 'no-store')
    return c.json({ c_nonce: await issuerFlow.createNonce(C_NONCE_TTL_MS) })
  })

  app.post('/credentials', async (c) => {
    try {
      let authorizationContext: CredentialEndpointAuthorizationContext
      try {
        authorizationContext = await authzFlow.authorizeCredentialEndpointAccess(authzId, {
          authorizationHeader: c.req.header('Authorization'),
          dpopHeader: c.req.header('DPoP'),
          htm: c.req.method,
          htu: `${baseUrl}/credentials`,
          nonceRequired: false,
        })
      } catch (e) {
        return c.json({ error: 'invalid_token', error_description: (e as Error).message }, 401)
      }
      const token = c.req.header('Authorization')?.replace(/^(Bearer|DPoP)\s+/i, '') ?? ''
      const issuance = byAccessToken.get(token)
      if (!issuance) return c.json({ error: 'invalid_token', error_description: 'unknown access token' }, 401)

      // Allocate a Token Status List entry for this credential at the Status List provider
      if (!issuance.status) {
        const res = await fetch(`${opts.statusListEntityId}/lists/${STATUS_LIST_ID}/entries`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${opts.statusListApiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner: baseUrl, label: issuance.user }),
        })
        if (!res.ok) throw new Error(`status list allocation failed: ${res.status}`)
        issuance.status = ((await res.json()) as { status_list: { idx: number; uri: string } }).status_list
      }

      const credential = await issuerFlow.issueCredential(issuerId, CredentialRequest(await c.req.json()), {
        authorizationContext,
        alg: 'ES256',
        claims: { ...issuance.claims, status: { status_list: issuance.status } },
        proofJwt: { usePreAuth: true },
      })
      issuance.issuedAt = new Date().toISOString()
      console.log(`[issuer] issued ${opts.credentialConfigurationId} for ${issuance.user} (status idx ${issuance.status.idx})`)
      return c.json(credential)
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  return { app, entity }
}
