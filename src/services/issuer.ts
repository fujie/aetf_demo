import { emit } from '../common/events.js'
import { type Bi, bi, pick, t } from '../common/i18n.js'
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
import { type SigningKey, jwksOf, readDataFile, signJwt, verifyWithJwks, writeDataFile } from '../common/keys.js'
import { esc, page, qrSvg, trustChainHtml, escMsg } from '../common/html.js'
import { toErrorResponse } from '../common/vcknots-util.js'
import {
  ATTESTATION_HEADER,
  ATTESTATION_POP_HEADER,
  WalletAttestationError,
  verifyWalletAttestation,
} from '../common/wallet-attestation.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'
import { WALLET_UI_URL } from '../config.js'
import { StatusType, statusTypeName } from '../status-list/token-status-list.js'
import { createOidcRp } from '../common/oidc-rp.js'
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
  /** Current Status Type set at the Status List (0x00 VALID, 0x01 INVALID, 0x02 SUSPENDED). */
  statusValue?: number
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

/** Claims of the credential with their display names (Japanese, English). */
const credentialClaims = [
  ['family_name', '姓', 'Family name'],
  ['given_name', '名', 'Given name'],
  ['name', '氏名', 'Name'],
  ['eduPersonPrincipalName', 'ePPN', 'ePPN'],
  ['eduPersonAffiliation', '所属種別', 'Affiliation'],
  ['organization', '所属機関', 'Organization'],
  ['student_number', '学籍番号', 'Student number'],
  ['department', '学部・学科', 'Department'],
  ['enrollment_status', '在籍状況', 'Enrollment status'],
] as const

/**
 * GakuNin Issuer: OID4VCI Credential Issuer + Authorization Server built with vcknots.
 * Configured as a GakuNin SP: it authenticates users at the Institution IdP and obtains attributes
 * from the Attribute Provider, trusting both through OpenID Federation.
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
          display: [
            { name: '学認 学生証明書', locale: 'ja-JP', background_color: '#155e86', text_color: '#FFFFFF' },
            { name: 'GakuNin Student Credential', locale: 'en-US', background_color: '#155e86', text_color: '#FFFFFF' },
          ],
          claims: [
            ...credentialClaims.map(([path, ja, en]) => ({
              path: [path],
              display: [
                { name: ja, locale: 'ja-JP' },
                { name: en, locale: 'en-US' },
              ],
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

  const statusListAggregationEndpoint = `${opts.statusListEntityId}/aggregation?issuer=${encodeURIComponent(baseUrl)}`

  // ---- OpenID Federation ------------------------------------------------------------------
  const entity = createFederationEntity({
    entityId: baseUrl,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'GakuNin Issuer (Example University)' },
      openid_credential_issuer: {
        ...(issuerMetadata as unknown as Record<string, unknown>),
        ...(credentialJwks ? { jwks: credentialJwks } : {}),
      },
      oauth_authorization_server: {
        issuer: baseUrl,
        token_endpoint: `${baseUrl}/token`,
        token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
        // draft-ietf-oauth-status-list section 9.1
        status_list_aggregation_endpoint: statusListAggregationEndpoint,
      },
      openid_relying_party: {
        client_name: 'GakuNin Issuer',
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
  // by pre-authorized code; persisted under .data so that the admin list (and status changes of
  // issued credentials) survive restarts
  const ISSUANCE_STORE = 'issuer/issuances.json'
  const issuances = new Map<string, Issuance>(
    readDataFile<Issuance[]>(ISSUANCE_STORE, []).map((i) => [i.preAuthorizedCode, i])
  )
  const persistIssuances = () => writeDataFile(ISSUANCE_STORE, [...issuances.values()])
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
          t('学認Issuer', 'GakuNin Issuer'),
          `<section><p>${t('学認 学生証明書 (SD-JWT VC) を発行します。まず所属機関の IdP でログインしてください。', 'Issues the GakuNin student credential (SD-JWT VC). Log in at your institution IdP first.')}</p>
          <p><a class="btn" href="/login">${t('機関IdPでログイン', 'Log in with the Institution IdP')}</a></p></section>
          <section class="mut">Entity ID: <code>${esc(baseUrl)}</code> /
          <a href="/.well-known/openid-federation">Entity Configuration</a> /
          <a href="/.well-known/openid-credential-issuer">Credential Issuer Metadata</a> /
          <a href="/admin">${t('発行済みクレデンシャル管理', 'Issued credentials')}</a></section>`
        )
      )
    }
    const rows = credentialClaims
      .map(([k, ja, en]) => `<tr><th>${esc(t(ja, en))}</th><td><code>${esc(k)}</code></td><td>${esc(JSON.stringify(s.claims?.[k]))}</td></tr>`)
      .join('')
    return c.html(
      page(
        t('学認Issuer', 'GakuNin Issuer'),
        `<section><h3>${t('取得した属性', 'Obtained attributes')}</h3><table>${rows}</table>
        <p class="mut">${t('機関IdP', 'Institution IdP')}: ${trustChainHtml(s.idpPath ?? [])}<br>${t('属性Provider', 'Attribute Provider')}: ${trustChainHtml(s.apPath ?? [])}</p></section>
        <section><form method="post" action="/offer"><button>${t('Credential Offer を作成', 'Create Credential Offer')}</button></form></section>`
      )
    )
  })

  const oidc = createOidcRp({ entityId: baseUrl, rpKey: opts.rpKey, anchors: opts.anchors, scope: 'openid profile email gakunin' })

  app.get('/login', async (c) => {
    try {
      return c.redirect(await oidc.authorizationUrl(opts.idpEntityId), 302)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${escMsg((e as Error).message)}</pre>`), 500)
    }
  })

  app.get('/oidc/callback', async (c) => {
    const s = session(c)
    try {
      // 1. Institution IdP trusted via OpenID Federation; code redeemed with private_key_jwt (src/common/oidc-rp.ts)
      const login = await oidc.handleCallback(c.req.query())
      const idToken = login.idToken
      const idp = { chain: { path: login.opTrustChain } }
      const now = Math.floor(Date.now() / 1000)

      // 2. Fetch additional attributes from the Attribute Provider (also trusted via federation)
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
      emit(
        '学認Issuer',
        'ok',
        bi(
          `${String(idToken.sub)} が機関IdPでログイン、属性Providerから属性を取得`,
          `${String(idToken.sub)} logged in with the Institution IdP; attributes fetched from the Attribute Provider`
        ),
        bi(
          `IdP: ${idp.chain.path.join(' → ')} / 属性Provider: ${ap.chain.path.join(' → ')}`,
          `IdP: ${idp.chain.path.join(' → ')} / Attribute Provider: ${ap.chain.path.join(' → ')}`
        )
      )
      s.idpPath = idp.chain.path
      s.apPath = ap.chain.path
      return c.redirect('/', 302)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${escMsg((e as Error).message)}</pre>`), 500)
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
      persistIssuances()
      const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`
      emit(
        '学認Issuer',
        'info',
        bi(`Credential Offer を作成 (${String(s.claims.eduPersonPrincipalName)})`, `Created a Credential Offer (${String(s.claims.eduPersonPrincipalName)})`),
        'Pre-Authorized Code Flow (vcknots)'
      )
      return c.html(
        page(
          'Credential Offer',
          `<section><p>${t(
            `Wallet でこの Credential Offer を読み取ってください (有効期限 ${PRE_CODE_TTL_SEC / 60} 分)。`,
            `Scan this Credential Offer with the wallet (valid for ${PRE_CODE_TTL_SEC / 60} minutes).`
          )}</p>
          <p><a class="btn" href="${esc(`${WALLET_UI_URL}/receive?offer=${encodeURIComponent(offerUri)}`)}" target="_blank">${t('Web Wallet で開く', 'Open in Web Wallet')}</a></p>
          ${await qrSvg(offerUri)}
          <p>${t('Wallet Instance (CLI) の場合', 'With the Wallet Instance CLI')}:</p>
          <pre id="cmd">./wallet-instance receive '${esc(offerUri)}'</pre>
          <p class="mut">Offer URI:</p><pre id="offer">${esc(offerUri)}</pre></section>
          <section><a href="/">${t('戻る', 'Back')}</a> / <a href="/admin">${t('発行済みクレデンシャル管理', 'Issued credentials')}</a></section>`
        )
      )
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  const STATUS_ACTIONS: Record<number, [label: Bi, target: number][]> = {
    [StatusType.VALID]: [
      [bi('一時停止 (SUSPENDED)', 'Suspend (SUSPENDED)'), StatusType.SUSPENDED],
      [bi('失効 (INVALID)', 'Revoke (INVALID)'), StatusType.INVALID],
    ],
    [StatusType.SUSPENDED]: [
      [bi('再開 (VALID)', 'Reinstate (VALID)'), StatusType.VALID],
      [bi('失効 (INVALID)', 'Revoke (INVALID)'), StatusType.INVALID],
    ],
    [StatusType.INVALID]: [],
  }

  app.get('/admin', (c) => {
    const rows = [...issuances.values()]
      .map((i) => {
        const value = i.statusValue ?? StatusType.VALID
        const actions = (STATUS_ACTIONS[value] ?? [])
          .map(
            ([label, target]) =>
              `<form style="display:inline" method="post" action="/admin/status"><input type="hidden" name="code" value="${esc(i.preAuthorizedCode)}"><input type="hidden" name="status" value="${target}"><button>${esc(pick(label))}</button></form>`
          )
          .join(' ')
        return `<tr><td>${esc(i.user)}</td><td>${esc(i.createdAt)}</td><td>${esc(i.issuedAt ?? t('未受領', 'not received'))}</td>
        <td>${i.walletClientId ? `<code>${esc(i.walletClientId)}</code><br><span class="mut">${trustChainHtml(i.walletProviderPath ?? [])}</span>` : ''}</td>
        <td>${i.status ? `${escMsg(i.status.uri)}<br>idx=${i.status.idx}` : ''}</td>
        <td>${i.status ? `<span class="${value === StatusType.VALID ? 'ok' : 'ng'}">${esc(statusTypeName(value))}</span> ${actions}` : ''}</td></tr>`
      })
      .join('')
    return c.html(
      page(
        t('学認Issuer - 発行済みクレデンシャル', 'GakuNin Issuer - issued credentials'),
        `<section><table><tr><th>${t('ユーザー', 'User')}</th><th>${t('Offer作成', 'Offer created')}</th><th>${t('発行', 'Issued')}</th><th>Wallet Instance</th><th>Status List</th><th>${t('状態', 'Status')}</th></tr>${rows}</table></section>
        <section class="mut">Status List Aggregation: <a href="${esc(statusListAggregationEndpoint)}">${esc(statusListAggregationEndpoint)}</a></section>
        <section><a href="/">${t('戻る', 'Back')}</a></section>`
      )
    )
  })

  /** Updates the Token Status List entry of an issued credential at the Status List provider. */
  app.post('/admin/status', async (c) => {
    const form = await c.req.parseBody()
    const issuance = issuances.get(String(form.code))
    const target = Number(form.status)
    const allowed = (STATUS_ACTIONS[issuance?.statusValue ?? StatusType.VALID] ?? []).some(([, t]) => t === target)
    if (issuance?.status && allowed) {
      const res = await fetch(`${issuance.status.uri}/entries/${issuance.status.idx}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${opts.statusListApiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: target }),
      })
      if (res.ok) {
        issuance.statusValue = target
        persistIssuances()
        emit(
          '学認Issuer',
          target === StatusType.VALID ? 'ok' : 'info',
          bi(`${issuance.user} のクレデンシャルを ${statusTypeName(target)} に変更`, `Set the credential of ${issuance.user} to ${statusTypeName(target)}`),
          `Status List idx ${issuance.status.idx}`
        )
      }
      else console.warn('[issuer] status update failed', res.status, await res.text())
    }
    return c.redirect('/admin', 303)
  })

  // ---- OID4VCI / OAuth endpoints ----------------------------------------------------------
  app.get('/.well-known/openid-credential-issuer', async (c) =>
    c.json(await issuerFlow.findIssuerMetadata(issuerId))
  )
  app.get('/.well-known/oauth-authorization-server', async (c) =>
    c.json({
      ...(await authzFlow.findAuthzServerMetadata(authzId)),
      status_list_aggregation_endpoint: statusListAggregationEndpoint,
    })
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
        emit('学認Issuer', 'error', bi('Token リクエストを拒否: Wallet Attestation が無効', 'Token request rejected: invalid Wallet Attestation'), e.message)
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
        persistIssuances()
      }
      console.log(`[issuer] access token issued to wallet ${attestation.clientId} (WP chain: ${attestation.trustChainPath.join(' -> ')})`)
      emit('学認Issuer', 'ok', bi('Wallet Attestation を検証しアクセストークンを発行', 'Verified the Wallet Attestation and issued an access token'), `${attestation.walletName ?? ''} ${attestation.clientId} / Wallet Provider: ${attestation.trustChainPath.join(' → ')} / Wallet Instance status: ${attestation.status.statusName}`)
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
        issuance.statusValue = StatusType.VALID
      }

      const credential = await issuerFlow.issueCredential(issuerId, CredentialRequest(await c.req.json()), {
        authorizationContext,
        alg: 'ES256',
        claims: { ...issuance.claims, status: { status_list: issuance.status } },
        proofJwt: { usePreAuth: true },
      })
      issuance.issuedAt = new Date().toISOString()
      persistIssuances()
      console.log(`[issuer] issued ${opts.credentialConfigurationId} for ${issuance.user} (status idx ${issuance.status.idx})`)
      emit('学認Issuer', 'ok', bi(`SD-JWT VC を発行 (${issuance.user})`, `Issued an SD-JWT VC (${issuance.user})`), `${opts.credentialConfigurationId}, Status List idx ${issuance.status.idx}`)
      return c.json(credential)
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  return { app, entity }
}
