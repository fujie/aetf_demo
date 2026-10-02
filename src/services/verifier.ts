import { emit } from '../common/events.js'
import { randomUUID } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Hono } from 'hono'
import * as jose from 'jose'
import * as x509 from '@peculiar/x509'
import { initializeContext } from '@trustknots/vcknots'
import {
  ClientIdentifier,
  VerifierAuthorizationResponse,
  VerifierClientId,
  VerifierMetadata,
  VerifierRequestObjectId,
  initializeVerifierFlow,
} from '@trustknots/vcknots/verifier'
import { DATA_DIR, verifyWithJwks, writeDataFile } from '../common/keys.js'
import { esc, page, qrSvg, trustChainHtml, escMsg } from '../common/html.js'
import { toErrorResponse } from '../common/vcknots-util.js'
import {
  ATTESTATION_HEADER,
  ATTESTATION_POP_HEADER,
  verifyWalletAttestation,
} from '../common/wallet-attestation.js'
import { type TrustAnchorConfig, resolveEntityMetadata, resolveTrustChain } from '../federation/resolver.js'
import { WALLET_UI_URL } from '../config.js'
import { RP_REGISTRATION_TYP } from './trust-list.js'
import { federationStatusListKeyResolver } from '../status-list/federation-key-resolver.js'
import { StatusType, createStatusListClient } from '../status-list/token-status-list.js'

type Check = { name: string; ok: boolean; detail: string }
type PresentationResult = {
  state: string
  transactionId: string
  createdAt: string
  requestUri: string
  status: 'pending' | 'verified' | 'rejected'
  checks: Check[]
  disclosed?: Record<string, unknown>
}

const REQUESTED_CLAIMS = ['family_name', 'given_name', 'organization', 'enrollment_status']

/** Request-object signing key of the Relying Party Instance (certified by the Access CA). */
const loadOrCreateKey = async () => {
  const keyPath = join(DATA_DIR, 'verifier', 'key.pem')
  let privateKeyPem: string
  if (existsSync(keyPath)) {
    privateKeyPem = readFileSync(keyPath, 'utf-8')
  } else {
    const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
    privateKeyPem = await jose.exportPKCS8(privateKey)
    writeDataFile('verifier/key.pem', privateKeyPem)
  }
  const { d: _d, ...publicJwk } = await jose.exportJWK(await jose.importPKCS8(privateKeyPem, 'ES256', { extractable: true }))
  return { privateKeyPem, signingKey: await jose.importPKCS8(privateKeyPem, 'ES256'), publicJwk }
}

/** Splits a presented SD-JWT (`<jwt>~<disclosure>~...~<kb-jwt>`) and decodes it. */
const decodeSdJwt = (presentation: string) => {
  const parts = presentation.split('~')
  const issuerJwt = parts[0]
  const disclosed: Record<string, unknown> = {}
  for (const d of parts.slice(1)) {
    if (!d || d.split('.').length === 3) continue
    try {
      const arr = JSON.parse(Buffer.from(d, 'base64url').toString('utf-8'))
      if (Array.isArray(arr) && arr.length === 3) disclosed[arr[1]] = arr[2]
    } catch {}
  }
  return { issuerJwt, payload: jose.decodeJwt(issuerJwt), header: jose.decodeProtectedHeader(issuerJwt), disclosed }
}

/**
 * Verifier (OID4VP) built with vcknots.
 *  - registers itself to the Trust List at startup (so that Wallets can trust it)
 *  - verifies the Wallet Attestation sent with the response (Wallet trusted via OpenID Federation)
 *  - verifies the SD-JWT VC + KB-JWT (vcknots), the Issuer via OpenID Federation,
 *    and the revocation status via the Status List (Status List provider trusted via OpenID Federation)
 */
export const createVerifier = async (opts: {
  baseUrl: string
  name: string
  anchors: TrustAnchorConfig[]
  trustListEntityId: string
  vct: string
}) => {
  const { baseUrl } = opts
  const dnsName = new URL(baseUrl).hostname
  const clientId = ClientIdentifier(`x509_san_dns:${dnsName}`)
  const verifierId = VerifierClientId(baseUrl)

  const rpKey = await loadOrCreateKey()
  let verifierFlow: ReturnType<typeof initializeVerifierFlow> | undefined
  let accessCertificate: x509.X509Certificate | undefined
  const flow = () => {
    if (!verifierFlow) throw new Error('not registered at the Registrar yet (no access certificate)')
    return verifierFlow
  }

  const results = new Map<string, PresentationResult>() // by state
  const statusListClient = createStatusListClient(federationStatusListKeyResolver(opts.anchors))

  /**
   * Registration at the Registrar (red "Registration" arrow): obtains a Wallet-Relying Party Access
   * Certificate (ETSI TS 119 411-8) from the Access CA and (re)initialises vcknots with it, so that
   * request objects carry it in `x5c`.
   */
  const registerToTrustList = async () => {
    const { metadata } = await resolveEntityMetadata<{ registration_endpoint: string }>(
      opts.trustListEntityId,
      'trust_list_provider',
      opts.anchors
    )
    const request = await new jose.SignJWT({
      client_id: clientId,
      dns_name: dnsName,
      organization_name: 'Example Student Discount Co., Ltd.',
      organization_identifier: 'NTRJP-1234567890123',
      common_name: opts.name,
      country: 'JP',
      contact_uri: `${baseUrl}/`,
      intended_use: {
        purpose: '学割の適用確認 (在籍確認)',
        credential: opts.vct,
        claims: REQUESTED_CLAIMS,
      },
    })
      .setProtectedHeader({ alg: 'ES256', typ: RP_REGISTRATION_TYP, jwk: rpKey.publicJwk })
      .setAudience(opts.trustListEntityId)
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(rpKey.signingKey)
    const res = await fetch(metadata.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request }),
    })
    if (!res.ok) throw new Error(`registration failed: ${res.status} ${await res.text()}`)
    const { access_certificate } = (await res.json()) as { access_certificate: string }
    accessCertificate = new x509.X509Certificate(access_certificate)

    const context = initializeContext({ debug: true })
    const newFlow = initializeVerifierFlow(context)
    await newFlow.createVerifierMetadata(
      verifierId,
      VerifierMetadata({
        client_name: opts.name,
        vp_formats_supported: {
          'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
        },
      }),
      { privateKey: rpKey.privateKeyPem, certificate: access_certificate, format: 'pem', alg: 'ES256' }
    )
    verifierFlow = newFlow
    console.log(`[verifier] registered ${clientId}; access certificate serial ${accessCertificate.serialNumber} (${accessCertificate.issuer})`)
    emit('Verifier', 'ok', 'Registrar に登録しアクセス証明書 (WRPAC) を取得', `serial ${accessCertificate.serialNumber}`)
  }

  const app = new Hono()

  app.get('/', (c) => {
    const rows = [...results.values()]
      .reverse()
      .map(
        (r) => `<tr><td><a href="/requests/${encodeURIComponent(r.state)}">${esc(r.state.slice(0, 8))}</a></td><td>${esc(r.createdAt)}</td>
        <td>${r.status === 'verified' ? '<span class="ok">検証成功</span>' : r.status === 'rejected' ? '<span class="ng">検証失敗</span>' : '待機中'}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        `Verifier - ${opts.name}`,
        `<section><p>学認 学生証明書 (SD-JWT VC) の提示を要求します。</p>
        <form method="post" action="/requests"><button>提示リクエストを作成</button></form>
        <p class="mut">client_id: <code>${esc(clientId)}</code> / Registrar: <a href="${esc(opts.trustListEntityId)}/">${escMsg(opts.trustListEntityId)}</a></p>
        <p class="mut">Access Certificate (WRPAC): ${accessCertificate ? `<code>${esc(accessCertificate.subject)}</code><br>issuer <code>${esc(accessCertificate.issuer)}</code> serial <code>${esc(accessCertificate.serialNumber)}</code>` : '<span class="ng">未登録</span>'}</p>
        <form method="post" action="/register"><button>Registrar へ登録 / 再登録 (Access Certificate 再発行)</button></form></section>
        <section><h3>履歴</h3><table><tr><th>state</th><th>作成</th><th>結果</th></tr>${rows}</table></section>`
      )
    )
  })

  app.post('/register', async (c) => {
    try {
      await registerToTrustList()
      return c.redirect('/', 303)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${escMsg((e as Error).message)}</pre>`), 500)
    }
  })

  app.post('/requests', async (c) => {
    try {
      const state = randomUUID().replaceAll('-', '')
      const query = {
        dcql_query: {
          credentials: [
            {
              id: 'gakunin_student',
              format: 'dc+sd-jwt',
              meta: { vct_values: [opts.vct] },
              claims: REQUESTED_CLAIMS.map((claim) => ({ path: [claim] })),
            },
          ],
        },
      }
      const { request, transactionId } = await flow().createAuthzRequest(
        verifierId,
        'vp_token',
        clientId,
        'direct_post',
        query,
        true,
        {
          state,
          base_url: baseUrl,
          response_uri: `${baseUrl}/callback`,
          request_uri: `${baseUrl}/request.jwt`,
        }
      )
      const requestUri = `openid4vp:?${Object.entries(request)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v && typeof v === 'object' ? JSON.stringify(v) : String(v))}`)
        .join('&')}`
      emit('Verifier', 'info', `提示リクエストを作成 (${state.slice(0, 8)})`, `DCQL: ${REQUESTED_CLAIMS.join(', ')} / x5c にアクセス証明書`)
      results.set(state, {
        state,
        transactionId,
        createdAt: new Date().toISOString(),
        requestUri,
        status: 'pending',
        checks: [],
      })
      if (c.req.header('Accept')?.includes('application/json')) {
        return c.json({ state, request_uri: requestUri, result_url: `${baseUrl}/requests/${state}` })
      }
      return c.redirect(`/requests/${state}`, 303)
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  app.get('/requests/:state', async (c) => {
    const r = results.get(c.req.param('state'))
    if (!r) return c.json({ error: 'not_found' }, 404)
    if (c.req.header('Accept')?.includes('application/json')) return c.json(r)
    const checks = r.checks
      .map((ch) => `<tr><td>${ch.ok ? '<span class="ok">OK</span>' : '<span class="ng">NG</span>'}</td><td>${esc(ch.name)}</td><td>${ch.detail}</td></tr>`)
      .join('')
    const body =
      r.status === 'pending'
        ? `<section><p>Wallet でこのリクエストを読み取ってください。</p>
           <p><a class="btn" href="${esc(`${WALLET_UI_URL}/present?request=${encodeURIComponent(r.requestUri)}`)}" target="_blank">Web Wallet で開く</a></p>
           ${await qrSvg(r.requestUri)}
           <p>Wallet Instance (CLI) の場合:</p><pre>./wallet-instance present '${esc(r.requestUri)}'</pre>
           <p class="mut">このページは自動更新されます。</p></section>`
        : `<section><h3>${r.status === 'verified' ? '<span class="ok">検証成功</span>' : '<span class="ng">検証失敗</span>'}</h3>
           <table>${checks}</table></section>
           ${r.disclosed ? `<section><h3>開示された属性</h3><pre>${esc(JSON.stringify(r.disclosed, null, 2))}</pre></section>` : ''}`
    return c.html(page(`Verifier - 提示リクエスト ${r.state.slice(0, 8)}`, `${body}<section><a href="/">戻る</a></section>`, { refresh: r.status === 'pending' ? 3 : undefined }))
  })

  app.get('/request.jwt/:id', async (c) => {
    try {
      const id = VerifierRequestObjectId.schema.parse(c.req.param('id'))
      const jar = await flow().findRequestObject(verifierId, id)
      return c.body(jar, 200, { 'Content-Type': 'application/oauth-authz-req+jwt' })
    } catch (e) {
      const { body, status } = toErrorResponse(e)
      return c.json(body, status)
    }
  })

  app.post('/callback', async (c) => {
    const form = await c.req.formData().catch(() => null)
    const state = typeof form?.get('state') === 'string' ? String(form?.get('state')) : ''
    const result = results.get(state)
    if (!form || !result || result.status !== 'pending') {
      return c.json({ error: 'invalid_request', error_description: 'unknown or completed state' }, 400)
    }
    const checks: Check[] = []
    const report = () =>
      checks.forEach((ch) =>
        emit('Verifier', ch.ok ? 'ok' : 'error', `${ch.name}: ${ch.ok ? 'OK' : 'NG'}`, ch.detail.replace(/<br>/g, ' / ').replace(/<[^>]+>/g, '').replace(/&rarr;/g, '→'))
      )
    const fail = (status: 400 | 401 = 400) => {
      result.status = 'rejected'
      result.checks = checks
      report()
      emit('Verifier', 'error', `提示を拒否 (${state.slice(0, 8)})`)
      const last = checks[checks.length - 1]
      const plain = (last?.detail ?? '').replace(/<br>/g, ' / ').replace(/<[^>]+>/g, '').replace(/&rarr;/g, '->').replace(/\s+/g, ' ')
      return c.json({ error: 'access_denied', error_description: `${last?.name}: ${plain}` }, status)
    }

    // 1. Wallet Attestation -> Wallet Provider trusted via OpenID Federation
    try {
      const att = await verifyWalletAttestation(
        c.req.header(ATTESTATION_HEADER),
        c.req.header(ATTESTATION_POP_HEADER),
        baseUrl,
        opts.anchors
      )
      checks.push({
        name: 'Wallet Attestation',
        ok: true,
        detail: `${esc(att.walletName ?? '')} <code>${esc(att.clientId)}</code><br>Wallet Provider: ${trustChainHtml(att.trustChainPath)}<br>Wallet Instance status: ${esc(att.status.statusName)} (Status List idx ${att.status.idx})`,
      })
    } catch (e) {
      checks.push({ name: 'Wallet Attestation', ok: false, detail: escMsg((e as Error).message) })
      return fail(401)
    }

    // 2. VP verification (vcknots: SD-JWT signature, disclosures, KB-JWT nonce/aud)
    let presentation: string
    try {
      const rawVpToken = form.get('vp_token')
      const vpToken = JSON.parse(String(rawVpToken)) as Record<string, string[]>
      const response = VerifierAuthorizationResponse({ vp_token: vpToken, state })
      await flow().verifyPresentations(response, result.transactionId, { isKbJwt: true })
      const first = Object.values(vpToken)[0]
      presentation = Array.isArray(first) ? first[0] : String(first)
      checks.push({ name: 'VP / KB-JWT (vcknots)', ok: true, detail: 'SD-JWT VC と Key Binding JWT を検証しました' })
    } catch (e) {
      checks.push({ name: 'VP / KB-JWT (vcknots)', ok: false, detail: esc(toErrorResponse(e).body.error_description) })
      return fail()
    }
    const sdJwt = decodeSdJwt(presentation)

    // 3. Issuer trusted via OpenID Federation (openid_credential_issuer, signing key in federation metadata)
    try {
      const iss = String(sdJwt.payload.iss)
      const { metadata, chain } = await resolveEntityMetadata<{ jwks?: { keys: jose.JWK[] } }>(
        iss,
        'openid_credential_issuer',
        opts.anchors
      )
      await verifyWithJwks(sdJwt.issuerJwt, metadata.jwks, { typ: 'dc+sd-jwt' })
      if (sdJwt.payload.vct !== opts.vct) throw new Error(`unexpected vct ${String(sdJwt.payload.vct)}`)
      checks.push({ name: 'Issuer (OpenID Federation)', ok: true, detail: trustChainHtml(chain.path) })
    } catch (e) {
      checks.push({ name: 'Issuer (OpenID Federation)', ok: false, detail: escMsg((e as Error).message) })
      return fail()
    }

    // 4. Status check per draft-ietf-oauth-status-list section 8.3 (the Referenced Token itself was
    //    validated in steps 2-3). The Status Issuer is trusted via OpenID Federation.
    try {
      const st = await statusListClient.check(sdJwt.payload as Record<string, unknown>)
      const chain = st.statusIssuer ? await resolveTrustChain(st.statusIssuer, opts.anchors) : undefined
      const detail = `idx=${st.idx} status=0x${st.status.toString(16).padStart(2, '0')} (${st.statusName})
        <br>${escMsg(st.uri)} iat=${new Date(st.token.iat * 1000).toISOString()} ttl=${st.token.ttl ?? '-'}s${st.fromCache ? ' (cached)' : ''}
        <br>Status Issuer: ${chain ? trustChainHtml(chain.path) : '-'}`
      if (st.status !== StatusType.VALID) {
        checks.push({ name: 'Status List', ok: false, detail })
        return fail()
      }
      checks.push({ name: 'Status List', ok: true, detail })
    } catch (e) {
      checks.push({ name: 'Status List', ok: false, detail: escMsg((e as Error).message) })
      return fail()
    }

    result.status = 'verified'
    report()
    emit('Verifier', 'ok', `提示を受理 (${state.slice(0, 8)})`, Object.entries(sdJwt.disclosed).map(([k, v]) => `${k}=${String(v)}`).join(', '))
    result.checks = checks
    result.disclosed = sdJwt.disclosed
    console.log(`[verifier] presentation ${state} verified:`, sdJwt.disclosed)
    return c.json({ redirect_uri: `${baseUrl}/requests/${state}` })
  })

  return { app, registerToTrustList, clientId }
}
