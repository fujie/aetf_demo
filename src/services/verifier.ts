import { randomUUID, webcrypto } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { inflateSync } from 'node:zlib'
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
import { esc, page, qrSvg, trustChainHtml } from '../common/html.js'
import { toErrorResponse } from '../common/vcknots-util.js'
import {
  ATTESTATION_HEADER,
  ATTESTATION_POP_HEADER,
  verifyWalletAttestation,
} from '../common/wallet-attestation.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'
import { STATUS_LIST_TYP } from './status-list.js'

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

/** Self-signed ES256 certificate for request-object signing (client_id x509_san_dns:<host>). */
const loadOrCreateCertificate = async (dnsName: string) => {
  const dir = join(DATA_DIR, 'verifier')
  const keyPath = join(dir, 'key.pem')
  const certPath = join(dir, 'cert.pem')
  if (existsSync(keyPath) && existsSync(certPath)) {
    return { privateKey: readFileSync(keyPath, 'utf-8'), certificate: readFileSync(certPath, 'utf-8') }
  }
  x509.cryptoProvider.set(webcrypto as unknown as Crypto)
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
  const keys = await webcrypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: Date.now().toString(16),
    name: `CN=${dnsName}, O=Prototype Verifier`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    signingAlgorithm: alg,
    keys: keys as unknown as CryptoKeyPair,
    extensions: [
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: dnsName }]),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyCertSign, true),
      new x509.BasicConstraintsExtension(true, undefined, true),
    ],
  })
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)
  const privateKey = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(pkcs8).toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----\n`
  const certificate = cert.toString('pem')
  writeDataFile('verifier/key.pem', privateKey)
  writeDataFile('verifier/cert.pem', certificate)
  return { privateKey, certificate }
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

  const context = initializeContext({ debug: true })
  const verifierFlow = initializeVerifierFlow(context)
  const { privateKey, certificate } = await loadOrCreateCertificate(dnsName)
  await verifierFlow.createVerifierMetadata(
    verifierId,
    VerifierMetadata({
      client_name: opts.name,
      vp_formats_supported: {
        'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
      },
    }),
    { privateKey, certificate, format: 'pem', alg: 'ES256' }
  )

  const results = new Map<string, PresentationResult>() // by state

  /** Registration to the Trust List (red "Registration" arrow in the diagram). */
  const registerToTrustList = async () => {
    const { metadata } = await resolveEntityMetadata<{ registration_endpoint: string }>(
      opts.trustListEntityId,
      'trust_list_provider',
      opts.anchors
    )
    const der = new x509.X509Certificate(certificate).rawData
    const res = await fetch(metadata.registration_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: clientId,
        name: opts.name,
        x5c: [Buffer.from(der).toString('base64')],
        response_uri_origin: baseUrl,
      }),
    })
    if (!res.ok) throw new Error(`trust list registration failed: ${res.status} ${await res.text()}`)
    console.log(`[verifier] registered ${clientId} to Trust List ${opts.trustListEntityId}`)
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
        <p class="mut">client_id: <code>${esc(clientId)}</code> (Trust List: <a href="${esc(opts.trustListEntityId)}/">${esc(opts.trustListEntityId)}</a>)</p>
        <form method="post" action="/register"><button>Trust List へ登録 / 再登録</button></form></section>
        <section><h3>履歴</h3><table><tr><th>state</th><th>作成</th><th>結果</th></tr>${rows}</table></section>`
      )
    )
  })

  app.post('/register', async (c) => {
    try {
      await registerToTrustList()
      return c.redirect('/', 303)
    } catch (e) {
      return c.html(page('Error', `<pre class="ng">${esc((e as Error).message)}</pre>`), 500)
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
              claims: [
                { path: ['family_name'] },
                { path: ['given_name'] },
                { path: ['organization'] },
                { path: ['enrollment_status'] },
              ],
            },
          ],
        },
      }
      const { request, transactionId } = await verifierFlow.createAuthzRequest(
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
        ? `<section><p>Wallet でこのリクエストを読み取ってください。</p>${await qrSvg(r.requestUri)}
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
      const jar = await verifierFlow.findRequestObject(verifierId, id)
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
    const fail = (status: 400 | 401 = 400) => {
      result.status = 'rejected'
      result.checks = checks
      const last = checks[checks.length - 1]
      return c.json({ error: 'access_denied', error_description: `${last?.name}: ${last?.detail}` }, status)
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
        detail: `${esc(att.walletName ?? '')} <code>${esc(att.clientId)}</code><br>Wallet Provider: ${trustChainHtml(att.trustChainPath)}`,
      })
    } catch (e) {
      checks.push({ name: 'Wallet Attestation', ok: false, detail: esc((e as Error).message) })
      return fail(401)
    }

    // 2. VP verification (vcknots: SD-JWT signature, disclosures, KB-JWT nonce/aud)
    let presentation: string
    try {
      const rawVpToken = form.get('vp_token')
      const vpToken = JSON.parse(String(rawVpToken)) as Record<string, string[]>
      const response = VerifierAuthorizationResponse({ vp_token: vpToken, state })
      await verifierFlow.verifyPresentations(response, result.transactionId, { isKbJwt: true })
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
      checks.push({ name: 'Issuer (OpenID Federation)', ok: false, detail: esc((e as Error).message) })
      return fail()
    }

    // 4. Revocation check with the Token Status List (Status List provider trusted via OpenID Federation)
    try {
      const ref = (sdJwt.payload.status as { status_list?: { idx: number; uri: string } } | undefined)?.status_list
      if (!ref) throw new Error('credential has no status_list reference')
      const res = await fetch(ref.uri, { headers: { Accept: 'application/statuslist+jwt' } })
      if (!res.ok) throw new Error(`status list fetch failed: ${res.status}`)
      const token = (await res.text()).trim()
      const slIss = String(jose.decodeJwt(token).iss)
      if (!ref.uri.startsWith(`${slIss}/`)) throw new Error('status list uri is not hosted by its issuer')
      const { metadata, chain } = await resolveEntityMetadata<{ jwks?: { keys: jose.JWK[] } }>(
        slIss,
        'status_list_provider',
        opts.anchors
      )
      const { payload } = await verifyWithJwks(token, metadata.jwks, { typ: STATUS_LIST_TYP, subject: ref.uri })
      const sl = payload.status_list as { bits: number; lst: string }
      const bytes = inflateSync(Buffer.from(sl.lst, 'base64url'))
      const perByte = 8 / sl.bits
      const value = (bytes[Math.floor(ref.idx / perByte)] >> ((ref.idx % perByte) * sl.bits)) & ((1 << sl.bits) - 1)
      if (value !== 0) {
        checks.push({ name: 'Status List', ok: false, detail: `idx=${ref.idx} status=${value} (INVALID / 失効済み)` })
        return fail()
      }
      checks.push({ name: 'Status List', ok: true, detail: `idx=${ref.idx} status=0 (VALID)<br>Status List: ${trustChainHtml(chain.path)}` })
    } catch (e) {
      checks.push({ name: 'Status List', ok: false, detail: esc((e as Error).message) })
      return fail()
    }

    result.status = 'verified'
    result.checks = checks
    result.disclosed = sdJwt.disclosed
    console.log(`[verifier] presentation ${state} verified:`, sdJwt.disclosed)
    return c.json({ redirect_uri: `${baseUrl}/requests/${state}` })
  })

  return { app, registerToTrustList, clientId }
}
