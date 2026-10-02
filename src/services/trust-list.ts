import { createHash, webcrypto } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Context, Hono } from 'hono'
import * as jose from 'jose'
import * as x509 from '@peculiar/x509'
import { DATA_DIR, type SigningKey, jwksOf, writeDataFile } from '../common/keys.js'
import { esc, page } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { createAccessCa, selfSignedCertificate } from '../trust-list/access-ca.js'
import {
  ETSI19602,
  LOTE_MEDIA_TYPE,
  type ListOfTrustedEntities,
  buildWrpacProvidersLoTE,
  signLoTE,
} from '../trust-list/etsi119602.js'

export const RP_REGISTRATION_TYP = 'rp-registration+jwt'
const LOTE_VALIDITY_DAYS = 30
const LOTE_REISSUE_AFTER_MS = 24 * 60 * 60 * 1000

type RegistrationStatus = 'active' | 'suspended' | 'cancelled'
type Registration = {
  clientId: string
  organizationName: string
  organizationIdentifier: string
  commonName: string
  country: string
  dnsName: string
  contactUri: string
  intendedUse?: { purpose?: string; credential?: string; claims?: string[] }
  status: RegistrationStatus
  registeredAt: string
}

/**
 * "Trust List" of the diagram, modelled after the EUDI Wallet ecosystem (ARF 3.5, 6.4, 6.6.3.2):
 *  - Registrar: Relying Parties (Verifiers) register here (red "Registration" arrow)
 *  - Access Certificate Authority (WRPAC Provider): issues a Wallet-Relying Party Access
 *    Certificate (ETSI TS 119 411-8) to each registered RP and publishes a CRL
 *  - LoTE Provider / Scheme Operator: publishes the WRPAC Providers List of Trusted Entities
 *    (ETSI TS 119 602, JAdES-signed JSON) carrying the Access CA certificate as trust anchor
 * Wallet Units validate the LoTE signer through OpenID Federation (`trust_list_provider` metadata).
 */
export const createTrustList = async (opts: {
  entityId: string
  federationKey: SigningKey
  /** LoTE (JAdES) signing key of the scheme operator. */
  signingKey: SigningKey
  authorityHints: string[]
}) => {
  const { entityId } = opts
  const loteUri = `${entityId}/lote/wrpac-providers.jwt`
  const schemeOperator = 'GakuNin Trust List Scheme Operator (NII)'
  const postalAddress = {
    lang: 'en',
    StreetAddress: '2-1-2 Hitotsubashi, Chiyoda-ku',
    Locality: 'Tokyo',
    PostalCode: '101-8430',
    Country: 'JP',
  }

  const accessCa = await createAccessCa({
    baseUrl: entityId,
    name: 'GakuNin',
    country: 'JP',
    organizationIdentifier: 'NTRJP-0000000000000',
  })

  // Scheme operator signing certificate for the JAdES signature (key = federation-published jwks)
  const loteSignerPublicKey = (await webcrypto.subtle.importKey('jwk', opts.signingKey.publicJwk as JsonWebKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])) as CryptoKey
  const loteSignerCert = await selfSignedCertificate({
    name: `C=JP, O=NII, CN=${schemeOperator}`,
    privateKey: opts.signingKey.privateKey,
    publicKey: loteSignerPublicKey,
  })

  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: schemeOperator },
      trust_list_provider: {
        scheme_operator_name: schemeOperator,
        lote_locations: [{ lote_type: ETSI19602.WRPAC_PROVIDERS_LOTE_TYPE, location: loteUri, mime_type: LOTE_MEDIA_TYPE }],
        registration_endpoint: `${entityId}/registrar/registrations`,
        lote_signing_alg_values_supported: ['ES256'],
        jwks: jwksOf(opts.signingKey),
      },
    },
  })

  // ---- Registrar state ------------------------------------------------------------------------
  const regPath = join(DATA_DIR, 'trust-list', 'registrations.json')
  const registrations = new Map<string, Registration>(
    existsSync(regPath) ? (JSON.parse(readFileSync(regPath, 'utf-8')) as Registration[]).map((r) => [r.clientId, r]) : []
  )
  const persistRegistrations = () => writeDataFile('trust-list/registrations.json', [...registrations.values()])

  // ---- LoTE publication ------------------------------------------------------------------------
  const seqPath = join(DATA_DIR, 'trust-list', 'lote-sequence.json')
  let sequence: { number: number; contentHash: string } = existsSync(seqPath)
    ? JSON.parse(readFileSync(seqPath, 'utf-8'))
    : { number: 0, contentHash: '' }
  let published: { jwt: string; lote: ListOfTrustedEntities; issuedAt: number } | undefined

  const publishLoTE = async () => {
    const now = new Date()
    const build = (seq: number) =>
      buildWrpacProvidersLoTE({
        sequenceNumber: seq,
        issued: now,
        nextUpdate: new Date(now.getTime() + LOTE_VALIDITY_DAYS * 24 * 3600 * 1000),
        schemeOperatorName: schemeOperator,
        schemeOperatorAddress: postalAddress,
        schemeOperatorElectronicAddress: entityId,
        schemeName: 'GakuNin WRPAC Providers List',
        schemeInformationUri: `${entityId}/`,
        schemeTerritory: 'JP',
        distributionPoint: loteUri,
        providers: [
          {
            name: 'GakuNin WRP Access CA',
            tradeName: 'NII',
            informationUri: `${entityId}/`,
            electronicAddress: entityId,
            postalAddress,
            caCertificateDer: new Uint8Array(accessCa.caCert.rawData),
            crlUri: accessCa.crlUri,
            caIssuersUri: accessCa.caIssuersUri,
          },
        ],
      })
    // LoTESequenceNumber is incremented whenever the trusted entities change
    const hash = createHash('sha256').update(JSON.stringify(build(0).TrustedEntitiesList)).digest('hex')
    if (hash !== sequence.contentHash) {
      sequence = { number: sequence.number + 1, contentHash: hash }
      writeDataFile('trust-list/lote-sequence.json', sequence)
    }
    const lote = build(sequence.number)
    const jwt = await signLoTE(lote, { privateKey: opts.signingKey.privateKey, certificateDer: new Uint8Array(loteSignerCert.rawData) }, now)
    published = { jwt, lote, issuedAt: now.getTime() }
    return published
  }
  const currentLoTE = async () =>
    !published || Date.now() - published.issuedAt > LOTE_REISSUE_AFTER_MS ? publishLoTE() : published

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  // ---- UI --------------------------------------------------------------------------------------
  app.get('/', async (c) => {
    const { lote } = await currentLoTE()
    const certsOf = (clientId: string) => accessCa.issued.filter((i) => i.clientId === clientId)
    const actions = (r: Registration) => {
      const btn = (action: string, label: string) =>
        `<form style="display:inline" method="post" action="/registrar/registrations/${encodeURIComponent(r.clientId)}/${action}"><button>${label}</button></form>`
      if (r.status === 'active') return `${btn('suspend', '一時停止')} ${btn('cancel', '登録取消')}`
      if (r.status === 'suspended') return `${btn('resume', '再開')} ${btn('cancel', '登録取消')}`
      return ''
    }
    const rows = [...registrations.values()]
      .map(
        (r) => `<tr><td><code>${esc(r.clientId)}</code></td><td>${esc(r.organizationName)}<br><span class="mut">${esc(r.organizationIdentifier)}</span></td>
        <td>${esc(r.intendedUse?.purpose ?? '')}<br><span class="mut">${esc((r.intendedUse?.claims ?? []).join(', '))}</span></td>
        <td>${certsOf(r.clientId)
          .map((i) => `<code>${esc(i.serial)}</code> ${i.revoked ? `<span class="ng">revoked (${esc(x509.X509CrlReason[i.revoked.reason])})</span>` : '<span class="ok">valid</span>'}`)
          .join('<br>')}</td>
        <td class="${r.status === 'active' ? 'ok' : 'ng'}">${esc(r.status)}</td><td>${actions(r)}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        'Trust List (Registrar / Access CA / LoTE Provider)',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <p>LoTE (ETSI TS 119 602): <a href="/lote/wrpac-providers.jwt">wrpac-providers.jwt</a> (JAdES) /
        <a href="/lote/wrpac-providers.json">JSON</a> / Access CA: <a href="/ca/cert">certificate</a>, <a href="/ca/crl">CRL</a></p></section>
        <section><h3>Registrar: 登録済み Relying Party</h3>
        <table><tr><th>client_id</th><th>組織</th><th>利用目的 / 要求属性</th><th>Access Certificate (WRPAC)</th><th>状態</th><th></th></tr>${rows}</table></section>
        <section><h3>WRPAC Providers LoTE (LoTESequenceNumber ${lote.ListAndSchemeInformation.LoTESequenceNumber})</h3>
        <pre>${esc(JSON.stringify(lote, null, 2))}</pre></section>`
      )
    )
  })

  // ---- LoTE distribution -----------------------------------------------------------------------
  app.get('/lote/wrpac-providers.jwt', async (c) =>
    c.body((await currentLoTE()).jwt, 200, { 'Content-Type': LOTE_MEDIA_TYPE, 'Access-Control-Allow-Origin': '*' })
  )
  app.get('/lote/wrpac-providers.json', async (c) => c.json({ LoTE: (await currentLoTE()).lote }))

  // ---- Access CA -------------------------------------------------------------------------------
  app.get('/ca/cert', (c) => c.body(accessCa.caCert.toString('pem'), 200, { 'Content-Type': 'application/pem-certificate-chain' }))
  app.get('/ca/crl', async (c) => c.body(await accessCa.crl(), 200, { 'Content-Type': 'application/pkix-crl', 'Cache-Control': 'no-store' }))

  // ---- Registrar -------------------------------------------------------------------------------
  /**
   * Relying Party registration. The request is a JWS signed with the key to be certified (proof of
   * possession), carrying that key as `jwk` in the protected header. On success an access
   * certificate is issued by the Access CA. (Identity proofing of the RP is out of scope.)
   */
  app.post('/registrar/registrations', async (c) => {
    const body = await c.req.json<{ request?: string }>().catch(() => ({}) as { request?: string })
    let payload: jose.JWTPayload
    let publicJwk: jose.JWK
    try {
      const header = jose.decodeProtectedHeader(String(body.request))
      if (!header.jwk) throw new Error('jwk header required')
      publicJwk = header.jwk
      ;({ payload } = await jose.jwtVerify(String(body.request), await jose.importJWK(publicJwk, 'ES256'), {
        typ: RP_REGISTRATION_TYP,
        audience: entityId,
        maxTokenAge: '5m',
      }))
    } catch (e) {
      return c.json({ error: 'invalid_request', error_description: (e as Error).message }, 400)
    }
    const p = payload as Record<string, unknown>
    for (const k of ['client_id', 'dns_name', 'organization_name', 'organization_identifier', 'contact_uri']) {
      if (typeof p[k] !== 'string' || !p[k]) return c.json({ error: 'invalid_request', error_description: `${k} required` }, 400)
    }
    const clientId = String(p.client_id)
    if (clientId !== `x509_san_dns:${p.dns_name}`) {
      return c.json({ error: 'invalid_request', error_description: 'client_id must be x509_san_dns:<dns_name>' }, 400)
    }
    // a suspended RP cannot obtain new access certificates; a cancelled one may register again
    if (registrations.get(clientId)?.status === 'suspended') {
      return c.json({ error: 'access_denied', error_description: 'registration is suspended' }, 403)
    }
    const reg: Registration = {
      clientId,
      organizationName: String(p.organization_name),
      organizationIdentifier: String(p.organization_identifier),
      commonName: String(p.common_name ?? p.organization_name),
      country: String(p.country ?? 'JP'),
      dnsName: String(p.dns_name),
      contactUri: String(p.contact_uri),
      intendedUse: p.intended_use as Registration['intendedUse'],
      status: 'active',
      registeredAt: new Date().toISOString(),
    }
    registrations.set(clientId, reg)
    persistRegistrations()

    const publicKey = (await webcrypto.subtle.importKey('jwk', publicJwk as JsonWebKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])) as CryptoKey
    const cert = await accessCa.issue({ ...reg, publicKey })
    console.log(`[trust-list] registered ${clientId}; WRPAC serial ${cert.serialNumber}`)
    return c.json(
      {
        client_id: clientId,
        status: reg.status,
        access_certificate: cert.toString('pem'),
        // x5c for the presentation request: access certificate + intermediates, excluding the trust anchor
        x5c: [Buffer.from(cert.rawData).toString('base64')],
      },
      201
    )
  })

  const transition = (to: RegistrationStatus) => async (c: Context) => {
    const reg = registrations.get(decodeURIComponent(c.req.param('id') ?? ''))
    if (reg && reg.status !== 'cancelled') {
      if (to === 'suspended') accessCa.revokeAllOf(reg.clientId, x509.X509CrlReason.certificateHold)
      if (to === 'active' && reg.status === 'suspended') accessCa.releaseHold(reg.clientId)
      if (to === 'cancelled') {
        accessCa.releaseHold(reg.clientId)
        accessCa.revokeAllOf(reg.clientId, x509.X509CrlReason.cessationOfOperation)
      }
      reg.status = to
      persistRegistrations()
    }
    return c.redirect('/', 303)
  }
  app.post('/registrar/registrations/:id{.+}/suspend', transition('suspended'))
  app.post('/registrar/registrations/:id{.+}/resume', transition('active'))
  app.post('/registrar/registrations/:id{.+}/cancel', transition('cancelled'))

  await publishLoTE()
  return { app, entity }
}
