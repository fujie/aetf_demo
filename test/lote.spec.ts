import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { Ajv } from 'ajv'
import addFormatsModule from 'ajv-formats'
import * as jose from 'jose'
import { selfSignedCertificate } from '../src/trust-list/access-ca.js'
import { ETSI19602, buildWrpacProvidersLoTE, signLoTE } from '../src/trust-list/etsi119602.js'

// ETSI TS 119 602 JSON schema (copied from eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2,
// originally https://forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities)
const schema = JSON.parse(readFileSync(new URL('./fixtures/1960201_json_schema.json', import.meta.url), 'utf-8'))
const addFormats = addFormatsModule as unknown as (ajv: Ajv) => Ajv
const newAjv = (opts: ConstructorParameters<typeof Ajv>[0] = {}) => {
  const ajv = addFormats(new Ajv({ strict: false, ...opts }))
  // The ETSI schema references an external RFC 7517 JWK schema (used only by PublicKeyValues)
  ajv.addSchema({ $id: 'rfcs/rfc7517.json', definitions: { jwk: { type: 'object', required: ['kty'] } } })
  return ajv
}

const makeLoTE = async () => {
  const keys = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const cert = await selfSignedCertificate({ name: 'CN=Test', privateKey: keys.privateKey, publicKey: keys.publicKey })
  const address = { lang: 'en', StreetAddress: 'Street 1', Locality: 'Tokyo', Country: 'JP' }
  const lote = buildWrpacProvidersLoTE({
    sequenceNumber: 3,
    issued: new Date('2026-10-01T00:00:00Z'),
    nextUpdate: new Date('2026-10-31T00:00:00Z'),
    schemeOperatorName: 'Operator',
    schemeOperatorAddress: address,
    schemeOperatorElectronicAddress: 'https://operator.example',
    schemeName: 'Scheme',
    schemeInformationUri: 'https://operator.example/scheme',
    schemeTerritory: 'JP',
    distributionPoint: 'https://operator.example/lote.jwt',
    providers: [
      {
        name: 'Access CA',
        informationUri: 'https://ca.example',
        electronicAddress: 'https://ca.example',
        postalAddress: address,
        caCertificateDer: new Uint8Array(cert.rawData),
        crlUri: 'https://ca.example/crl',
        caIssuersUri: 'https://ca.example/cert',
      },
    ],
  })
  return { lote, keys, cert }
}

test('WRPAC Providers LoTE validates against the ETSI TS 119 602 JSON schema', async () => {
  const { lote } = await makeLoTE()
  const ajv = newAjv({ allErrors: true })
  const validate = ajv.compile(schema)
  const ok = validate({ LoTE: lote })
  assert.ok(ok, JSON.stringify(validate.errors, null, 2))
  assert.equal(lote.ListAndSchemeInformation.LoTEType, ETSI19602.WRPAC_PROVIDERS_LOTE_TYPE)
  const svcTypes = lote.TrustedEntitiesList?.[0].TrustedEntityServices.map((s) => s.ServiceInformation.ServiceTypeIdentifier)
  assert.deepEqual(svcTypes, [ETSI19602.SVC_TYPE_WRPAC_ISSUANCE, ETSI19602.SVC_TYPE_WRPAC_REVOCATION])
})

test('schema rejects a LoTE missing required scheme information', () => {
  const ajv = newAjv()
  assert.equal(ajv.compile(schema)({ LoTE: { ListAndSchemeInformation: { LoTEVersionIdentifier: 1 } } }), false)
})

test('JAdES compact signature: x5c / x5t#S256 / sigT (crit) and payload {LoTE}', async () => {
  const { lote, keys, cert } = await makeLoTE()
  const jws = await signLoTE(lote, { privateKey: keys.privateKey, certificateDer: new Uint8Array(cert.rawData) })
  const header = jose.decodeProtectedHeader(jws)
  assert.equal(header.alg, 'ES256')
  assert.deepEqual(header.crit, ['sigT'])
  assert.match(String(header.sigT), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  assert.equal(header.x5c?.[0], Buffer.from(cert.rawData).toString('base64'))
  const { payload } = await jose.compactVerify(jws, keys.publicKey, { crit: { sigT: true } })
  assert.deepEqual(JSON.parse(new TextDecoder().decode(payload)), { LoTE: lote })
  // a verifier that does not understand sigT must reject it (RFC 7515 crit)
  await assert.rejects(jose.compactVerify(jws, keys.publicKey))
})
