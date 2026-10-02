/**
 * ETSI TS 119 602 — Lists of Trusted Entities (LoTE), JSON binding, as used by the EUDI Wallet
 * ecosystem (ARF section 3.5 / 6.6.3.2) for the "WRPAC Providers" list: the trust anchors of the
 * Access Certificate Authorities that issue Wallet-Relying Party Access Certificates (WRPAC,
 * ETSI TS 119 411-8).
 *
 * Field names follow the ETSI JSON schema (1960201_json_schema.json); constants follow the EU LoTE
 * profiles (see eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2).
 * The LoTE is distributed as a JAdES (ETSI TS 119 182-1) compact JWS whose payload is
 * `{"LoTE": {...}}`.
 */
import { createHash } from 'node:crypto'
import * as jose from 'jose'

export const ETSI19602 = {
  LOTE_VERSION: 1,
  // EU WRPAC Providers list (ETSI TS 119 602 annex / EU profile)
  WRPAC_PROVIDERS_LOTE_TYPE: 'http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList',
  WRPAC_PROVIDERS_STATUS_DETERMINATION_APPROACH: 'http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU',
  WRPAC_PROVIDERS_SCHEME_COMMUNITY_RULES: 'http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU',
  SVC_TYPE_WRPAC_ISSUANCE: 'http://uri.etsi.org/19602/SvcType/WRPAC/Issuance',
  SVC_TYPE_WRPAC_REVOCATION: 'http://uri.etsi.org/19602/SvcType/WRPAC/Revocation',
} as const

/** ETSI TS 119 411-8 WRPAC certificate policy OIDs. */
export const ETSI119411_8 = {
  NCP_N_EUDIWRP: '0.4.0.194118.1.1',
  NCP_L_EUDIWRP: '0.4.0.194118.1.2',
  QCP_N_EUDIWRP: '0.4.0.194118.1.3',
  QCP_L_EUDIWRP: '0.4.0.194118.1.4',
} as const

export const LOTE_MEDIA_TYPE = 'application/jwt'

// ---- data model (subset of the JSON schema actually used) -------------------------------------

export type MultiLangString = { lang: string; value: string }
export type MultiLangURI = { lang: string; uriValue: string }
export type PostalAddress = {
  lang: string
  StreetAddress: string
  Locality?: string
  StateOrProvince?: string
  PostalCode?: string
  Country: string
}
export type PkiOb = { encoding?: string; specRef?: string; val: string }

export type ServiceInformation = {
  ServiceName: MultiLangString[]
  ServiceDigitalIdentity: { X509Certificates?: PkiOb[]; X509SKIs?: string[] }
  ServiceTypeIdentifier?: string
  ServiceStatus?: string
  StatusStartingTime?: string
  ServiceSupplyPoints?: { ServiceType?: string; uriValue: string }[]
  ServiceDefinitionURI?: MultiLangURI[]
}

export type TrustedEntity = {
  TrustedEntityInformation: {
    TEName: MultiLangString[]
    TETradeName?: MultiLangString[]
    TEAddress: { TEPostalAddress: PostalAddress[]; TEElectronicAddress: MultiLangURI[] }
    TEInformationURI: MultiLangURI[]
  }
  TrustedEntityServices: { ServiceInformation: ServiceInformation }[]
}

export type ListAndSchemeInformation = {
  LoTEVersionIdentifier: number
  LoTESequenceNumber: number
  LoTEType?: string
  SchemeOperatorName: MultiLangString[]
  SchemeOperatorAddress?: { SchemeOperatorPostalAddress: PostalAddress[]; SchemeOperatorElectronicAddress: MultiLangURI[] }
  SchemeName?: MultiLangString[]
  SchemeInformationURI?: MultiLangURI[]
  StatusDeterminationApproach?: string
  SchemeTypeCommunityRules?: MultiLangURI[]
  SchemeTerritory?: string
  ListIssueDateTime: string
  NextUpdate: string
  DistributionPoints?: string[]
}

export type ListOfTrustedEntities = {
  ListAndSchemeInformation: ListAndSchemeInformation
  TrustedEntitiesList?: TrustedEntity[]
}

/** ETSI date-time without fractional seconds, UTC. */
export const loteDateTime = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

const derB64 = (der: ArrayBuffer | Uint8Array) => Buffer.from(der as ArrayBuffer).toString('base64')

export type WrpacProvider = {
  name: string
  tradeName?: string
  informationUri: string
  electronicAddress: string
  postalAddress: PostalAddress
  /** CA certificate (DER) of the Access Certificate Authority = trust anchor. */
  caCertificateDer: Uint8Array
  crlUri: string
  caIssuersUri: string
}

/** Builds a WRPAC Providers LoTE (ETSI TS 119 602). */
export const buildWrpacProvidersLoTE = (opts: {
  sequenceNumber: number
  issued: Date
  nextUpdate: Date
  schemeOperatorName: string
  schemeOperatorAddress: PostalAddress
  schemeOperatorElectronicAddress: string
  schemeName: string
  schemeInformationUri: string
  schemeTerritory: string
  distributionPoint: string
  providers: WrpacProvider[]
}): ListOfTrustedEntities => ({
  ListAndSchemeInformation: {
    LoTEVersionIdentifier: ETSI19602.LOTE_VERSION,
    LoTESequenceNumber: opts.sequenceNumber,
    LoTEType: ETSI19602.WRPAC_PROVIDERS_LOTE_TYPE,
    SchemeOperatorName: [{ lang: 'en', value: opts.schemeOperatorName }],
    SchemeOperatorAddress: {
      SchemeOperatorPostalAddress: [opts.schemeOperatorAddress],
      SchemeOperatorElectronicAddress: [{ lang: 'en', uriValue: opts.schemeOperatorElectronicAddress }],
    },
    SchemeName: [{ lang: 'en', value: opts.schemeName }],
    SchemeInformationURI: [{ lang: 'en', uriValue: opts.schemeInformationUri }],
    StatusDeterminationApproach: ETSI19602.WRPAC_PROVIDERS_STATUS_DETERMINATION_APPROACH,
    SchemeTypeCommunityRules: [{ lang: 'en', uriValue: ETSI19602.WRPAC_PROVIDERS_SCHEME_COMMUNITY_RULES }],
    SchemeTerritory: opts.schemeTerritory,
    ListIssueDateTime: loteDateTime(opts.issued),
    NextUpdate: loteDateTime(opts.nextUpdate),
    DistributionPoints: [opts.distributionPoint],
  },
  TrustedEntitiesList: opts.providers.map((p) => ({
    TrustedEntityInformation: {
      TEName: [{ lang: 'en', value: p.name }],
      ...(p.tradeName ? { TETradeName: [{ lang: 'en', value: p.tradeName }] } : {}),
      TEAddress: {
        TEPostalAddress: [p.postalAddress],
        TEElectronicAddress: [{ lang: 'en', uriValue: p.electronicAddress }],
      },
      TEInformationURI: [{ lang: 'en', uriValue: p.informationUri }],
    },
    TrustedEntityServices: [
      {
        ServiceInformation: {
          ServiceName: [{ lang: 'en', value: `${p.name} - WRPAC issuance` }],
          ServiceDigitalIdentity: { X509Certificates: [{ val: derB64(p.caCertificateDer) }] },
          ServiceTypeIdentifier: ETSI19602.SVC_TYPE_WRPAC_ISSUANCE,
          ServiceSupplyPoints: [{ uriValue: p.caIssuersUri }],
        },
      },
      {
        ServiceInformation: {
          ServiceName: [{ lang: 'en', value: `${p.name} - WRPAC revocation (CRL)` }],
          ServiceDigitalIdentity: { X509Certificates: [{ val: derB64(p.caCertificateDer) }] },
          ServiceTypeIdentifier: ETSI19602.SVC_TYPE_WRPAC_REVOCATION,
          ServiceSupplyPoints: [{ uriValue: p.crlUri }],
        },
      },
    ],
  })),
})

/**
 * Signs the LoTE as a JAdES baseline B-B compact JWS (ETSI TS 119 182-1):
 * protected header with `alg`, `x5c` / `x5t#S256` (signing certificate) and the JAdES `sigT`
 * (claimed signing time) listed in `crit`.
 */
export const signLoTE = async (
  lote: ListOfTrustedEntities,
  signer: { privateKey: CryptoKey; certificateDer: Uint8Array },
  signingTime = new Date()
): Promise<string> =>
  new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ LoTE: lote })))
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'JOSE',
      x5c: [derB64(signer.certificateDer)],
      'x5t#S256': jose.base64url.encode(createHash('sha256').update(signer.certificateDer).digest()),
      sigT: loteDateTime(signingTime),
      crit: ['sigT'],
    })
    .sign(signer.privateKey, { crit: { sigT: true } })
