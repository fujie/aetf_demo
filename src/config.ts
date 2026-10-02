/**
 * Ports / Entity Identifiers of every entity in the diagram.
 * All entities run on localhost with different ports; the entity identifier is the base URL.
 */
const HOST = process.env.PUBLIC_HOST ?? 'localhost'

const url = (port: number) => `http://${HOST}:${port}`

export const PORTS = {
  trustAnchor: 7000, // Trust Anchor (eduGAIN)
  nii: 7001, // Intermediate Authority (NII)
  i2: 7002, // Intermediate Authority (Internet2 / InCommon)
  idp: 7010, // 機関IdP
  attributeProvider: 7011, // 属性Provider
  issuer: 7020, // 学認Issuer
  walletProvider: 7030, // Wallet Provider
  trustList: 7031, // Trust List (Verifier registry)
  statusList: 7032, // Status List
  verifier: 7040, // Verifier (OID4VP)
  incommonSp: 7050, // InCommon SP
} as const

export const ENTITY = Object.fromEntries(
  Object.entries(PORTS).map(([k, port]) => [k, url(port)])
) as Record<keyof typeof PORTS, string>

/** Credential configuration issued by the 学認Issuer. */
export const CREDENTIAL_CONFIGURATION_ID = 'GakuninStudentCredential'
export const CREDENTIAL_VCT = `${ENTITY.issuer}/vct/GakuninStudentCredential`

/** Shared secret the Issuer uses for the Status List management API (prototype only). */
export const STATUS_LIST_API_KEY = process.env.STATUS_LIST_API_KEY ?? 'issuer-status-list-api-key'
