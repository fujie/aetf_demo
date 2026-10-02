/**
 * Ports / Entity Identifiers of every entity in the diagram.
 * All entities run on localhost with different ports; the entity identifier is the base URL.
 */
const HOST = process.env.PUBLIC_HOST ?? 'localhost'

const url = (port: number) => `http://${HOST}:${port}`

/**
 * All ports are offsets from BASE_PORT (default 8700). Change it if a port is taken, e.g.
 * `BASE_PORT=9700 npm run demo`. (7000 is used by the macOS AirPlay Receiver, hence not the default.)
 */
export const BASE_PORT = Number(process.env.BASE_PORT ?? 8700)

export const PORTS = {
  trustAnchor: BASE_PORT + 0, // Trust Anchor (eduGAIN)
  nii: BASE_PORT + 1, // Intermediate Authority (NII)
  i2: BASE_PORT + 2, // Intermediate Authority (Internet2 / InCommon)
  idp: BASE_PORT + 10, // Institution IdP
  attributeProvider: BASE_PORT + 11, // Attribute Provider
  issuer: BASE_PORT + 20, // GakuNin Issuer
  gakuninSp: BASE_PORT + 25, // regular GakuNin SP
  walletProvider: BASE_PORT + 30, // Wallet Provider
  trustList: BASE_PORT + 31, // Trust List (Registrar / Access CA / LoTE)
  statusList: BASE_PORT + 32, // Status List
  verifier: BASE_PORT + 40, // Verifier (OID4VP)
  incommonSp: BASE_PORT + 50, // InCommon SP
} as const

export const ENTITY = Object.fromEntries(
  Object.entries(PORTS).map(([k, port]) => [k, url(port)])
) as Record<keyof typeof PORTS, string>

/** Display names of the entities (Japanese / English). */
export const ENTITY_NAMES: Record<string, { ja: string; en: string }> = {
  [ENTITY.trustAnchor]: { ja: 'eduGAIN (TA)', en: 'eduGAIN (TA)' },
  [ENTITY.nii]: { ja: 'NII', en: 'NII' },
  [ENTITY.i2]: { ja: 'I2', en: 'I2' },
  [ENTITY.idp]: { ja: '機関IdP', en: 'Institution IdP' },
  [ENTITY.attributeProvider]: { ja: '属性Provider', en: 'Attribute Provider' },
  [ENTITY.issuer]: { ja: '学認Issuer', en: 'GakuNin Issuer' },
  [ENTITY.gakuninSp]: { ja: '学認SP', en: 'GakuNin SP' },
  [ENTITY.walletProvider]: { ja: 'Wallet Provider', en: 'Wallet Provider' },
  [ENTITY.trustList]: { ja: 'Trust List', en: 'Trust List' },
  [ENTITY.statusList]: { ja: 'Status List', en: 'Status List' },
  [ENTITY.verifier]: { ja: 'Verifier', en: 'Verifier' },
  [ENTITY.incommonSp]: { ja: 'InCommon SP', en: 'InCommon SP' },
}

/** Credential configuration issued by the GakuNin Issuer. */
export const CREDENTIAL_CONFIGURATION_ID = 'GakuninStudentCredential'
export const CREDENTIAL_VCT = `${ENTITY.issuer}/vct/GakuninStudentCredential`

/** Shared secret the Issuer uses for the Status List management API (prototype only). */
export const STATUS_LIST_API_KEY = process.env.STATUS_LIST_API_KEY ?? 'issuer-status-list-api-key'

/** Web wallet UI (Go, `wallet-instance serve`) and the demo console. */
export const WALLET_UI_URL = process.env.WALLET_UI_URL ?? `http://${HOST}:${BASE_PORT + 60}`
export const DEMO_CONSOLE_PORT = BASE_PORT + 90
export const DEMO_CONSOLE_URL = `http://${HOST}:${DEMO_CONSOLE_PORT}`
