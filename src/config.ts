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
  idp: BASE_PORT + 10, // 機関IdP
  attributeProvider: BASE_PORT + 11, // 属性Provider
  issuer: BASE_PORT + 20, // 学認Issuer
  gakuninSp: BASE_PORT + 25, // 通常の学認SP
  walletProvider: BASE_PORT + 30, // Wallet Provider
  trustList: BASE_PORT + 31, // Trust List (Registrar / Access CA / LoTE)
  statusList: BASE_PORT + 32, // Status List
  verifier: BASE_PORT + 40, // Verifier (OID4VP)
  incommonSp: BASE_PORT + 50, // InCommon SP
} as const

export const ENTITY = Object.fromEntries(
  Object.entries(PORTS).map(([k, port]) => [k, url(port)])
) as Record<keyof typeof PORTS, string>

/** Display names of the entities (diagrams). */
export const ENTITY_LABELS: Record<string, string> = {
  [ENTITY.trustAnchor]: 'eduGAIN (TA)',
  [ENTITY.nii]: 'NII',
  [ENTITY.i2]: 'I2',
  [ENTITY.idp]: '機関IdP',
  [ENTITY.attributeProvider]: '属性Provider',
  [ENTITY.issuer]: '学認Issuer',
  [ENTITY.gakuninSp]: '学認SP',
  [ENTITY.walletProvider]: 'Wallet Provider',
  [ENTITY.trustList]: 'Trust List',
  [ENTITY.statusList]: 'Status List',
  [ENTITY.verifier]: 'Verifier',
  [ENTITY.incommonSp]: 'InCommon SP',
}

/** Credential configuration issued by the 学認Issuer. */
export const CREDENTIAL_CONFIGURATION_ID = 'GakuninStudentCredential'
export const CREDENTIAL_VCT = `${ENTITY.issuer}/vct/GakuninStudentCredential`

/** Shared secret the Issuer uses for the Status List management API (prototype only). */
export const STATUS_LIST_API_KEY = process.env.STATUS_LIST_API_KEY ?? 'issuer-status-list-api-key'

/** Web wallet UI (Go, `wallet-instance serve`) and the demo console. */
export const WALLET_UI_URL = process.env.WALLET_UI_URL ?? `http://${HOST}:${BASE_PORT + 60}`
export const DEMO_CONSOLE_PORT = BASE_PORT + 90
export const DEMO_CONSOLE_URL = `http://${HOST}:${DEMO_CONSOLE_PORT}`
