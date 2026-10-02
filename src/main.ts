import 'reflect-metadata'
import { serve } from '@hono/node-server'
import type { Hono } from 'hono'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import {
  BASE_PORT,
  CREDENTIAL_CONFIGURATION_ID,
  CREDENTIAL_VCT,
  DEMO_CONSOLE_PORT,
  DEMO_CONSOLE_URL,
  ENTITY,
  PORTS,
  STATUS_LIST_API_KEY,
  WALLET_UI_URL,
} from './config.js'
import { DATA_DIR, jwksOf, loadOrCreateKey, writeDataFile } from './common/keys.js'
import type { FederationEntity, MetadataPolicy } from './federation/entity.js'
import type { TrustAnchorConfig } from './federation/resolver.js'
import { createAuthority } from './services/authority.js'
import { createDemoConsole } from './services/demo-console.js'
import { createAttributeProvider } from './services/attribute-provider.js'
import { createIdp } from './services/idp.js'
import { createIncommonSp } from './services/incommon-sp.js'
import { createIssuer } from './services/issuer.js'
import { createGakuninSp } from './services/sp.js'
import { createStatusList } from './services/status-list.js'
import { createTrustList } from './services/trust-list.js'
import { createVerifier } from './services/verifier.js'
import { createWalletProvider } from './services/wallet-provider.js'

/** Starts a server; exits with a hint when the port is already in use. */
const listen = (app: Hono, port: number, onListening: () => void) => {
  const server = serve({ fetch: app.fetch, port }, onListening)
  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(
        `\n✘ Port ${port} is already in use.\n  Choose another port range with BASE_PORT, e.g.:  BASE_PORT=9700 npm run demo\n  (current BASE_PORT=${BASE_PORT}; ports BASE_PORT..BASE_PORT+90 are used)`
      )
    } else {
      console.error(err)
    }
    process.exit(1)
  })
}

const main = async () => {
  // ---- keys ---------------------------------------------------------------------------------
  const fed = async (name: string) => loadOrCreateKey(`${name}-federation`)
  const proto = async (name: string) => loadOrCreateKey(`${name}-protocol`)

  // ---- Trust Anchor / Intermediate Authorities ------------------------------------------
  const ta = createAuthority({
    entityId: ENTITY.trustAnchor,
    organizationName: 'eduGAIN',
    federationKey: await fed('edugain'),
  })
  const nii = createAuthority({
    entityId: ENTITY.nii,
    organizationName: 'NII (学認)',
    federationKey: await fed('nii'),
    authorityHints: [ENTITY.trustAnchor],
  })
  const i2 = createAuthority({
    entityId: ENTITY.i2,
    organizationName: 'Internet2 (InCommon)',
    federationKey: await fed('i2'),
    authorityHints: [ENTITY.trustAnchor],
  })

  // Trust Anchor configured out-of-band at every relying entity (and the Wallet Instance)
  const anchors: TrustAnchorConfig[] = [
    { entityId: ENTITY.trustAnchor, jwks: jwksOf(ta.entity.federationKey) },
  ]
  writeDataFile('trust-anchor.json', anchors[0])

  // ---- 学認 (NII) leaves ---------------------------------------------------------------------
  const idp = createIdp({
    entityId: ENTITY.idp,
    federationKey: await fed('idp'),
    signingKey: await proto('idp'),
    authorityHints: [ENTITY.nii],
    anchors,
    homeFederation: ENTITY.nii,
  })
  const ap = createAttributeProvider({
    entityId: ENTITY.attributeProvider,
    federationKey: await fed('attribute-provider'),
    signingKey: await proto('attribute-provider'),
    authorityHints: [ENTITY.nii],
    anchors,
  })
  const issuer = await createIssuer({
    entityId: ENTITY.issuer,
    federationKey: await fed('issuer'),
    rpKey: await proto('issuer-rp'),
    credentialKey: await proto('issuer-credential'),
    authorityHints: [ENTITY.nii],
    anchors,
    idpEntityId: ENTITY.idp,
    attributeProviderEntityId: ENTITY.attributeProvider,
    statusListEntityId: ENTITY.statusList,
    statusListApiKey: STATUS_LIST_API_KEY,
    credentialConfigurationId: CREDENTIAL_CONFIGURATION_ID,
    vct: CREDENTIAL_VCT,
  })
  const walletProvider = createWalletProvider({
    entityId: ENTITY.walletProvider,
    federationKey: await fed('wallet-provider'),
    signingKey: await proto('wallet-provider'),
    authorityHints: [ENTITY.nii],
    statusListEntityId: ENTITY.statusList,
    statusListApiKey: STATUS_LIST_API_KEY,
  })
  const trustList = await createTrustList({
    entityId: ENTITY.trustList,
    federationKey: await fed('trust-list'),
    signingKey: await proto('trust-list'),
    authorityHints: [ENTITY.nii],
  })
  const statusList = createStatusList({
    entityId: ENTITY.statusList,
    federationKey: await fed('status-list'),
    signingKey: await proto('status-list'),
    authorityHints: [ENTITY.nii],
    apiKey: STATUS_LIST_API_KEY,
  })

  const gakuninSp = createGakuninSp({
    entityId: ENTITY.gakuninSp,
    federationKey: await fed('gakunin-sp'),
    rpKey: await proto('gakunin-sp-rp'),
    authorityHints: [ENTITY.nii],
    anchors,
    idpEntityId: ENTITY.idp,
  })

  // ---- I2 leaf -------------------------------------------------------------------------------
  const incommonSp = createIncommonSp({
    entityId: ENTITY.incommonSp,
    federationKey: await fed('incommon-sp'),
    rpKey: await proto('incommon-sp-rp'),
    authorityHints: [ENTITY.i2],
    anchors,
    idpEntityId: ENTITY.idp,
    knownEntities: [
      ENTITY.gakuninSp,
      ENTITY.issuer,
      ENTITY.idp,
      ENTITY.attributeProvider,
      ENTITY.walletProvider,
      ENTITY.trustList,
      ENTITY.statusList,
      ENTITY.incommonSp,
      ENTITY.nii,
      ENTITY.i2,
      ENTITY.verifier,
    ],
  })

  // ---- Trust Chain enrolment (subordinate registration at the superiors) --------------------
  const enroll = (superior: FederationEntity, sub: FederationEntity, metadataPolicy?: MetadataPolicy) =>
    superior.register({
      entityId: sub.entityId,
      jwks: jwksOf(sub.federationKey),
      entityTypes: Object.keys(sub.metadata),
      ...(metadataPolicy ? { metadataPolicy } : {}),
    })

  // eduGAIN-wide policy: only modern signing algorithms for OpenID Providers
  const edugainPolicy: MetadataPolicy = {
    openid_provider: { id_token_signing_alg_values_supported: { subset_of: ['ES256', 'ES384', 'PS256'] } },
  }
  enroll(ta.entity, nii.entity, edugainPolicy)
  enroll(ta.entity, i2.entity, edugainPolicy)

  const gakuninPolicy: MetadataPolicy = {
    federation_entity: { contacts: { add: ['gakunin-fed@nii.example'] } },
  }
  enroll(nii.entity, idp.entity, gakuninPolicy)
  enroll(nii.entity, ap.entity, gakuninPolicy)
  enroll(nii.entity, gakuninSp.entity, gakuninPolicy)
  enroll(nii.entity, issuer.entity, {
    ...gakuninPolicy,
    openid_credential_issuer: { credential_configurations_supported: { essential: true } },
  })
  enroll(nii.entity, walletProvider.entity, {
    ...gakuninPolicy,
    wallet_provider: { attestation_signing_alg_values_supported: { subset_of: ['ES256'] } },
  })
  enroll(nii.entity, trustList.entity, gakuninPolicy)
  enroll(nii.entity, statusList.entity, gakuninPolicy)
  enroll(i2.entity, incommonSp.entity)

  // ---- Verifier (not a federation member; trusted by wallets via the Trust List) -----------
  const verifier = await createVerifier({
    baseUrl: ENTITY.verifier,
    name: 'Prototype Verifier (学割サービス)',
    anchors,
    trustListEntityId: ENTITY.trustList,
    vct: CREDENTIAL_VCT,
  })

  // ---- start servers ------------------------------------------------------------------------
  const apps: [keyof typeof PORTS, string, Hono][] = [
    ['trustAnchor', 'Trust Anchor (eduGAIN)', ta.app],
    ['nii', 'Intermediate Authority (NII)', nii.app],
    ['i2', 'Intermediate Authority (I2)', i2.app],
    ['idp', '機関IdP', idp.app],
    ['attributeProvider', '属性Provider', ap.app],
    ['issuer', '学認Issuer', issuer.app],
    ['walletProvider', 'Wallet Provider', walletProvider.app],
    ['trustList', 'Trust List', trustList.app],
    ['statusList', 'Status List', statusList.app],
    ['verifier', 'Verifier', verifier.app],
    ['incommonSp', 'InCommon SP', incommonSp.app],
    ['gakuninSp', '学認SP (通常のSP)', gakuninSp.app],
  ]
  await Promise.all(
    apps.map(
      ([key, label, app]) =>
        new Promise<void>((resolve) => {
          listen(app, PORTS[key], () => {
            console.log(`  ${label.padEnd(30)} ${ENTITY[key]}`)
            resolve()
          })
        })
    )
  )

  const demoConsole = createDemoConsole()
  await new Promise<void>((resolve) => listen(demoConsole.app, DEMO_CONSOLE_PORT, () => resolve()))
  console.log(`  ${'Demo Console'.padEnd(30)} ${DEMO_CONSOLE_URL}`)

  await verifier.registerToTrustList()
  console.log('\nAll entities are up. Trust anchor config written to .data/trust-anchor.json')
  if (process.argv.includes('--with-wallet')) startWebWallet()
  console.log(`\n▶ Demo console: ${DEMO_CONSOLE_URL}`)
}

/** Builds and starts the Go web wallet (`wallet-instance serve`) as a child process. */
const startWebWallet = () => {
  const dir = join(process.cwd(), 'wallet-instance')
  const bin = join(dir, process.platform === 'win32' ? 'wallet-instance.exe' : 'wallet-instance')
  console.log('Building the web wallet (go build)...')
  const build = spawnSync('go', ['build', '-o', bin, '.'], {
    cwd: dir,
    stdio: 'inherit',
    env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN ?? 'auto' },
  })
  if (build.status !== 0 || !existsSync(bin)) {
    console.error('Could not build the web wallet (Go 1.25+ required). Start it manually: cd wallet-instance && go run . serve')
    return
  }
  const child = spawn(bin, ['serve'], {
    cwd: dir,
    stdio: 'inherit',
    env: {
      ...process.env,
      WALLET_DIR: process.env.WALLET_DIR ?? join(DATA_DIR, 'web-wallet'),
      TRUST_ANCHOR: join(DATA_DIR, 'trust-anchor.json'),
      DEMO_CONSOLE: DEMO_CONSOLE_URL,
      WALLET_UI_PORT: new URL(WALLET_UI_URL).port,
      WALLET_PROVIDER: ENTITY.walletProvider,
      TRUST_LIST: ENTITY.trustList,
    },
  })
  const stop = () => child.kill()
  process.on('exit', stop)
  process.on('SIGINT', () => process.exit(0))
  process.on('SIGTERM', () => process.exit(0))
}

main().catch((e) => {
  console.error('startup failed', e)
  process.exit(1)
})
