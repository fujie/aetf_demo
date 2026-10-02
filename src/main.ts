import 'reflect-metadata'
import { serve } from '@hono/node-server'
import type { Hono } from 'hono'
import { CREDENTIAL_CONFIGURATION_ID, CREDENTIAL_VCT, ENTITY, PORTS, STATUS_LIST_API_KEY } from './config.js'
import { jwksOf, loadOrCreateKey, writeDataFile } from './common/keys.js'
import type { FederationEntity, MetadataPolicy } from './federation/entity.js'
import type { TrustAnchorConfig } from './federation/resolver.js'
import { createAuthority } from './services/authority.js'
import { createAttributeProvider } from './services/attribute-provider.js'
import { createIdp } from './services/idp.js'
import { createIncommonSp } from './services/incommon-sp.js'
import { createIssuer } from './services/issuer.js'
import { createStatusList } from './services/status-list.js'
import { createTrustList } from './services/trust-list.js'
import { createVerifier } from './services/verifier.js'
import { createWalletProvider } from './services/wallet-provider.js'

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
  })
  const trustList = createTrustList({
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

  // ---- I2 leaf -------------------------------------------------------------------------------
  const incommonSp = createIncommonSp({
    entityId: ENTITY.incommonSp,
    federationKey: await fed('incommon-sp'),
    rpKey: await proto('incommon-sp-rp'),
    authorityHints: [ENTITY.i2],
    anchors,
    knownEntities: [
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
  ]
  await Promise.all(
    apps.map(
      ([key, label, app]) =>
        new Promise<void>((resolve) => {
          serve({ fetch: app.fetch, port: PORTS[key] }, () => {
            console.log(`  ${label.padEnd(30)} ${ENTITY[key]}`)
            resolve()
          })
        })
    )
  )

  await verifier.registerToTrustList()
  console.log('\nAll entities are up. Trust anchor config written to .data/trust-anchor.json')
}

main().catch((e) => {
  console.error('startup failed', e)
  process.exit(1)
})
