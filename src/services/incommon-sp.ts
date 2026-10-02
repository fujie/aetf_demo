import { Hono } from 'hono'
import type { SigningKey } from '../common/keys.js'
import { jwksOf } from '../common/keys.js'
import { esc, page, trustChainHtml } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveTrustChain } from '../federation/resolver.js'
import { mountFederatedLogin } from './sp.js'

/**
 * InCommon SP: a Relying Party in the Internet2 (I2) federation. It shares the eduGAIN Trust
 * Anchor with 学認 (NII), so it can resolve trust chains of 学認 entities (inter-federation).
 * Users of 学認 institutions can log in with their 機関IdP: the IdP accepts this RP by resolving its
 * Trust Chain InCommon SP -> I2 -> eduGAIN, and this SP trusts the IdP via IdP -> NII -> eduGAIN.
 * The page doubles as a Trust Chain explorer.
 */
export const createIncommonSp = (opts: {
  entityId: string
  federationKey: SigningKey
  rpKey: SigningKey
  authorityHints: string[]
  anchors: TrustAnchorConfig[]
  knownEntities: string[]
  /** 学認 機関IdP used for inter-federation login. */
  idpEntityId: string
}) => {
  const entity = createFederationEntity({
    entityId: opts.entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'InCommon SP (Example US University)' },
      openid_relying_party: {
        client_name: 'InCommon SP (Example US University)',
        client_registration_types: ['automatic'],
        redirect_uris: [`${opts.entityId}/oidc/callback`],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: jwksOf(opts.rpKey),
      },
    },
  })
  const app = new Hono()
  mountFederationEndpoints(app, entity)
  const login = mountFederatedLogin(app, {
    entityId: opts.entityId,
    spName: 'InCommon SP',
    rpKey: opts.rpKey,
    anchors: opts.anchors,
    idpEntityId: opts.idpEntityId,
  })

  app.get('/', async (c) => {
    const target = c.req.query('entity')
    let result = ''
    if (target) {
      try {
        const chain = await resolveTrustChain(target, opts.anchors, { noCache: true })
        result = `<section><h3 class="ok">Trust Chain 検証成功</h3><p>${trustChainHtml(chain.path)}</p>
          <h4>Resolved metadata (metadata_policy 適用後)</h4><pre>${esc(JSON.stringify(chain.metadata, null, 2))}</pre>
          <h4>Trust Chain (JWT)</h4><pre>${esc(chain.chain.join('\n\n'))}</pre></section>`
      } catch (e) {
        result = `<section><h3 class="ng">Trust Chain 検証失敗</h3><pre>${esc((e as Error).message)}</pre></section>`
      }
    }
    const options = opts.knownEntities
      .map((e) => `<option value="${esc(e)}" ${e === target ? 'selected' : ''}>${esc(e)}</option>`)
      .join('')
    return c.html(
      page(
        'InCommon SP',
        `<section><h3>学認の機関IdPでログイン (eduGAIN 経由のフェデレーション間連携)</h3>
        <p class="mut">この SP は I2 (InCommon) 配下です。機関IdP は SP の Trust Chain (InCommon SP → I2 → eduGAIN) を、
        SP は機関IdP の Trust Chain (機関IdP → NII → eduGAIN) を検証して接続します。他フェデレーションの SP なので、機関IdP は最小限の属性のみ送信します。</p></section>
        ${login.loginPanel(c, { idpLabel: '学認の所属機関' })}
        <section><h3>Trust Chain Explorer</h3><p>Entity ID: <code>${esc(opts.entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <form method="get"><select name="entity">${options}</select> <button>Trust Chain を解決</button></form></section>${result}`
      )
    )
  })

  return { app, entity }
}
