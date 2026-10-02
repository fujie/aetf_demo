import { Hono } from 'hono'
import type { SigningKey } from '../common/keys.js'
import { jwksOf } from '../common/keys.js'
import { esc, page, trustChainHtml } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveTrustChain } from '../federation/resolver.js'

/**
 * InCommon SP: a Relying Party in the Internet2 (I2) federation. It shares the eduGAIN Trust
 * Anchor with 学認 (NII), so it can resolve trust chains of 学認 entities (inter-federation).
 * The page doubles as a Trust Chain explorer.
 */
export const createIncommonSp = (opts: {
  entityId: string
  federationKey: SigningKey
  rpKey: SigningKey
  authorityHints: string[]
  anchors: TrustAnchorConfig[]
  knownEntities: string[]
}) => {
  const entity = createFederationEntity({
    entityId: opts.entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'InCommon SP (Example US University)' },
      openid_relying_party: {
        client_name: 'InCommon SP',
        client_registration_types: ['automatic'],
        redirect_uris: [`${opts.entityId}/callback`],
        jwks: jwksOf(opts.rpKey),
      },
    },
  })
  const app = new Hono()
  mountFederationEndpoints(app, entity)

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
        'InCommon SP - Trust Chain Explorer',
        `<section><p>Entity ID: <code>${esc(opts.entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <form method="get"><select name="entity">${options}</select> <button>Trust Chain を解決</button></form></section>${result}`
      )
    )
  })

  return { app, entity }
}
