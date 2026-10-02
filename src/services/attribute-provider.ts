import { Hono } from 'hono'
import * as jose from 'jose'
import { type SigningKey, jwksOf, signJwt, verifyWithJwks } from '../common/keys.js'
import { esc, page } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'

/** Attributes held by the 属性Provider (e.g. student registry), keyed by eduPersonPrincipalName. */
const ATTRIBUTES: Record<string, Record<string, unknown>> = {
  'taro@example-u.ac.jp': {
    student_number: 'S2026-0001',
    department: '工学部 情報工学科',
    enrollment_status: 'enrolled',
    year_of_study: 3,
  },
  'hanako@example-u.ac.jp': {
    student_number: 'S2026-0002',
    department: '理学部 数学科',
    enrollment_status: 'enrolled',
    year_of_study: 1,
  },
}

export const ATTRIBUTE_RESPONSE_TYP = 'attribute-response+jwt'
export const ATTRIBUTE_REQUEST_TYP = 'attribute-request+jwt'

/**
 * 属性Provider: returns additional attributes for a user.
 * The requester authenticates with a signed request JWT; its key is taken from its federation
 * metadata (openid_relying_party.jwks) after resolving its Trust Chain.
 * The response is signed with the key in this entity's `attribute_provider` metadata.
 */
export const createAttributeProvider = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
  anchors: TrustAnchorConfig[]
}) => {
  const { entityId } = opts
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Example University 属性Provider' },
      attribute_provider: {
        attribute_endpoint: `${entityId}/attributes`,
        attributes_supported: ['student_number', 'department', 'enrollment_status', 'year_of_study'],
        jwks: jwksOf(opts.signingKey),
      },
    },
  })

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  app.get('/', (c) =>
    c.html(
      page(
        '属性Provider',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <pre>${esc(JSON.stringify(ATTRIBUTES, null, 2))}</pre></section>`
      )
    )
  )

  app.post('/attributes', async (c) => {
    const form = await c.req.parseBody()
    const request = String(form.request ?? '')
    let requester: string
    let subject: string
    try {
      const unverified = jose.decodeJwt(request)
      requester = String(unverified.iss)
      const { metadata } = await resolveEntityMetadata<{ jwks?: { keys: jose.JWK[] } }>(
        requester,
        'openid_relying_party',
        opts.anchors
      )
      const { payload } = await verifyWithJwks(request, metadata.jwks, {
        typ: ATTRIBUTE_REQUEST_TYP,
        audience: entityId,
        maxTokenAge: '2m',
      })
      subject = String(payload.sub)
    } catch (e) {
      return c.json({ error: 'unauthorized_client', error_description: (e as Error).message }, 401)
    }
    const attributes = ATTRIBUTES[subject]
    if (!attributes) return c.json({ error: 'not_found' }, 404)
    const now = Math.floor(Date.now() / 1000)
    const response = await signJwt(
      opts.signingKey,
      { iss: entityId, aud: requester, sub: subject, iat: now, exp: now + 120, attributes },
      ATTRIBUTE_RESPONSE_TYP
    )
    return c.body(response, 200, { 'Content-Type': 'application/jwt' })
  })

  return { app, entity }
}
