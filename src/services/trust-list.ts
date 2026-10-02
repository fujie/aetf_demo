import { Hono } from 'hono'
import * as x509 from '@peculiar/x509'
import { type SigningKey, jwksOf, signJwt } from '../common/keys.js'
import { esc, page } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'

export const TRUST_LIST_TYP = 'trust-list+jwt'

export type TrustListEntry = {
  client_id: string
  name: string
  /** x5c (base64 DER) of the Verifier's request-object signing certificate. */
  x5c: string[]
  response_uri_origin?: string
  registered_at: string
}

/**
 * Trust List (Verifier registry). Verifiers register here (red "Registration" arrow);
 * Wallets fetch the signed list (`trust-list+jwt`) and validate the signer via OpenID Federation
 * (`trust_list_provider.jwks`).
 */
export const createTrustList = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
}) => {
  const { entityId } = opts
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Prototype Trust List Provider' },
      trust_list_provider: {
        trust_list_endpoint: `${entityId}/trust-list`,
        registration_endpoint: `${entityId}/registrations`,
        jwks: jwksOf(opts.signingKey),
      },
    },
  })
  const entries = new Map<string, TrustListEntry>()

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  app.get('/', (c) => {
    const rows = [...entries.values()]
      .map((e) => {
        let subject = ''
        try {
          subject = new x509.X509Certificate(Buffer.from(e.x5c[0], 'base64')).subject
        } catch {}
        return `<tr><td><code>${esc(e.client_id)}</code></td><td>${esc(e.name)}</td><td>${esc(subject)}</td>
          <td>${esc(e.registered_at)}</td>
          <td><form method="post" action="/registrations/delete"><input type="hidden" name="client_id" value="${esc(e.client_id)}"><button>削除</button></form></td></tr>`
      })
      .join('')
    return c.html(
      page(
        'Trust List (Verifier Registry)',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a> / <a href="/trust-list">trust-list+jwt</a></p></section>
        <section><h3>登録済み Verifier</h3><table><tr><th>client_id</th><th>名称</th><th>証明書</th><th>登録日時</th><th></th></tr>${rows}</table></section>`
      )
    )
  })

  /** Verifier registration (prototype: auto-approved). */
  app.post('/registrations', async (c) => {
    const body = await c.req.json<Partial<TrustListEntry>>().catch(() => ({}) as Partial<TrustListEntry>)
    if (!body.client_id || !body.name || !Array.isArray(body.x5c) || body.x5c.length === 0) {
      return c.json({ error: 'invalid_request', error_description: 'client_id, name, x5c required' }, 400)
    }
    try {
      new x509.X509Certificate(Buffer.from(body.x5c[0], 'base64'))
    } catch {
      return c.json({ error: 'invalid_request', error_description: 'x5c[0] is not a certificate' }, 400)
    }
    const entry: TrustListEntry = {
      client_id: body.client_id,
      name: body.name,
      x5c: body.x5c,
      response_uri_origin: body.response_uri_origin,
      registered_at: new Date().toISOString(),
    }
    entries.set(entry.client_id, entry)
    return c.json(entry, 201)
  })

  app.post('/registrations/delete', async (c) => {
    const form = await c.req.parseBody()
    entries.delete(String(form.client_id))
    return c.redirect('/', 303)
  })

  app.get('/trust-list', async (c) => {
    const now = Math.floor(Date.now() / 1000)
    const jwt = await signJwt(
      opts.signingKey,
      { iss: entityId, iat: now, exp: now + 300, entries: [...entries.values()] },
      TRUST_LIST_TYP
    )
    return c.body(jwt, 200, { 'Content-Type': 'application/jwt', 'Cache-Control': 'no-store' })
  })

  return { app, entity }
}
