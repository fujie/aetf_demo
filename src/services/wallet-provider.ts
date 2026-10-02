import { randomUUID } from 'node:crypto'
import { Hono } from 'hono'
import * as jose from 'jose'
import { type SigningKey, jwksOf, signJwt } from '../common/keys.js'
import { esc, page } from '../common/html.js'
import { ATTESTATION_TYP } from '../common/wallet-attestation.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'

export const ATTESTATION_REQUEST_TYP = 'wallet-attestation-request+jwt'
const ATTESTATION_LIFETIME_SEC = 60 * 60

type WalletInstance = {
  id: string
  jwk: jose.JWK
  thumbprint: string
  registeredAt: string
  revoked: boolean
  attestationsIssued: number
}

/**
 * Wallet Provider: registers Wallet Instances and issues Wallet Attestations
 * (`oauth-client-attestation+jwt`) bound to the instance key (`cnf.jwk`).
 * Its attestation signing key is published as `wallet_provider.jwks` in its
 * Entity Configuration so that Issuers / Verifiers can validate it via OpenID Federation.
 */
export const createWalletProvider = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
}) => {
  const { entityId } = opts
  const walletName = 'GakuNin Prototype Wallet'
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Prototype Wallet Provider' },
      wallet_provider: {
        wallet_name: walletName,
        wallet_instance_registration_endpoint: `${entityId}/wallet-instances`,
        wallet_attestation_endpoint: `${entityId}/wallet-attestations`,
        attestation_signing_alg_values_supported: ['ES256'],
        jwks: jwksOf(opts.signingKey),
      },
    },
  })
  const instances = new Map<string, WalletInstance>()

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  app.get('/', (c) => {
    const rows = [...instances.values()]
      .map(
        (i) => `<tr><td><code>${esc(i.id)}</code></td><td>${esc(i.registeredAt)}</td>
        <td>${i.attestationsIssued}</td><td>${i.revoked ? '<span class="ng">revoked</span>' : '<span class="ok">active</span>'}</td>
        <td>${i.revoked ? '' : `<form method="post" action="/wallet-instances/${encodeURIComponent(i.id)}/revoke"><button>失効</button></form>`}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        'Wallet Provider',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p></section>
        <section><h3>Wallet Instances</h3><table><tr><th>ID</th><th>登録日時</th><th>Attestation発行数</th><th>状態</th><th></th></tr>${rows}</table></section>`
      )
    )
  })

  /** Wallet Instance registration (red "Registration" arrow in the diagram). */
  app.post('/wallet-instances', async (c) => {
    const body = await c.req.json<{ jwk?: jose.JWK }>().catch(() => ({}) as { jwk?: jose.JWK })
    if (!body.jwk || body.jwk.kty !== 'EC' || body.jwk.d) {
      return c.json({ error: 'invalid_request', error_description: 'public EC jwk required' }, 400)
    }
    // NOTE: a production Wallet Provider would verify key attestation / app integrity here.
    const thumbprint = await jose.calculateJwkThumbprint(body.jwk)
    const existing = [...instances.values()].find((i) => i.thumbprint === thumbprint)
    if (existing) return c.json({ wallet_instance_id: existing.id })
    const id = `${entityId}/instances/${randomUUID()}`
    instances.set(id, {
      id,
      jwk: body.jwk,
      thumbprint,
      registeredAt: new Date().toISOString(),
      revoked: false,
      attestationsIssued: 0,
    })
    return c.json({ wallet_instance_id: id }, 201)
  })

  app.post('/wallet-instances/:id{.+}/revoke', (c) => {
    const inst = instances.get(decodeURIComponent(c.req.param('id')))
    if (inst) inst.revoked = true
    return c.redirect('/', 303)
  })

  /** Issues a Wallet Attestation. Body: request JWT signed by the instance key. */
  app.post('/wallet-attestations', async (c) => {
    const body = await c.req.json<{ request?: string }>().catch(() => ({}) as { request?: string })
    let instance: WalletInstance | undefined
    try {
      const unverified = jose.decodeJwt(String(body.request))
      instance = instances.get(String(unverified.iss))
      if (!instance) throw new Error('unknown wallet instance')
      if (instance.revoked) throw new Error('wallet instance revoked')
      await jose.jwtVerify(String(body.request), await jose.importJWK(instance.jwk, 'ES256'), {
        typ: ATTESTATION_REQUEST_TYP,
        audience: entityId,
        maxTokenAge: '2m',
      })
    } catch (e) {
      return c.json({ error: 'invalid_request', error_description: (e as Error).message }, 400)
    }
    const now = Math.floor(Date.now() / 1000)
    const attestation = await signJwt(
      opts.signingKey,
      {
        iss: entityId,
        sub: instance.id,
        iat: now,
        exp: now + ATTESTATION_LIFETIME_SEC,
        cnf: { jwk: instance.jwk },
        wallet_name: walletName,
        wallet_link: entityId,
      },
      ATTESTATION_TYP
    )
    instance.attestationsIssued += 1
    return c.json({ wallet_attestation: attestation })
  })

  return { app, entity }
}
