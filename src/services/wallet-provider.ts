import { emit } from '../common/events.js'
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
  /** Token Status List entry referenced from every Wallet Attestation of this instance. */
  status?: { idx: number; uri: string }
}

const WALLET_STATUS_LIST_ID = 'wallet-provider-1'

/**
 * Wallet Provider: registers Wallet Instances and issues Wallet Attestations
 * (`oauth-client-attestation+jwt`) bound to the instance key (`cnf.jwk`).
 * Its attestation signing key is published as `wallet_provider.jwks` in its
 * Entity Configuration so that Issuers / Verifiers can validate it via OpenID Federation.
 * Revocation of a Wallet Instance is published through the Token Status List: every attestation
 * carries `status.status_list` (as for Wallet Unit Attestations in the EUDI Wallet ecosystem), and
 * the entry is set to INVALID when the instance is revoked.
 */
export const createWalletProvider = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
  statusListEntityId: string
  statusListApiKey: string
}) => {
  const statusApi = async (path: string, body: unknown) => {
    const res = await fetch(`${opts.statusListEntityId}/lists/${WALLET_STATUS_LIST_ID}${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${opts.statusListApiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!res.ok) throw new Error(`status list API ${path}: ${res.status} ${await res.text()}`)
    return res.json()
  }
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
        <td>${i.attestationsIssued}</td><td>${i.status ? `idx ${i.status.idx}` : ''}</td><td>${i.revoked ? '<span class="ng">revoked</span>' : '<span class="ok">active</span>'}</td>
        <td>${i.revoked ? '' : `<form method="post" action="/wallet-instances/${encodeURIComponent(i.id)}/revoke"><button>失効</button></form>`}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        'Wallet Provider',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p></section>
        <section><h3>Wallet Instances</h3><table><tr><th>ID</th><th>登録日時</th><th>Attestation発行数</th><th>Status List</th><th>状態</th><th></th></tr>${rows}</table></section>`
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
    let status: WalletInstance['status']
    try {
      status = ((await statusApi('/entries', { owner: entityId, label: id })) as { status_list: { idx: number; uri: string } }).status_list
    } catch (e) {
      return c.json({ error: 'server_error', error_description: (e as Error).message }, 500)
    }
    instances.set(id, {
      status,
      id,
      jwk: body.jwk,
      thumbprint,
      registeredAt: new Date().toISOString(),
      revoked: false,
      attestationsIssued: 0,
    })
    emit('Wallet Provider', 'ok', 'Wallet Instance を登録', id)
    return c.json({ wallet_instance_id: id }, 201)
  })

  app.post('/wallet-instances/:id{.+}/revoke', async (c) => {
    const inst = instances.get(decodeURIComponent(c.req.param('id')))
    if (inst && !inst.revoked) {
      inst.revoked = true
      // publish the revocation so that already issued Wallet Attestations are rejected too
      if (inst.status) await statusApi(`/entries/${inst.status.idx}`, { status: 1 }).catch((e) => console.error(e))
      emit('Wallet Provider', 'info', 'Wallet Instance を失効', `${inst.id} / Status List idx ${inst.status?.idx} を INVALID に更新 (発行済み Wallet Attestation も無効)`)
    }
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
      emit('Wallet Provider', 'error', 'Wallet Attestation の発行を拒否', (e as Error).message)
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
        ...(instance.status ? { status: { status_list: instance.status } } : {}),
        wallet_name: walletName,
        wallet_link: entityId,
      },
      ATTESTATION_TYP
    )
    instance.attestationsIssued += 1
    emit('Wallet Provider', 'ok', 'Wallet Attestation を発行', `${instance.id} (有効期限 ${ATTESTATION_LIFETIME_SEC / 60} 分)`)
    return c.json({ wallet_attestation: attestation })
  })

  return { app, entity }
}
