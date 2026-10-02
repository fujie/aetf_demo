import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { deflateSync } from 'node:zlib'
import { Hono } from 'hono'
import * as jose from 'jose'
import { DATA_DIR, type SigningKey, jwksOf, signJwt, writeDataFile } from '../common/keys.js'
import { esc, page } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'

export const STATUS_LIST_TYP = 'statuslist+jwt'
const LIST_SIZE = 1024 // bits=1 -> 128 bytes

type StatusList = { id: string; bits: Uint8Array; next: number; owner: string; labels: Map<number, string> }

/**
 * Status List provider implementing the IETF Token Status List (draft-ietf-oauth-status-list)
 * with 1-bit statuses (0 = VALID, 1 = INVALID). The Status List Token signing key is published as
 * `status_list_provider.jwks` so that Verifiers validate it via OpenID Federation.
 */
export const createStatusList = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
  apiKey: string
}) => {
  const { entityId } = opts
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Prototype Status List Provider' },
      status_list_provider: {
        status_list_endpoint_base: `${entityId}/lists`,
        status_list_token_types_supported: [STATUS_LIST_TYP],
        jwks: jwksOf(opts.signingKey),
      },
    },
  })
  // Persisted under .data so that credentials issued before a restart keep a resolvable status.
  const STORE = 'status-lists.json'
  const lists = new Map<string, StatusList>()
  if (existsSync(join(DATA_DIR, STORE))) {
    const saved = JSON.parse(readFileSync(join(DATA_DIR, STORE), 'utf-8')) as {
      id: string; bits: string; next: number; owner: string; labels: [number, string][]
    }[]
    for (const l of saved) {
      lists.set(l.id, { ...l, bits: new Uint8Array(Buffer.from(l.bits, 'base64')), labels: new Map(l.labels) })
    }
  }
  const persist = () =>
    writeDataFile(
      STORE,
      [...lists.values()].map((l) => ({ ...l, bits: Buffer.from(l.bits).toString('base64'), labels: [...l.labels] }))
    )
  const listUri = (id: string) => `${entityId}/lists/${id}`
  const getOrCreate = (id: string, owner: string) => {
    let l = lists.get(id)
    if (!l) {
      l = { id, bits: new Uint8Array(LIST_SIZE / 8), next: 0, owner, labels: new Map() }
      lists.set(id, l)
    }
    return l
  }
  const isSet = (l: StatusList, idx: number) => ((l.bits[idx >> 3] >> (idx & 7)) & 1) === 1

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  const requireApiKey = (auth: string | undefined) => auth === `Bearer ${opts.apiKey}`

  app.get('/', (c) => {
    const body = [...lists.values()]
      .map((l) => {
        const rows = [...Array(l.next).keys()]
          .map(
            (i) =>
              `<tr><td>${i}</td><td>${esc(l.labels.get(i) ?? '')}</td><td>${isSet(l, i) ? '<span class="ng">INVALID (1)</span>' : '<span class="ok">VALID (0)</span>'}</td></tr>`
          )
          .join('')
        return `<section><h3>List <code>${esc(listUri(l.id))}</code></h3><p class="mut">owner: ${esc(l.owner)}</p>
          <table><tr><th>idx</th><th>label</th><th>status</th></tr>${rows}</table></section>`
      })
      .join('')
    return c.html(
      page(
        'Status List',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p></section>${body}`
      )
    )
  })

  /** Allocates a status index for a newly issued credential (Issuer only). */
  app.post('/lists/:id/entries', async (c) => {
    if (!requireApiKey(c.req.header('Authorization'))) return c.json({ error: 'unauthorized' }, 401)
    const body = await c.req.json<{ owner?: string; label?: string }>().catch(() => ({}) as { owner?: string; label?: string })
    const l = getOrCreate(c.req.param('id'), body.owner ?? 'unknown')
    if (l.next >= LIST_SIZE) return c.json({ error: 'list_full' }, 409)
    const idx = l.next++
    if (body.label) l.labels.set(idx, body.label)
    persist()
    return c.json({ status_list: { idx, uri: listUri(l.id) } }, 201)
  })

  /** Sets the status of an index (0 = VALID, 1 = INVALID). */
  app.post('/lists/:id/entries/:idx', async (c) => {
    if (!requireApiKey(c.req.header('Authorization'))) return c.json({ error: 'unauthorized' }, 401)
    const l = lists.get(c.req.param('id'))
    const idx = Number(c.req.param('idx'))
    if (!l || !Number.isInteger(idx) || idx < 0 || idx >= l.next) return c.json({ error: 'not_found' }, 404)
    const { status } = await c.req.json<{ status: number }>()
    if (status === 1) l.bits[idx >> 3] |= 1 << (idx & 7)
    else l.bits[idx >> 3] &= ~(1 << (idx & 7))
    persist()
    return c.json({ idx, status: isSet(l, idx) ? 1 : 0 })
  })

  /** Status List Token (application/statuslist+jwt). */
  app.get('/lists/:id', async (c) => {
    const l = lists.get(c.req.param('id'))
    if (!l) return c.json({ error: 'not_found' }, 404)
    const now = Math.floor(Date.now() / 1000)
    const jwt = await signJwt(
      opts.signingKey,
      {
        iss: entityId,
        sub: listUri(l.id),
        iat: now,
        exp: now + 600,
        ttl: 60,
        status_list: { bits: 1, lst: jose.base64url.encode(deflateSync(l.bits)) },
      },
      STATUS_LIST_TYP
    )
    return c.body(jwt, 200, { 'Content-Type': 'application/statuslist+jwt', 'Cache-Control': 'no-store' })
  })

  return { app, entity }
}
