import { emit } from '../common/events.js'
import { bi, t } from '../common/i18n.js'
import { randomInt } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { DATA_DIR, type SigningKey, jwksOf, signJwt, writeDataFile } from '../common/keys.js'
import { esc, page, escMsg } from '../common/html.js'
import { createFederationEntity, mountFederationEndpoints } from '../federation/entity.js'
import {
  type Bits,
  STATUS_LIST_MEDIA_TYPE,
  STATUS_LIST_TYP,
  StatusList,
  StatusType,
  statusTypeName,
} from '../status-list/token-status-list.js'

export { STATUS_LIST_TYP }

/** 2 bits per Referenced Token so that VALID / INVALID / SUSPENDED can be expressed (section 7). */
const BITS: Bits = 2
/** 2^12 entries; size in bits divisible by 8 (section 13.4). */
const LIST_SIZE = 4096
/** Status List Token lifetime (`exp`) and caching hint (`ttl`), section 13.7. */
const TOKEN_LIFETIME_SEC = 10 * 60
const TTL_SEC = Number(process.env.STATUS_LIST_TTL ?? 10)
const MAX_HISTORY = 200

const SETTABLE_STATUSES = new Set<number>([StatusType.VALID, StatusType.INVALID, StatusType.SUSPENDED])

type Snapshot = { from: number; bytes: Uint8Array }
type ManagedList = {
  id: string
  owner: string
  list: StatusList
  allocated: Set<number>
  labels: Map<number, string>
  /** Snapshots for historical resolution (section 8.4), oldest first; last = current. */
  history: Snapshot[]
}

type Persisted = {
  id: string
  owner: string
  bits: Bits
  allocated: number[]
  labels: [number, string][]
  history: { from: number; bytes: string }[]
}

/**
 * Status List provider following draft-ietf-oauth-status-list.
 * Acts as Status Issuer (signs Status List Tokens) and Status Provider (serves them).
 *  - Status List Token: `typ` statuslist+jwt, `sub` (= uri), `iat`, `exp`, `ttl`, `status_list`
 *    {bits, lst, aggregation_uri}
 *  - HTTP GET with content negotiation on `application/statuslist+jwt`, CORS enabled
 *  - Historical resolution via the `time` query parameter
 *  - Status List Aggregation (`status_lists`)
 * The GakuNin Issuer (Issuer of the Referenced Tokens) updates statuses through a management API.
 * Key resolution / trust: the token signing key is published as `status_list_provider.jwks` in the
 * entity's OpenID Federation metadata.
 */
export const createStatusList = (opts: {
  entityId: string
  federationKey: SigningKey
  signingKey: SigningKey
  authorityHints: string[]
  apiKey: string
}) => {
  const { entityId } = opts
  const aggregationUri = `${entityId}/aggregation`
  const entity = createFederationEntity({
    entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    metadata: {
      federation_entity: { organization_name: 'Prototype Status List Provider' },
      status_list_provider: {
        status_list_aggregation_endpoint: aggregationUri,
        status_list_token_media_types_supported: [STATUS_LIST_MEDIA_TYPE],
        status_list_token_signing_alg_values_supported: ['ES256'],
        jwks: jwksOf(opts.signingKey),
      },
    },
  })

  // ---- storage (persisted under .data so that statuses survive restarts) ---------------------
  const STORE = 'status-lists-v2.json'
  const lists = new Map<string, ManagedList>()
  if (existsSync(join(DATA_DIR, STORE))) {
    for (const p of JSON.parse(readFileSync(join(DATA_DIR, STORE), 'utf-8')) as Persisted[]) {
      const history = p.history.map((h) => ({ from: h.from, bytes: new Uint8Array(Buffer.from(h.bytes, 'base64')) }))
      lists.set(p.id, {
        id: p.id,
        owner: p.owner,
        list: new StatusList(p.bits, new Uint8Array(history[history.length - 1].bytes)),
        allocated: new Set(p.allocated),
        labels: new Map(p.labels),
        history,
      })
    }
  }
  const persist = () =>
    writeDataFile(
      STORE,
      [...lists.values()].map(
        (l): Persisted => ({
          id: l.id,
          owner: l.owner,
          bits: l.list.bits,
          allocated: [...l.allocated],
          labels: [...l.labels],
          history: l.history.map((h) => ({ from: h.from, bytes: Buffer.from(h.bytes).toString('base64') })),
        })
      )
    )
  const now = () => Math.floor(Date.now() / 1000)
  const snapshot = (l: ManagedList) => {
    const t = now()
    const last = l.history[l.history.length - 1]
    if (last && last.from === t) last.bytes = new Uint8Array(l.list.bytes)
    else l.history.push({ from: t, bytes: new Uint8Array(l.list.bytes) })
    if (l.history.length > MAX_HISTORY) l.history.splice(0, l.history.length - MAX_HISTORY)
  }
  const listUri = (id: string) => `${entityId}/lists/${id}`
  const getOrCreate = (id: string, owner: string) => {
    let l = lists.get(id)
    if (!l) {
      // initialised with 0x00 (VALID), the most common value (section 13.3)
      l = { id, owner, list: new StatusList(BITS, LIST_SIZE), allocated: new Set(), labels: new Map(), history: [] }
      snapshot(l)
      lists.set(id, l)
    }
    return l
  }

  const signToken = (l: ManagedList, bytes: Uint8Array, iat: number, exp: number) =>
    signJwt(
      opts.signingKey,
      {
        iss: entityId,
        sub: listUri(l.id),
        iat,
        exp,
        ttl: TTL_SEC,
        status_list: new StatusList(l.list.bits, bytes).toJson(aggregationUri),
      },
      STATUS_LIST_TYP
    )

  /** Content negotiation (section 8.1): only the JWT representation is offered. */
  const acceptsJwt = (accept: string | undefined) => {
    if (!accept) return true
    return accept
      .split(',')
      .map((v) => v.split(';')[0].trim().toLowerCase())
      .some((t) => t === STATUS_LIST_MEDIA_TYPE || t === 'application/*' || t === '*/*')
  }

  const app = new Hono()
  mountFederationEndpoints(app, entity)
  app.use('/lists/*', cors({ origin: '*', allowMethods: ['GET'] }))
  app.use('/aggregation', cors({ origin: '*', allowMethods: ['GET'] }))

  const requireApiKey = (auth: string | undefined) => auth === `Bearer ${opts.apiKey}`

  app.get('/', (c) => {
    const statusCell = (v: number) =>
      `<span class="${v === StatusType.VALID ? 'ok' : 'ng'}">${esc(statusTypeName(v))} (0x${v.toString(16).padStart(2, '0')})</span>`
    const body = [...lists.values()]
      .map((l) => {
        const rows = [...l.allocated]
          .sort((a, b) => a - b)
          .map((i) => `<tr><td>${i}</td><td>${esc(l.labels.get(i) ?? '')}</td><td>${statusCell(l.list.get(i))}</td></tr>`)
          .join('')
        const history = l.history
          .map((h) => `<a href="/lists/${encodeURIComponent(l.id)}?time=${h.from}">${new Date(h.from * 1000).toISOString()}</a>`)
          .reverse()
          .slice(0, 10)
          .join('<br>')
        return `<section><h3>Status List <code>${escMsg(listUri(l.id))}</code></h3>
          <p class="mut">owner: ${esc(l.owner)} / bits=${l.list.bits} / size=${l.list.size} / ttl=${TTL_SEC}s /
          <a href="/lists/${encodeURIComponent(l.id)}">Status List Token</a></p>
          <table><tr><th>idx</th><th>Referenced Token</th><th>status</th></tr>${rows}</table>
          <p class="mut">${t('履歴', 'History')} (historical resolution, <code>?time=</code>):<br>${history}</p></section>`
      })
      .join('')
    return c.html(
      page(
        'Status List (Token Status List)',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a> /
        <a href="/aggregation">Status List Aggregation</a></p></section>${body}`
      )
    )
  })

  /** Allocates a fresh, random, never re-used index (sections 12.5 / 13.2 / 13.3). Issuer only. */
  app.post('/lists/:id/entries', async (c) => {
    if (!requireApiKey(c.req.header('Authorization'))) return c.json({ error: 'unauthorized' }, 401)
    const body = await c.req.json<{ owner?: string; label?: string }>().catch(() => ({}) as { owner?: string; label?: string })
    const l = getOrCreate(c.req.param('id'), body.owner ?? 'unknown')
    if (l.allocated.size >= l.list.size) return c.json({ error: 'list_full' }, 409)
    let idx: number
    do idx = randomInt(l.list.size)
    while (l.allocated.has(idx))
    l.allocated.add(idx)
    if (body.label) l.labels.set(idx, body.label)
    persist()
    emit('Status List', 'info', bi(`idx ${idx} を割当 (${body.label ?? ''})`, `Allocated idx ${idx} (${body.label ?? ''})`), listUri(l.id))
    return c.json({ status_list: { idx, uri: listUri(l.id) } }, 201)
  })

  /** Updates the status of an index: 0x00 VALID, 0x01 INVALID (terminal), 0x02 SUSPENDED. */
  app.post('/lists/:id/entries/:idx', async (c) => {
    if (!requireApiKey(c.req.header('Authorization'))) return c.json({ error: 'unauthorized' }, 401)
    const l = lists.get(c.req.param('id'))
    const idx = Number(c.req.param('idx'))
    if (!l || !l.allocated.has(idx)) return c.json({ error: 'not_found' }, 404)
    const { status } = await c.req.json<{ status: number }>().catch(() => ({ status: Number.NaN }))
    if (!SETTABLE_STATUSES.has(status)) return c.json({ error: 'invalid_request', error_description: 'unsupported status type' }, 400)
    if (l.list.get(idx) === StatusType.INVALID && status !== StatusType.INVALID) {
      return c.json({ error: 'conflict', error_description: 'INVALID (revoked) is terminal' }, 409)
    }
    l.list.set(idx, status)
    snapshot(l)
    persist()
    emit('Status List', status === StatusType.VALID ? 'ok' : 'info', bi(`idx ${idx} を ${statusTypeName(status)} に更新`, `Set idx ${idx} to ${statusTypeName(status)}`), listUri(l.id))
    return c.json({ idx, status, status_name: statusTypeName(status) })
  })

  /** Status List Token (section 8.1 / 8.2), with historical resolution (section 8.4). */
  app.get('/lists/:id', async (c) => {
    if (!acceptsJwt(c.req.header('Accept'))) {
      return c.json({ error: 'not_acceptable', error_description: `only ${STATUS_LIST_MEDIA_TYPE} is supported` }, 406)
    }
    const l = lists.get(c.req.param('id'))
    if (!l) return c.json({ error: 'not_found' }, 404)
    const headers = { 'Content-Type': STATUS_LIST_MEDIA_TYPE, 'Cache-Control': `max-age=${TTL_SEC}` }

    const timeParam = c.req.query('time')
    if (timeParam !== undefined) {
      const t = Number(timeParam)
      if (!Number.isInteger(t) || t < 0) return c.json({ error: 'invalid_request' }, 400)
      const i = l.history.findLastIndex((h) => h.from <= t)
      if (i < 0 || t > now()) return c.json({ error: 'not_found', error_description: 'no status list for that time' }, 404)
      const next = l.history[i + 1]
      const exp = next ? next.from : now() + TOKEN_LIFETIME_SEC
      return c.body(await signToken(l, l.history[i].bytes, l.history[i].from, exp), 200, headers)
    }
    const t = now()
    return c.body(await signToken(l, l.list.bytes, t, t + TOKEN_LIFETIME_SEC), 200, headers)
  })

  /** Status List Aggregation (section 9.3). Optional `issuer` filter. */
  app.get('/aggregation', (c) => {
    const issuer = c.req.query('issuer')
    return c.json({
      status_lists: [...lists.values()].filter((l) => !issuer || l.owner === issuer).map((l) => listUri(l.id)),
    })
  })

  return { app, entity, aggregationUri }
}
