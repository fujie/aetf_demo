import { emit } from '../common/events.js'
import { bi, pick, t } from '../common/i18n.js'
import { randomUUID } from 'node:crypto'
import { type Context, Hono } from 'hono'
import * as jose from 'jose'
import { type SigningKey, jwksOf, readDataFile, signJwt, writeDataFile } from '../common/keys.js'
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
  state: InstanceState
  attestationsIssued: number
  /** Token Status List entry referenced from the Wallet Attestations currently being issued. */
  status?: { idx: number; uri: string }
  /** Entries of earlier attestation generations (left INVALID after a revocation). */
  retiredStatus: { idx: number; uri: string }[]
}

/**
 * active    -> Status List entry VALID (0x00)
 * suspended -> entry SUSPENDED (0x02): temporarily disabled, can be reactivated on the same entry
 * revoked   -> entry INVALID (0x01): terminal for that entry. Reactivation allocates a NEW entry
 *              for subsequently issued attestations; attestations issued before stay invalid.
 */
type InstanceState = 'active' | 'suspended' | 'revoked'
const STATE_LABEL: Record<InstanceState, { ja: string; en: string }> = {
  active: { ja: '有効', en: 'active' },
  suspended: { ja: '一時停止', en: 'suspended' },
  revoked: { ja: '失効', en: 'revoked' },
}

const WALLET_STATUS_LIST_ID = 'wallet-provider-1'

/**
 * Wallet Provider: registers Wallet Instances and issues Wallet Attestations
 * (`oauth-client-attestation+jwt`) bound to the instance key (`cnf.jwk`).
 * Its attestation signing key is published as `wallet_provider.jwks` in its
 * Entity Configuration so that Issuers / Verifiers can validate it via OpenID Federation.
 * Revocation of a Wallet Instance is published through the Token Status List: every attestation
 * carries `status.status_list` (as for Wallet Unit Attestations in the EUDI Wallet ecosystem), and
 * the entry is set to SUSPENDED / INVALID when the instance is suspended / revoked.
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
  // persisted under .data so that registered Wallet Instances survive restarts
  // (the Web Wallet keeps its registration, and the Status List entries are persisted too)
  const STORE = 'wallet-provider/instances.json'
  const instances = new Map<string, WalletInstance>(
    readDataFile<WalletInstance[]>(STORE, []).map((i) => [i.id, i])
  )
  const persist = () => writeDataFile(STORE, [...instances.values()])
  const allocateStatus = async (id: string) =>
    ((await statusApi('/entries', { owner: entityId, label: id })) as { status_list: { idx: number; uri: string } }).status_list

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  app.get('/', (c) => {
    const btn = (i: WalletInstance, action: string, label: string) =>
      `<form style="display:inline" method="post" action="/wallet-instances/${encodeURIComponent(i.id)}/${action}"><button>${label}</button></form>`
    const actions = (i: WalletInstance) =>
      i.state === 'active'
        ? `${btn(i, 'suspend', t('一時停止', 'Suspend'))} ${btn(i, 'revoke', t('失効', 'Revoke'))}`
        : i.state === 'suspended'
          ? `${btn(i, 'reactivate', t('再有効化', 'Reactivate'))} ${btn(i, 'revoke', t('失効', 'Revoke'))}`
          : btn(i, 'reactivate', t('再有効化 (新しい Status List エントリ)', 'Reactivate (new Status List entry)'))
    const rows = [...instances.values()]
      .map(
        (i) => `<tr><td><code>${esc(i.id)}</code></td><td>${esc(i.registeredAt)}</td>
        <td>${i.attestationsIssued}</td>
        <td>${i.status ? `idx ${i.status.idx}` : ''}${i.retiredStatus.length ? `<br><span class="mut">${t('旧', 'old')}: ${i.retiredStatus.map((r) => `idx ${r.idx} (INVALID)`).join(', ')}</span>` : ''}</td>
        <td class="${i.state === 'active' ? 'ok' : 'ng'}">${pick(STATE_LABEL[i.state])}</td><td>${actions(i)}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        'Wallet Provider',
        `<section><p>Entity ID: <code>${esc(entityId)}</code> / <a href="/.well-known/openid-federation">Entity Configuration</a></p>
        <p class="mut">${t(
          '一時停止は Status List を SUSPENDED に、失効は INVALID にします。一時停止からの再有効化は同じエントリを VALID に戻し、失効からの再有効化は INVALID が終端状態のため新しいエントリを割り当てます (以後に発行する Wallet Attestation から有効。失効前の Attestation は無効のまま)。',
          'Suspending sets the Status List entry to SUSPENDED, revoking sets it to INVALID. Reactivating a suspended instance sets the same entry back to VALID; since INVALID is final, reactivating a revoked instance allocates a new entry (effective for attestations issued afterwards; earlier attestations stay invalid).'
        )}</p></section>
        <section><h3>Wallet Instances</h3><table><tr><th>ID</th><th>${t('登録日時', 'Registered')}</th><th>${t('Attestation発行数', 'Attestations issued')}</th><th>Status List</th><th>${t('状態', 'Status')}</th><th></th></tr>${rows}</table></section>`
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
      status = await allocateStatus(id)
    } catch (e) {
      return c.json({ error: 'server_error', error_description: (e as Error).message }, 500)
    }
    instances.set(id, {
      status,
      id,
      jwk: body.jwk,
      thumbprint,
      registeredAt: new Date().toISOString(),
      state: 'active',
      attestationsIssued: 0,
      retiredStatus: [],
    })
    persist()
    emit('Wallet Provider', 'ok', bi('Wallet Instance を登録', 'Registered a Wallet Instance'), id)
    return c.json({ wallet_instance_id: id }, 201)
  })

  const setStatus = (inst: WalletInstance, status: number) =>
    inst.status ? statusApi(`/entries/${inst.status.idx}`, { status }) : Promise.resolve()

  const transition = (action: 'suspend' | 'revoke' | 'reactivate') => async (c: Context) => {
    const inst = instances.get(decodeURIComponent(c.req.param('id') ?? ''))
    if (!inst) return c.redirect('/', 303)
    try {
      if (action === 'suspend' && inst.state === 'active') {
        await setStatus(inst, 2)
        inst.state = 'suspended'
        emit(
          'Wallet Provider',
          'info',
          bi('Wallet Instance を一時停止', 'Suspended the Wallet Instance'),
          bi(`${inst.id} / Status List idx ${inst.status?.idx} を SUSPENDED に更新`, `${inst.id} / Status List idx ${inst.status?.idx} set to SUSPENDED`)
        )
      } else if (action === 'revoke' && inst.state !== 'revoked') {
        // publish the revocation so that already issued Wallet Attestations are rejected too
        await setStatus(inst, 1)
        inst.state = 'revoked'
        emit(
          'Wallet Provider',
          'info',
          bi('Wallet Instance を失効', 'Revoked the Wallet Instance'),
          bi(
            `${inst.id} / Status List idx ${inst.status?.idx} を INVALID に更新 (発行済み Wallet Attestation も無効)`,
            `${inst.id} / Status List idx ${inst.status?.idx} set to INVALID (issued Wallet Attestations become invalid too)`
          )
        )
      } else if (action === 'reactivate' && inst.state === 'suspended') {
        await setStatus(inst, 0)
        inst.state = 'active'
        emit(
          'Wallet Provider',
          'ok',
          bi('Wallet Instance を再有効化', 'Reactivated the Wallet Instance'),
          bi(
            `${inst.id} / Status List idx ${inst.status?.idx} を VALID に戻した (発行済み Wallet Attestation も再び有効)`,
            `${inst.id} / Status List idx ${inst.status?.idx} set back to VALID (issued Wallet Attestations are valid again)`
          )
        )
      } else if (action === 'reactivate' && inst.state === 'revoked') {
        // INVALID is terminal: retire the entry and allocate a fresh one for new attestations
        if (inst.status) inst.retiredStatus.push(inst.status)
        inst.status = await allocateStatus(inst.id)
        inst.state = 'active'
        emit(
          'Wallet Provider',
          'ok',
          bi('Wallet Instance を再有効化', 'Reactivated the Wallet Instance'),
          bi(
            `${inst.id} / 新しい Status List idx ${inst.status.idx} を割当 (失効前の Wallet Attestation は無効のまま、Wallet は再取得が必要)`,
            `${inst.id} / allocated the new Status List idx ${inst.status.idx} (attestations issued before the revocation stay invalid; the wallet must fetch a new one)`
          )
        )
      }
    } catch (e) {
      console.error(e)
      emit('Wallet Provider', 'error', bi('Wallet Instance の状態変更に失敗', 'Failed to change the Wallet Instance state'), (e as Error).message)
    }
    persist()
    return c.redirect('/', 303)
  }
  app.post('/wallet-instances/:id{.+}/suspend', transition('suspend'))
  app.post('/wallet-instances/:id{.+}/revoke', transition('revoke'))
  app.post('/wallet-instances/:id{.+}/reactivate', transition('reactivate'))

  /** Issues a Wallet Attestation. Body: request JWT signed by the instance key. */
  app.post('/wallet-attestations', async (c) => {
    const body = await c.req.json<{ request?: string }>().catch(() => ({}) as { request?: string })
    let instance: WalletInstance | undefined
    try {
      const unverified = jose.decodeJwt(String(body.request))
      instance = instances.get(String(unverified.iss))
      if (!instance) throw new Error('unknown wallet instance')
      if (instance.state !== 'active') throw new Error(`wallet instance ${instance.state}`)
      await jose.jwtVerify(String(body.request), await jose.importJWK(instance.jwk, 'ES256'), {
        typ: ATTESTATION_REQUEST_TYP,
        audience: entityId,
        maxTokenAge: '2m',
      })
    } catch (e) {
      emit('Wallet Provider', 'error', bi('Wallet Attestation の発行を拒否', 'Refused to issue a Wallet Attestation'), (e as Error).message)
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
    persist()
    emit(
      'Wallet Provider',
      'ok',
      bi('Wallet Attestation を発行', 'Issued a Wallet Attestation'),
      bi(`${instance.id} (有効期限 ${ATTESTATION_LIFETIME_SEC / 60} 分)`, `${instance.id} (valid for ${ATTESTATION_LIFETIME_SEC / 60} minutes)`)
    )
    return c.json({ wallet_attestation: attestation })
  })

  return { app, entity }
}
