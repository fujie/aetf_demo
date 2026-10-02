import { t } from '../common/i18n.js'
import { Hono } from 'hono'
import type { SigningKey } from '../common/keys.js'
import { esc, page, escMsg } from '../common/html.js'
import {
  type SubordinateRegistration,
  createFederationEntity,
  mountFederationEndpoints,
} from '../federation/entity.js'

/** Trust Anchor (eduGAIN) / Intermediate Authority (NII, I2). */
export const createAuthority = (opts: {
  entityId: string
  organizationName: string
  federationKey: SigningKey
  authorityHints?: string[]
}) => {
  const entity = createFederationEntity({
    entityId: opts.entityId,
    federationKey: opts.federationKey,
    authorityHints: opts.authorityHints,
    subordinates: new Map<string, SubordinateRegistration>(),
    metadata: {
      federation_entity: { organization_name: opts.organizationName },
    },
  })

  const app = new Hono()
  mountFederationEndpoints(app, entity)

  app.get('/', (c) => {
    const hints = entity.authorityHints ?? []
    const role = opts.authorityHints?.length ? 'Intermediate Authority' : 'Trust Anchor'
    const rows = [...(entity.subordinates?.values() ?? [])]
      .map(
        (s) => `<tr><td><a href="${esc(s.entityId)}/">${escMsg(s.entityId)}</a></td>
          <td>${esc((s.entityTypes ?? []).join(', '))}${s.disabled ? ` <span class="ng">${t('登録停止中', 'suspended')}</span>` : ''}${s.wrongJwks ? ` <span class="ng">${t('jwks 不正', 'wrong jwks')}</span>` : ''}${s.expired ? ` <span class="ng">${t('期限切れ', 'expired')}</span>` : ''}</td>
          <td><a href="/fetch?sub=${encodeURIComponent(s.entityId)}">Subordinate Statement</a></td>
          <td>${s.metadataPolicy ? `<pre>${esc(JSON.stringify(s.metadataPolicy, null, 1))}</pre>` : ''}</td></tr>`
      )
      .join('')
    return c.html(
      page(
        `${opts.organizationName} (${role})`,
        `<section><p>Entity ID: <code>${esc(opts.entityId)}</code></p>
        <p><a href="/.well-known/openid-federation">Entity Configuration</a>
        ${hints.length ? ` / authority_hints: ${hints.map((h) => escMsg(h)).join(', ')}` : ''}</p></section>
        <section><h3>Subordinates</h3><table><tr><th>Entity</th><th>Entity types</th><th>Statement</th><th>metadata_policy</th></tr>${rows}</table></section>`
      )
    )
  })

  return { app, entity }
}
