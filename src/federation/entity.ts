import type { Hono } from 'hono'
import type * as jose from 'jose'
import { type SigningKey, jwksOf, signJwt } from '../common/keys.js'

export const ENTITY_STATEMENT_TYP = 'entity-statement+jwt'
export const WELL_KNOWN_FEDERATION = '/.well-known/openid-federation'

/** OpenID Federation metadata: entity type -> metadata parameters. */
export type FederationMetadata = Record<string, Record<string, unknown>>

/** metadata_policy: entity type -> parameter -> operator -> value. */
export type MetadataPolicy = Record<string, Record<string, Record<string, unknown>>>

/**
 * A subordinate registered with a Trust Anchor or Intermediate Authority
 * (out-of-band "Trust Chain" enrolment in the diagram).
 */
export type SubordinateRegistration = {
  entityId: string
  /** The subordinate's Federation Entity Keys (public). */
  jwks: { keys: jose.JWK[] }
  metadataPolicy?: MetadataPolicy
  /** Metadata values the superior asserts about the subordinate (overrides). */
  metadata?: FederationMetadata
  /** Entity types the subordinate is expected to have (used by the list endpoint filter). */
  entityTypes?: string[]
}

export type FederationEntityOptions = {
  entityId: string
  /** Federation Entity Key used to sign Entity Configuration / Subordinate Statements. */
  federationKey: SigningKey
  /** Superior entities (empty / undefined for a Trust Anchor). */
  authorityHints?: string[]
  metadata: FederationMetadata
  /** Present for Trust Anchors and Intermediate Authorities. */
  subordinates?: Map<string, SubordinateRegistration>
  lifetimeSec?: number
}

export type FederationEntity = FederationEntityOptions & {
  isAuthority: boolean
  entityConfiguration(): Promise<string>
  subordinateStatement(sub: string): Promise<string | null>
  register(reg: SubordinateRegistration): void
}

export const createFederationEntity = (options: FederationEntityOptions): FederationEntity => {
  const lifetime = options.lifetimeSec ?? 24 * 60 * 60
  const isAuthority = options.subordinates !== undefined
  const metadata: FederationMetadata = {
    ...options.metadata,
    federation_entity: {
      ...(options.metadata.federation_entity ?? {}),
      ...(isAuthority
        ? {
            federation_fetch_endpoint: `${options.entityId}/fetch`,
            federation_list_endpoint: `${options.entityId}/list`,
          }
        : {}),
    },
  }

  const now = () => Math.floor(Date.now() / 1000)

  return {
    ...options,
    metadata,
    isAuthority,
    async entityConfiguration() {
      const iat = now()
      return signJwt(
        options.federationKey,
        {
          iss: options.entityId,
          sub: options.entityId,
          iat,
          exp: iat + lifetime,
          jwks: jwksOf(options.federationKey),
          metadata,
          ...(options.authorityHints && options.authorityHints.length > 0
            ? { authority_hints: options.authorityHints }
            : {}),
        },
        ENTITY_STATEMENT_TYP
      )
    },
    async subordinateStatement(sub: string) {
      const reg = options.subordinates?.get(sub)
      if (!reg) return null
      const iat = now()
      return signJwt(
        options.federationKey,
        {
          iss: options.entityId,
          sub: reg.entityId,
          iat,
          exp: iat + lifetime,
          jwks: reg.jwks,
          ...(reg.metadataPolicy ? { metadata_policy: reg.metadataPolicy } : {}),
          ...(reg.metadata ? { metadata: reg.metadata } : {}),
        },
        ENTITY_STATEMENT_TYP
      )
    },
    register(reg: SubordinateRegistration) {
      if (!options.subordinates) throw new Error(`${options.entityId} is not an authority`)
      options.subordinates.set(reg.entityId, reg)
    },
  }
}

/** Mounts the Federation API endpoints (Entity Configuration, fetch, list) on a Hono app. */
export const mountFederationEndpoints = (app: Hono, entity: FederationEntity) => {
  app.get(WELL_KNOWN_FEDERATION, async (c) =>
    c.body(await entity.entityConfiguration(), 200, {
      'Content-Type': 'application/entity-statement+jwt',
    })
  )
  if (!entity.isAuthority) return

  app.get('/fetch', async (c) => {
    const sub = c.req.query('sub')
    if (!sub) return c.json({ error: 'invalid_request', error_description: 'sub is required' }, 400)
    const statement = await entity.subordinateStatement(sub)
    if (!statement) {
      return c.json({ error: 'not_found', error_description: `unknown subordinate: ${sub}` }, 404)
    }
    return c.body(statement, 200, { 'Content-Type': 'application/entity-statement+jwt' })
  })

  app.get('/list', (c) => {
    const entityType = c.req.query('entity_type')
    const subs = [...(entity.subordinates?.values() ?? [])]
      .filter((s) => !entityType || (s.entityTypes ?? []).includes(entityType))
      .map((s) => s.entityId)
    return c.json(subs)
  })
}
