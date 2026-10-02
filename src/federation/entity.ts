import type { Hono } from 'hono'
import * as jose from 'jose'
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
  /** Fault injection for testing broken trust chains (demo settings). */
  disabled?: boolean
  /** Subordinate Statement carries a key that is not the subordinate's. */
  wrongJwks?: boolean
  /** Subordinate Statement is issued already expired. */
  expired?: boolean
}

/** Fault injection on an entity's own Entity Configuration (demo settings). */
export type EntityFaults = {
  /** Entity Configuration is not published (404). */
  ecDisabled?: boolean
  /**
   * Key rotation not propagated: the entity signs (and advertises) a new key, but its superiors'
   * Subordinate Statements / the configured Trust Anchor key still hold the old one.
   */
  rotatedKey?: SigningKey
}

/** A key that belongs to nobody (for wrongJwks). */
let strayKey: Promise<SigningKey> | undefined
export const ephemeralKey = async (): Promise<SigningKey> => {
  const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  const privateJwk = await jose.exportJWK(privateKey)
  const { d: _d, ...pub } = privateJwk
  const kid = await jose.calculateJwkThumbprint(pub)
  return {
    kid,
    alg: 'ES256',
    privateKey: privateKey as CryptoKey,
    publicJwk: { ...pub, kid, alg: 'ES256', use: 'sig' },
    privateJwk: { ...privateJwk, kid },
  }
}
const strayJwks = async () => jwksOf(await (strayKey ??= ephemeralKey()))

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
  faults: EntityFaults
  /** Returns null when the Entity Configuration is not published (fault injection). */
  entityConfiguration(): Promise<string | null>
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

  const self: FederationEntity = {
    ...options,
    metadata,
    isAuthority,
    faults: {},
    async entityConfiguration() {
      if (self.faults.ecDisabled) return null
      const key = self.faults.rotatedKey ?? options.federationKey
      const iat = now()
      return signJwt(
        key,
        {
          iss: options.entityId,
          sub: options.entityId,
          iat,
          exp: iat + lifetime,
          jwks: jwksOf(key),
          metadata,
          ...(self.authorityHints && self.authorityHints.length > 0
            ? { authority_hints: self.authorityHints }
            : {}),
        },
        ENTITY_STATEMENT_TYP
      )
    },
    async subordinateStatement(sub: string) {
      const reg = options.subordinates?.get(sub)
      if (!reg || reg.disabled) return null
      const iat = reg.expired ? now() - 2 * 3600 : now()
      return signJwt(
        self.faults.rotatedKey ?? options.federationKey,
        {
          iss: options.entityId,
          sub: reg.entityId,
          iat,
          exp: reg.expired ? iat + 3600 : iat + lifetime,
          jwks: reg.wrongJwks ? await strayJwks() : reg.jwks,
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
  return self
}

/** Mounts the Federation API endpoints (Entity Configuration, fetch, list) on a Hono app. */
export const mountFederationEndpoints = (app: Hono, entity: FederationEntity) => {
  app.get(WELL_KNOWN_FEDERATION, async (c) => {
    const ec = await entity.entityConfiguration()
    if (!ec) return c.json({ error: 'not_found', error_description: 'entity configuration is not published' }, 404)
    return c.body(ec, 200, { 'Content-Type': 'application/entity-statement+jwt' })
  })
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
      .filter((s) => !s.disabled)
      .filter((s) => !entityType || (s.entityTypes ?? []).includes(entityType))
      .map((s) => s.entityId)
    return c.json(subs)
  })
}
