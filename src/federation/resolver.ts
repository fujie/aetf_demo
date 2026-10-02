import * as jose from 'jose'
import { verifyWithJwks } from '../common/keys.js'
import {
  ENTITY_STATEMENT_TYP,
  type FederationMetadata,
  type MetadataPolicy,
  WELL_KNOWN_FEDERATION,
} from './entity.js'
import { applyPolicy, mergePolicies } from './policy.js'

export type TrustAnchorConfig = { entityId: string; jwks: { keys: jose.JWK[] } }

type EntityStatement = jose.JWTPayload & {
  iss: string
  sub: string
  exp: number
  jwks?: { keys: jose.JWK[] }
  metadata?: FederationMetadata
  metadata_policy?: MetadataPolicy
  authority_hints?: string[]
}

export type ResolvedTrustChain = {
  entityId: string
  trustAnchor: string
  /** Entity IDs from leaf up to the Trust Anchor. */
  path: string[]
  /** Trust chain JWTs: [leaf EC, SS(leaf), ..., TA EC]. */
  chain: string[]
  /** Resolved metadata after applying metadata policies. */
  metadata: FederationMetadata
  exp: number
}

const MAX_PATH_LENGTH = 5

/**
 * Trace of a Trust Chain resolution (for visualisation): every HTTP fetch, authority_hints
 * discovery and signature verification, in order.
 */
export type TraceEvent =
  | { type: 'fetch'; kind: 'ec' | 'ss'; url: string; entity: string; issuer?: string; ok: boolean; error?: string }
  | { type: 'authority_hints'; entity: string; hints: string[] }
  | {
      type: 'verify'
      /** statement verified: EC of `entity`, or SS issued by `issuer` about `entity` */
      kind: 'ec' | 'ss'
      entity: string
      issuer?: string
      /** where the verification key came from */
      keySource: 'self' | 'subordinate_statement' | 'superior_ec' | 'trust_anchor_config'
      keySourceEntity?: string
      kid?: string
      ok: boolean
      error?: string
    }
  | { type: 'statement'; kind: 'ec' | 'ss'; entity: string; issuer: string; jwt: string }
  | {
      type: 'metadata'
      /** metadata in the leaf's Entity Configuration */
      leaf: FederationMetadata
      /** metadata set by the immediate superior in its Subordinate Statement (overrides the leaf) */
      superiorMetadata?: { issuer: string; metadata: FederationMetadata }
      /** metadata_policy of each Subordinate Statement, Trust Anchor first */
      policies: { issuer: string; policy: MetadataPolicy }[]
      merged: MetadataPolicy
      resolved: FederationMetadata
    }
  | { type: 'error'; message: string }
export type Trace = TraceEvent[]

const fetchJwt = async (url: string): Promise<string> => {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`)
  return (await res.text()).trim()
}

const checkTyp = (jwt: string) => {
  const header = jose.decodeProtectedHeader(jwt)
  if (header.typ !== ENTITY_STATEMENT_TYP) {
    throw new Error(`unexpected typ ${String(header.typ)}`)
  }
}

/** Fetches and verifies an Entity Configuration (self-signed). */
const kidOf = (jwt: string) => {
  try {
    return jose.decodeProtectedHeader(jwt).kid
  } catch {
    return undefined
  }
}

const fetchEntityConfiguration = async (
  entityId: string,
  trace?: Trace
): Promise<{ jwt: string; payload: EntityStatement }> => {
  const url = `${entityId.replace(/\/$/, '')}${WELL_KNOWN_FEDERATION}`
  let jwt: string
  try {
    jwt = await fetchJwt(url)
    checkTyp(jwt)
  } catch (e) {
    trace?.push({ type: 'fetch', kind: 'ec', url, entity: entityId, ok: false, error: (e as Error).message })
    throw e
  }
  trace?.push({ type: 'fetch', kind: 'ec', url, entity: entityId, ok: true })
  trace?.push({ type: 'statement', kind: 'ec', entity: entityId, issuer: entityId, jwt })
  const unverified = jose.decodeJwt(jwt) as EntityStatement
  if (unverified.iss !== entityId || unverified.sub !== entityId) {
    throw new Error(`entity configuration iss/sub mismatch for ${entityId}`)
  }
  try {
    const { payload } = await verifyWithJwks(jwt, unverified.jwks)
    trace?.push({ type: 'verify', kind: 'ec', entity: entityId, keySource: 'self', kid: kidOf(jwt), ok: true })
    return { jwt, payload: payload as EntityStatement }
  } catch (e) {
    trace?.push({ type: 'verify', kind: 'ec', entity: entityId, keySource: 'self', kid: kidOf(jwt), ok: false, error: (e as Error).message })
    throw e
  }
}

type PartialChain = {
  /** [SS(entity) by superior, SS(superior) by its superior, ...] */
  statements: { jwt: string; payload: EntityStatement }[]
  taJwt: string
  path: string[]
  exp: number
}

/**
 * Builds a verified chain from `entity` (whose EC is already verified only as self-signed)
 * up to one of the configured Trust Anchors.
 */
const resolveUpwards = async (
  ec: { jwt: string; payload: EntityStatement },
  anchors: TrustAnchorConfig[],
  depth: number,
  errors: string[],
  trace?: Trace
): Promise<PartialChain | null> => {
  const entityId = ec.payload.sub
  const anchor = anchors.find((a) => a.entityId === entityId)
  if (anchor) {
    // The Trust Anchor's EC must be signed by a key configured out-of-band.
    try {
      await verifyWithJwks(ec.jwt, anchor.jwks)
      trace?.push({ type: 'verify', kind: 'ec', entity: entityId, keySource: 'trust_anchor_config', kid: kidOf(ec.jwt), ok: true })
      return { statements: [], taJwt: ec.jwt, path: [entityId], exp: ec.payload.exp }
    } catch (e) {
      trace?.push({ type: 'verify', kind: 'ec', entity: entityId, keySource: 'trust_anchor_config', kid: kidOf(ec.jwt), ok: false, error: (e as Error).message })
      errors.push(`trust anchor ${entityId}: ${(e as Error).message}`)
      return null
    }
  }
  trace?.push({ type: 'authority_hints', entity: entityId, hints: ec.payload.authority_hints ?? [] })
  if (depth > MAX_PATH_LENGTH) {
    errors.push(`max path length exceeded at ${entityId}`)
    return null
  }

  for (const authority of ec.payload.authority_hints ?? []) {
    try {
      const superior = await fetchEntityConfiguration(authority, trace)
      const fetchEndpoint = superior.payload.metadata?.federation_entity
        ?.federation_fetch_endpoint as string | undefined
      if (!fetchEndpoint) throw new Error(`${authority} has no federation_fetch_endpoint`)

      const ssUrl = `${fetchEndpoint}?sub=${encodeURIComponent(entityId)}`
      let ssJwt: string
      try {
        ssJwt = await fetchJwt(ssUrl)
        checkTyp(ssJwt)
      } catch (e) {
        trace?.push({ type: 'fetch', kind: 'ss', url: ssUrl, entity: entityId, issuer: authority, ok: false, error: (e as Error).message })
        throw e
      }
      trace?.push({ type: 'fetch', kind: 'ss', url: ssUrl, entity: entityId, issuer: authority, ok: true })
      trace?.push({ type: 'statement', kind: 'ss', entity: entityId, issuer: authority, jwt: ssJwt })
      // Subordinate statement is signed by the superior's federation key ...
      const verifyStep = async <T>(
        f: () => Promise<T>,
        ev: Omit<Extract<TraceEvent, { type: 'verify' }>, 'type' | 'ok' | 'error'>
      ) => {
        try {
          const r = await f()
          trace?.push({ type: 'verify', ...ev, ok: true })
          return r
        } catch (e) {
          trace?.push({ type: 'verify', ...ev, ok: false, error: (e as Error).message })
          throw e
        }
      }
      const { payload: ss } = await verifyStep(() => verifyWithJwks(ssJwt, superior.payload.jwks), {
        kind: 'ss',
        entity: entityId,
        issuer: authority,
        keySource: 'superior_ec',
        keySourceEntity: authority,
        kid: kidOf(ssJwt),
      })
      const statement = ss as EntityStatement
      if (statement.iss !== authority || statement.sub !== entityId) {
        throw new Error('subordinate statement iss/sub mismatch')
      }
      // ... and vouches for the keys that signed the subordinate's EC.
      await verifyStep(() => verifyWithJwks(ec.jwt, statement.jwks), {
        kind: 'ec',
        entity: entityId,
        keySource: 'subordinate_statement',
        keySourceEntity: authority,
        kid: kidOf(ec.jwt),
      })

      const upper = await resolveUpwards(superior, anchors, depth + 1, errors, trace)
      if (!upper) continue
      return {
        statements: [{ jwt: ssJwt, payload: statement }, ...upper.statements],
        taJwt: upper.taJwt,
        path: [entityId, ...upper.path],
        exp: Math.min(ec.payload.exp, statement.exp, upper.exp),
      }
    } catch (e) {
      errors.push(`${entityId} -> ${authority}: ${(e as Error).message}`)
    }
  }
  if ((ec.payload.authority_hints ?? []).length === 0) {
    errors.push(`${entityId} has no authority_hints and is not a configured trust anchor`)
  }
  return null
}

const cache = new Map<string, ResolvedTrustChain>()

/**
 * Resolves and validates a Trust Chain for `entityId` against the given Trust Anchors,
 * then applies metadata policies to obtain the entity's resolved metadata.
 */
export const resolveTrustChain = async (
  entityId: string,
  anchors: TrustAnchorConfig[],
  options: { noCache?: boolean; trace?: Trace } = {}
): Promise<ResolvedTrustChain> => {
  const cacheKey = `${entityId}|${anchors.map((a) => a.entityId).join(',')}`
  const cached = cache.get(cacheKey)
  if (!options.noCache && !options.trace && cached && cached.exp > Date.now() / 1000 + 30) return cached

  const trace = options.trace
  const errors: string[] = []
  const leaf = await fetchEntityConfiguration(entityId, trace)
  const partial = await resolveUpwards(leaf, anchors, 0, errors, trace)
  if (!partial) {
    trace?.push({ type: 'error', message: errors.join('; ') })
    throw new Error(`no valid trust chain for ${entityId}: ${errors.join('; ')}`)
  }

  let metadata: FederationMetadata = structuredClone(leaf.payload.metadata ?? {})
  const immediate = partial.statements[0]?.payload
  if (immediate?.metadata) {
    for (const [type, params] of Object.entries(immediate.metadata)) {
      metadata[type] = { ...(metadata[type] ?? {}), ...params }
    }
  }
  const policies = partial.statements
    .filter((s) => !!s.payload.metadata_policy)
    .map((s) => ({ issuer: s.payload.iss, policy: s.payload.metadata_policy as MetadataPolicy }))
    .reverse() // Trust Anchor first
  let merged: MetadataPolicy
  try {
    merged = mergePolicies(policies.map((p) => p.policy))
    metadata = applyPolicy(metadata, merged)
  } catch (e) {
    const message = `metadata_policy: ${(e as Error).message}`
    trace?.push({ type: 'error', message })
    throw new Error(`no valid trust chain for ${entityId}: ${message}`)
  }
  trace?.push({
    type: 'metadata',
    leaf: structuredClone(leaf.payload.metadata ?? {}),
    ...(immediate?.metadata ? { superiorMetadata: { issuer: immediate.iss, metadata: immediate.metadata } } : {}),
    policies,
    merged,
    resolved: structuredClone(metadata),
  })

  const resolved: ResolvedTrustChain = {
    entityId,
    trustAnchor: partial.path[partial.path.length - 1],
    path: partial.path,
    chain: [leaf.jwt, ...partial.statements.map((s) => s.jwt), partial.taJwt],
    metadata,
    exp: partial.exp,
  }
  cache.set(cacheKey, resolved)
  return resolved
}

/** Resolves a trust chain and returns the metadata of the requested entity type, or throws. */
export const resolveEntityMetadata = async <T = Record<string, unknown>>(
  entityId: string,
  entityType: string,
  anchors: TrustAnchorConfig[]
): Promise<{ metadata: T; chain: ResolvedTrustChain }> => {
  const chain = await resolveTrustChain(entityId, anchors)
  const metadata = chain.metadata[entityType]
  if (!metadata) {
    throw new Error(`${entityId} is not registered as ${entityType} in the federation`)
  }
  return { metadata: metadata as T, chain }
}

export const clearTrustChainCache = () => cache.clear()
