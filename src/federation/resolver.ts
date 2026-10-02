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
const fetchEntityConfiguration = async (
  entityId: string
): Promise<{ jwt: string; payload: EntityStatement }> => {
  const jwt = await fetchJwt(`${entityId.replace(/\/$/, '')}${WELL_KNOWN_FEDERATION}`)
  checkTyp(jwt)
  const unverified = jose.decodeJwt(jwt) as EntityStatement
  if (unverified.iss !== entityId || unverified.sub !== entityId) {
    throw new Error(`entity configuration iss/sub mismatch for ${entityId}`)
  }
  const { payload } = await verifyWithJwks(jwt, unverified.jwks)
  return { jwt, payload: payload as EntityStatement }
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
  errors: string[]
): Promise<PartialChain | null> => {
  const entityId = ec.payload.sub
  const anchor = anchors.find((a) => a.entityId === entityId)
  if (anchor) {
    // The Trust Anchor's EC must be signed by a key configured out-of-band.
    try {
      await verifyWithJwks(ec.jwt, anchor.jwks)
      return { statements: [], taJwt: ec.jwt, path: [entityId], exp: ec.payload.exp }
    } catch (e) {
      errors.push(`trust anchor ${entityId}: ${(e as Error).message}`)
      return null
    }
  }
  if (depth > MAX_PATH_LENGTH) {
    errors.push(`max path length exceeded at ${entityId}`)
    return null
  }

  for (const authority of ec.payload.authority_hints ?? []) {
    try {
      const superior = await fetchEntityConfiguration(authority)
      const fetchEndpoint = superior.payload.metadata?.federation_entity
        ?.federation_fetch_endpoint as string | undefined
      if (!fetchEndpoint) throw new Error(`${authority} has no federation_fetch_endpoint`)

      const ssJwt = await fetchJwt(`${fetchEndpoint}?sub=${encodeURIComponent(entityId)}`)
      checkTyp(ssJwt)
      // Subordinate statement is signed by the superior's federation key ...
      const { payload: ss } = await verifyWithJwks(ssJwt, superior.payload.jwks)
      const statement = ss as EntityStatement
      if (statement.iss !== authority || statement.sub !== entityId) {
        throw new Error('subordinate statement iss/sub mismatch')
      }
      // ... and vouches for the keys that signed the subordinate's EC.
      await verifyWithJwks(ec.jwt, statement.jwks)

      const upper = await resolveUpwards(superior, anchors, depth + 1, errors)
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
  options: { noCache?: boolean } = {}
): Promise<ResolvedTrustChain> => {
  const cacheKey = `${entityId}|${anchors.map((a) => a.entityId).join(',')}`
  const cached = cache.get(cacheKey)
  if (!options.noCache && cached && cached.exp > Date.now() / 1000 + 30) return cached

  const errors: string[] = []
  const leaf = await fetchEntityConfiguration(entityId)
  const partial = await resolveUpwards(leaf, anchors, 0, errors)
  if (!partial) {
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
    .map((s) => s.payload.metadata_policy)
    .filter((p): p is MetadataPolicy => !!p)
    .reverse() // Trust Anchor first
  metadata = applyPolicy(metadata, mergePolicies(policies))

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
