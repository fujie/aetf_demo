import * as jose from 'jose'
import { verifyWithJwks } from './keys.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'
import { federationStatusListKeyResolver } from '../status-list/federation-key-resolver.js'
import { StatusType, createStatusListClient } from '../status-list/token-status-list.js'

/**
 * OAuth 2.0 Attestation-Based Client Authentication
 * (draft-ietf-oauth-attestation-based-client-auth) as used for Wallet Attestations.
 */
export const ATTESTATION_HEADER = 'OAuth-Client-Attestation'
export const ATTESTATION_POP_HEADER = 'OAuth-Client-Attestation-PoP'
export const ATTESTATION_TYP = 'oauth-client-attestation+jwt'
export const ATTESTATION_POP_TYP = 'oauth-client-attestation-pop+jwt'

export type VerifiedWalletAttestation = {
  clientId: string
  walletProvider: string
  walletName?: string
  trustChainPath: string[]
  holderKey: jose.JWK
  /** Wallet Instance status from the Token Status List referenced by the attestation. */
  status: { idx: number; uri: string; statusName: string }
}

const statusClients = new Map<string, ReturnType<typeof createStatusListClient>>()
const statusClientFor = (anchors: TrustAnchorConfig[]) => {
  const key = anchors.map((a) => a.entityId).join(',')
  let client = statusClients.get(key)
  if (!client) {
    client = createStatusListClient(federationStatusListKeyResolver(anchors))
    statusClients.set(key, client)
  }
  return client
}

const seenJti = new Map<string, number>()

/** Drops cached Status List tokens and replay state (used when the whole demo is reset). */
export const resetWalletAttestationState = () => {
  statusClients.clear()
  seenJti.clear()
}

export class WalletAttestationError extends Error {}

/**
 * Verifies the Wallet Attestation presented by a Wallet Instance:
 *  1. Resolve the Wallet Provider (attestation `iss`) via OpenID Federation and require `wallet_provider` metadata
 *  2. Verify the attestation signature with the Wallet Provider key from the resolved metadata
 *  3. Verify the PoP JWT with the instance key in `cnf.jwk` (audience = this server)
 *  4. Check that the Wallet Instance has not been revoked: the attestation references a Token
 *     Status List entry (`status.status_list`) that the Wallet Provider sets to INVALID on revocation
 */
export const verifyWalletAttestation = async (
  attestation: string | undefined,
  pop: string | undefined,
  expectedAudience: string,
  anchors: TrustAnchorConfig[]
): Promise<VerifiedWalletAttestation> => {
  if (!attestation || !pop) {
    throw new WalletAttestationError(
      `${ATTESTATION_HEADER} and ${ATTESTATION_POP_HEADER} headers are required`
    )
  }
  let unverified: jose.JWTPayload
  try {
    unverified = jose.decodeJwt(attestation)
  } catch {
    throw new WalletAttestationError('wallet attestation is not a JWT')
  }
  if (typeof unverified.iss !== 'string') throw new WalletAttestationError('attestation iss missing')

  let walletProviderMetadata: { jwks?: { keys: jose.JWK[] }; wallet_name?: string }
  let path: string[]
  try {
    const resolved = await resolveEntityMetadata<typeof walletProviderMetadata>(
      unverified.iss,
      'wallet_provider',
      anchors
    )
    walletProviderMetadata = resolved.metadata
    path = resolved.chain.path
  } catch (e) {
    throw new WalletAttestationError(`untrusted wallet provider: ${(e as Error).message}`)
  }

  let payload: jose.JWTPayload
  try {
    ;({ payload } = await verifyWithJwks(attestation, walletProviderMetadata.jwks, {
      typ: ATTESTATION_TYP,
      issuer: unverified.iss,
      requiredClaims: ['sub', 'exp', 'cnf'],
    }))
  } catch (e) {
    throw new WalletAttestationError(`invalid wallet attestation: ${(e as Error).message}`)
  }
  const cnf = payload.cnf as { jwk?: jose.JWK } | undefined
  if (!cnf?.jwk) throw new WalletAttestationError('attestation cnf.jwk missing')

  let popPayload: jose.JWTPayload
  try {
    const key = await jose.importJWK(cnf.jwk, 'ES256')
    ;({ payload: popPayload } = await jose.jwtVerify(pop, key, {
      typ: ATTESTATION_POP_TYP,
      audience: expectedAudience,
      maxTokenAge: '5m',
      algorithms: ['ES256'],
      requiredClaims: ['jti', 'iat'],
    }))
  } catch (e) {
    throw new WalletAttestationError(`invalid attestation PoP: ${(e as Error).message}`)
  }
  if (popPayload.iss !== undefined && popPayload.iss !== payload.sub) {
    throw new WalletAttestationError('PoP iss does not match attestation sub')
  }
  const now = Date.now()
  for (const [k, exp] of seenJti) if (exp < now) seenJti.delete(k)
  const jtiKey = `${payload.sub}:${popPayload.jti}`
  if (seenJti.has(jtiKey)) throw new WalletAttestationError('PoP jti replayed')
  seenJti.set(jtiKey, now + 10 * 60 * 1000)

  let status: VerifiedWalletAttestation['status']
  try {
    const st = await statusClientFor(anchors).check(payload as Record<string, unknown>)
    status = { idx: st.idx, uri: st.uri, statusName: st.statusName }
    if (st.status !== StatusType.VALID) {
      throw new WalletAttestationError(`wallet instance is ${st.statusName} (Status List idx ${st.idx})`)
    }
  } catch (e) {
    if (e instanceof WalletAttestationError) throw e
    throw new WalletAttestationError(`wallet attestation status check failed: ${(e as Error).message}`)
  }

  return {
    status,
    clientId: String(payload.sub),
    walletProvider: unverified.iss,
    walletName: (payload.wallet_name as string | undefined) ?? walletProviderMetadata.wallet_name,
    trustChainPath: path,
    holderKey: cnf.jwk,
  }
}
