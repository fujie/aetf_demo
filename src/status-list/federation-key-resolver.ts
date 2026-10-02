import type * as jose from 'jose'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'
import type { StatusListKeyResolver } from './token-status-list.js'

/**
 * Key resolution and trust management for Status List Tokens (draft section 11.3), profiled for
 * this ecosystem: the Status Issuer is an OpenID Federation entity (`iss` of the token) with
 * `status_list_provider` metadata, reachable from the configured Trust Anchor; its signing keys
 * are taken from `status_list_provider.jwks` of the resolved metadata. The Status List Token URI
 * must be hosted under the Status Issuer's entity identifier.
 */
export const federationStatusListKeyResolver =
  (anchors: TrustAnchorConfig[]): StatusListKeyResolver =>
  async (_token, _header, claims) => {
    if (typeof claims.iss !== 'string') throw new Error('Status List Token has no iss (Status Issuer)')
    if (typeof claims.sub !== 'string' || !claims.sub.startsWith(`${claims.iss.replace(/\/$/, '')}/`)) {
      throw new Error('Status List Token URI is not hosted under its Status Issuer')
    }
    const { metadata } = await resolveEntityMetadata<{ jwks?: { keys: jose.JWK[] } }>(
      claims.iss,
      'status_list_provider',
      anchors
    )
    if (!metadata.jwks) throw new Error('status_list_provider metadata has no jwks')
    return metadata.jwks
  }
