import { randomUUID } from 'node:crypto'
import type * as jose from 'jose'
import { type SigningKey, signJwt, verifyWithJwks } from './keys.js'
import { type TrustAnchorConfig, resolveEntityMetadata } from '../federation/resolver.js'

/**
 * OpenID Connect Relying Party for OpenID Federation (automatic registration):
 *  - the OP is trusted by resolving its Trust Chain (`openid_provider` metadata)
 *  - the RP is not pre-registered: its `client_id` is its Entity Identifier, and the OP resolves the
 *    RP's Trust Chain to obtain `redirect_uris` / `jwks`
 *  - client authentication at the token endpoint with private_key_jwt (key in the RP's
 *    `openid_relying_party.jwks`)
 */
export type OidcLoginResult = {
  idToken: jose.JWTPayload
  /** Trust chain path of the OP (OP -> ... -> Trust Anchor). */
  opTrustChain: string[]
  opEntityId: string
}

type Pending = { nonce: string; op: string; returnTo?: string; exp: number }

export const createOidcRp = (opts: {
  entityId: string
  rpKey: SigningKey
  anchors: TrustAnchorConfig[]
  redirectPath?: string
  scope?: string
}) => {
  const redirectUri = `${opts.entityId}${opts.redirectPath ?? '/oidc/callback'}`
  const pending = new Map<string, Pending>()

  const resolveOp = (op: string) =>
    resolveEntityMetadata<{
      issuer: string
      authorization_endpoint: string
      token_endpoint: string
      jwks: { keys: jose.JWK[] }
    }>(op, 'openid_provider', opts.anchors)

  return {
    redirectUri,

    /** Builds the authorization request URL for the given OP. */
    async authorizationUrl(op: string, returnTo?: string): Promise<string> {
      const { metadata } = await resolveOp(op)
      const state = randomUUID()
      const nonce = randomUUID()
      const now = Date.now()
      for (const [k, v] of pending) if (v.exp < now) pending.delete(k)
      pending.set(state, { nonce, op, returnTo, exp: now + 10 * 60 * 1000 })
      const url = new URL(metadata.authorization_endpoint)
      url.search = new URLSearchParams({
        response_type: 'code',
        client_id: opts.entityId,
        redirect_uri: redirectUri,
        scope: opts.scope ?? 'openid profile email',
        state,
        nonce,
      }).toString()
      return url.toString()
    },

    /** Handles the authorization response: redeems the code and validates the ID Token. */
    async handleCallback(query: Record<string, string>): Promise<OidcLoginResult & { returnTo?: string }> {
      if (query.error) throw new Error(`OP returned ${query.error}: ${query.error_description ?? ''}`)
      const p = query.state ? pending.get(query.state) : undefined
      if (!p || !query.code) throw new Error('invalid or expired state')
      pending.delete(query.state)

      const op = await resolveOp(p.op)
      const now = Math.floor(Date.now() / 1000)
      const clientAssertion = await signJwt(
        opts.rpKey,
        { iss: opts.entityId, sub: opts.entityId, aud: op.metadata.issuer, jti: randomUUID(), iat: now, exp: now + 60 },
        'JWT'
      )
      const res = await fetch(op.metadata.token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: query.code,
          client_id: opts.entityId,
          redirect_uri: redirectUri,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: clientAssertion,
        }),
      })
      const body = (await res.json()) as { id_token?: string; error_description?: string }
      if (!res.ok || !body.id_token) throw new Error(`OP token error: ${body.error_description ?? res.status}`)
      const { payload } = await verifyWithJwks(body.id_token, op.metadata.jwks, {
        issuer: op.metadata.issuer,
        audience: opts.entityId,
      })
      if (payload.nonce !== p.nonce) throw new Error('nonce mismatch')
      return { idToken: payload, opTrustChain: op.chain.path, opEntityId: p.op, returnTo: p.returnTo }
    },
  }
}
