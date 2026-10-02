import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import * as jose from 'jose'

export const DATA_DIR = process.env.DATA_DIR ?? join(process.cwd(), '.data')

/** ES256 signing key used by an entity (federation key or protocol key). */
export type SigningKey = {
  kid: string
  alg: 'ES256'
  privateKey: CryptoKey
  publicJwk: jose.JWK
  privateJwk: jose.JWK
}

const toSigningKey = async (privateJwk: jose.JWK): Promise<SigningKey> => {
  const { d: _d, ...pub } = privateJwk
  const kid = privateJwk.kid ?? (await jose.calculateJwkThumbprint(pub))
  const publicJwk: jose.JWK = { ...pub, kid, alg: 'ES256', use: 'sig' }
  const privateKey = (await jose.importJWK({ ...privateJwk, kid }, 'ES256')) as CryptoKey
  return { kid, alg: 'ES256', privateKey, publicJwk, privateJwk: { ...privateJwk, kid } }
}

/**
 * Loads an ES256 key from `.data/keys/<name>.json`, creating it on first use so
 * that entity identities survive restarts.
 */
export const loadOrCreateKey = async (name: string): Promise<SigningKey> => {
  const path = join(DATA_DIR, 'keys', `${name}.json`)
  if (existsSync(path)) {
    return toSigningKey(JSON.parse(readFileSync(path, 'utf-8')))
  }
  const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  const privateJwk = await jose.exportJWK(privateKey)
  const pub = { kty: privateJwk.kty, crv: privateJwk.crv, x: privateJwk.x, y: privateJwk.y }
  privateJwk.kid = await jose.calculateJwkThumbprint(pub as jose.JWK)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(privateJwk, null, 2), { mode: 0o600 })
  return toSigningKey(privateJwk)
}

export const jwksOf = (...keys: SigningKey[]): { keys: jose.JWK[] } => ({
  keys: keys.map((k) => k.publicJwk),
})

export const signJwt = async (
  key: SigningKey,
  payload: jose.JWTPayload,
  typ: string,
  extraHeader: Record<string, unknown> = {}
): Promise<string> =>
  new jose.SignJWT(payload)
    .setProtectedHeader({ ...extraHeader, alg: key.alg, kid: key.kid, typ })
    .sign(key.privateKey)

/** Verifies a compact JWS against a JWKS, selecting the key by `kid`. */
export const verifyWithJwks = async (
  jwt: string,
  jwks: { keys: jose.JWK[] } | undefined,
  options: jose.JWTVerifyOptions = {}
): Promise<jose.JWTVerifyResult> => {
  if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error('no keys available to verify JWT')
  }
  return jose.jwtVerify(jwt, jose.createLocalJWKSet(jwks as jose.JSONWebKeySet), {
    algorithms: ['ES256'],
    ...options,
  })
}

/** Reads a JSON file under DATA_DIR, or returns `fallback` when it does not exist. */
export const readDataFile = <T>(name: string, fallback: T): T => {
  const path = join(DATA_DIR, name)
  return existsSync(path) ? (JSON.parse(readFileSync(path, 'utf-8')) as T) : fallback
}

export const writeDataFile = (name: string, content: unknown) => {
  const path = join(DATA_DIR, name)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content, null, 2))
  return path
}
