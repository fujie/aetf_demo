/**
 * Token Status List (draft-ietf-oauth-status-list) — JSON / JWT representation.
 *
 * - Status List (section 4): `bits` ∈ {1,2,4,8}, statuses packed from the least significant bit,
 *   byte array compressed with DEFLATE in the ZLIB format, base64url in `lst`.
 * - Status List Token (section 5.1): `typ` = `statuslist+jwt`, claims `sub` (= uri), `iat`,
 *   `exp`, `ttl`, `status_list`.
 * - Referenced Token (section 6.2): `status.status_list` = { idx, uri }.
 * - Validation rules (section 8.3) for the Relying Party / Holder.
 */
import { deflateSync, inflateSync, constants as zlibConstants } from 'node:zlib'
import * as jose from 'jose'

export const STATUS_LIST_TYP = 'statuslist+jwt'
export const STATUS_LIST_MEDIA_TYPE = 'application/statuslist+jwt'

/** Status Types (section 7.1). */
export const StatusType = {
  VALID: 0x00,
  INVALID: 0x01,
  SUSPENDED: 0x02,
} as const

export const statusTypeName = (value: number): string => {
  switch (value) {
    case StatusType.VALID:
      return 'VALID'
    case StatusType.INVALID:
      return 'INVALID'
    case StatusType.SUSPENDED:
      return 'SUSPENDED'
    default:
      return value === 0x03 || (value >= 0x0c && value <= 0x0f)
        ? `APPLICATION_SPECIFIC(0x${value.toString(16).padStart(2, '0')})`
        : `UNKNOWN(0x${value.toString(16).padStart(2, '0')})`
  }
}

export type Bits = 1 | 2 | 4 | 8
export const ALLOWED_BITS: readonly Bits[] = [1, 2, 4, 8]

/** JSON StatusList structure (section 4.2). */
export type StatusListJson = { bits: Bits; lst: string; aggregation_uri?: string }

/** The uncompressed status array. */
export class StatusList {
  readonly bits: Bits
  readonly bytes: Uint8Array

  constructor(bits: Bits, sizeOrBytes: number | Uint8Array) {
    if (!ALLOWED_BITS.includes(bits)) throw new Error(`invalid bits: ${bits}`)
    this.bits = bits
    this.bytes =
      typeof sizeOrBytes === 'number'
        ? // size in bits divisible by 8 (section 13.4), initialised with 0x00 VALID (section 13.3)
          new Uint8Array(Math.ceil((sizeOrBytes * bits) / 8))
        : sizeOrBytes
  }

  /** Number of statuses the list can hold. */
  get size() {
    return (this.bytes.length * 8) / this.bits
  }

  private locate(idx: number) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= this.size) {
      throw new RangeError(`index ${idx} out of bounds (size ${this.size})`)
    }
    const perByte = 8 / this.bits
    return { byte: Math.floor(idx / perByte), shift: (idx % perByte) * this.bits, mask: (1 << this.bits) - 1 }
  }

  get(idx: number): number {
    const { byte, shift, mask } = this.locate(idx)
    return (this.bytes[byte] >> shift) & mask
  }

  set(idx: number, value: number) {
    const { byte, shift, mask } = this.locate(idx)
    if (!Number.isInteger(value) || value < 0 || value > mask) {
      throw new RangeError(`status 0x${value.toString(16)} does not fit into ${this.bits} bit(s)`)
    }
    this.bytes[byte] = (this.bytes[byte] & ~(mask << shift)) | (value << shift)
  }

  /** DEFLATE + ZLIB, highest compression level (section 4.1 step 4), base64url. */
  toJson(aggregationUri?: string): StatusListJson {
    const compressed = deflateSync(this.bytes, { level: zlibConstants.Z_BEST_COMPRESSION })
    return {
      bits: this.bits,
      lst: jose.base64url.encode(compressed),
      ...(aggregationUri ? { aggregation_uri: aggregationUri } : {}),
    }
  }

  static fromJson(json: unknown): StatusList {
    const sl = json as Partial<StatusListJson> | undefined
    if (!sl || typeof sl !== 'object') throw new Error('status_list must be an object')
    if (!ALLOWED_BITS.includes(sl.bits as Bits)) throw new Error(`invalid bits: ${String(sl.bits)}`)
    if (typeof sl.lst !== 'string' || sl.lst.length === 0) throw new Error('lst must be a non-empty string')
    let bytes: Buffer
    try {
      bytes = inflateSync(Buffer.from(jose.base64url.decode(sl.lst)))
    } catch (e) {
      throw new Error(`lst is not a valid ZLIB/DEFLATE stream: ${(e as Error).message}`)
    }
    return new StatusList(sl.bits as Bits, new Uint8Array(bytes))
  }
}

// ---------------------------------------------------------------------------------------------
// Referenced Token / Relying Party side
// ---------------------------------------------------------------------------------------------

export type StatusListReference = { idx: number; uri: string }

/** Validation rule 1: `status` / `status_list` / `idx` / `uri` (section 6.2). */
export const getStatusListReference = (referencedTokenPayload: Record<string, unknown>): StatusListReference => {
  const status = referencedTokenPayload.status
  if (!status || typeof status !== 'object') throw new Error('Referenced Token has no status claim')
  const ref = (status as Record<string, unknown>).status_list as Record<string, unknown> | undefined
  if (!ref || typeof ref !== 'object') throw new Error('status claim has no status_list')
  if (typeof ref.idx !== 'number' || !Number.isInteger(ref.idx) || ref.idx < 0) {
    throw new Error('status_list.idx must be a non-negative integer')
  }
  if (typeof ref.uri !== 'string') throw new Error('status_list.uri must be a string')
  try {
    new URL(ref.uri)
  } catch {
    throw new Error('status_list.uri must be a URI')
  }
  return { idx: ref.idx, uri: ref.uri }
}

export type StatusListTokenClaims = jose.JWTPayload & {
  sub: string
  iat: number
  exp?: number
  ttl?: number
  status_list: StatusListJson
}

export type StatusCheckResult = {
  idx: number
  uri: string
  status: number
  statusName: string
  /** Issuer (`iss`) of the Status List Token, when present. */
  statusIssuer?: string
  token: StatusListTokenClaims
  fromCache: boolean
}

/** Resolves the verification key(s) for a Status List Token (ecosystem specific, section 11.3). */
export type StatusListKeyResolver = (
  token: string,
  header: jose.ProtectedHeaderParameters,
  unverifiedClaims: jose.JWTPayload
) => Promise<{ keys: jose.JWK[] }>

type CacheEntry = { token: string; claims: StatusListTokenClaims; list: StatusList; refreshAt: number }

/** Lower/upper bounds applied to `ttl` (section 11.5 "reasonable ranges"). */
const MIN_TTL_SEC = 5
const MAX_TTL_SEC = 24 * 60 * 60
const MAX_REDIRECTS = 3

const fetchStatusListToken = async (uri: string, time?: number): Promise<string> => {
  let url = time === undefined ? uri : `${uri}${uri.includes('?') ? '&' : '?'}time=${time}`
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const res = await fetch(url, {
      headers: { Accept: STATUS_LIST_MEDIA_TYPE },
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    })
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      url = new URL(res.headers.get('location') as string, url).toString()
      continue
    }
    if (res.status < 200 || res.status >= 300) throw new Error(`GET ${url} -> ${res.status}`)
    const contentType = res.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase()
    if (contentType !== STATUS_LIST_MEDIA_TYPE) {
      throw new Error(`unexpected content-type ${contentType} (expected ${STATUS_LIST_MEDIA_TYPE})`)
    }
    return (await res.text()).trim()
  }
  throw new Error('too many redirects')
}

/**
 * Status List Token client implementing the validation rules of section 8.3 with ttl-based caching
 * (section 13.7: cache for `ttl` after fetching, never beyond `exp`).
 */
export const createStatusListClient = (resolveKeys: StatusListKeyResolver) => {
  const cache = new Map<string, CacheEntry>()

  const load = async (uri: string, opts: { time?: number }): Promise<CacheEntry & { fromCache: boolean }> => {
    const now = Math.floor(Date.now() / 1000)
    const cached = opts.time === undefined ? cache.get(uri) : undefined
    if (cached && cached.refreshAt > now && (cached.claims.exp === undefined || cached.claims.exp > now)) {
      return { ...cached, fromCache: true }
    }

    // 2. resolve the Status List Token from the URI
    const token = await fetchStatusListToken(uri, opts.time)

    // 3a. validate the JWT (signature, typ) — key resolution is delegated
    const header = jose.decodeProtectedHeader(token)
    if (header.typ !== STATUS_LIST_TYP) throw new Error(`typ must be ${STATUS_LIST_TYP}`)
    const unverified = jose.decodeJwt(token)
    const jwks = await resolveKeys(token, header, unverified)
    const { payload } = await jose.jwtVerify(token, jose.createLocalJWKSet(jwks as jose.JSONWebKeySet), {
      typ: STATUS_LIST_TYP,
      // exp is checked by jose when present (4c); for historical resolution use the requested time
      ...(opts.time !== undefined ? { currentDate: new Date(opts.time * 1000) } : {}),
    })
    // 3b. required claims
    for (const claim of ['sub', 'iat', 'status_list'] as const) {
      if (payload[claim] === undefined) throw new Error(`Status List Token is missing ${claim}`)
    }
    if (payload.ttl !== undefined && (typeof payload.ttl !== 'number' || !(payload.ttl > 0))) {
      throw new Error('ttl must be a positive number')
    }
    const claims = payload as StatusListTokenClaims
    // 4a. sub MUST equal the uri of the Referenced Token
    if (claims.sub !== uri) throw new Error(`Status List Token sub ${claims.sub} != ${uri}`)
    if (opts.time !== undefined && !(claims.iat <= opts.time && (claims.exp === undefined || opts.time < claims.exp))) {
      throw new Error('historical Status List Token is not valid for the requested time')
    }
    // 5. decompress
    const list = StatusList.fromJson(claims.status_list)

    const ttl = Math.min(Math.max(claims.ttl ?? MAX_TTL_SEC, MIN_TTL_SEC), MAX_TTL_SEC)
    const entry: CacheEntry = { token, claims, list, refreshAt: now + ttl }
    if (opts.time === undefined) cache.set(uri, entry)
    return { ...entry, fromCache: false }
  }

  return {
    /** Evaluates the status of a Referenced Token (section 8.3 steps 1-7). */
    async check(referencedTokenPayload: Record<string, unknown>, opts: { time?: number } = {}): Promise<StatusCheckResult> {
      const ref = getStatusListReference(referencedTokenPayload)
      const entry = await load(ref.uri, opts)
      // 6. out of bounds -> reject
      if (ref.idx >= entry.list.size) throw new Error(`idx ${ref.idx} is out of bounds of the Status List`)
      const status = entry.list.get(ref.idx)
      return {
        ...ref,
        status,
        statusName: statusTypeName(status),
        statusIssuer: typeof entry.claims.iss === 'string' ? entry.claims.iss : undefined,
        token: entry.claims,
        fromCache: entry.fromCache,
      }
    },
    clearCache: () => cache.clear(),
  }
}
