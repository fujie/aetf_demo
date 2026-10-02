/**
 * HTTP forwarding helpers for the deployment topology: one container runs every entity and
 * dispatches by host name; small proxies (one per public host name) forward to it.
 */

/** Header carrying the public host name from a proxy to the main container. */
export const PUBLIC_HOST_HEADER = 'x-aetf-host'

const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'host', 'content-length']

/** Public host name of a request: proxy header > X-Forwarded-Host > Host. */
export const publicHost = (req: Request) =>
  (req.headers.get(PUBLIC_HOST_HEADER) ?? req.headers.get('x-forwarded-host') ?? req.headers.get('host') ?? '')
    .split(',')[0]
    .trim()
    .toLowerCase()

/** Forwards `req` to `targetOrigin` (same path and query), adding `extraHeaders`. */
export const forward = async (req: Request, targetOrigin: string, extraHeaders: Record<string, string> = {}) => {
  const src = new URL(req.url)
  const headers = new Headers(req.headers)
  for (const h of HOP_BY_HOP) headers.delete(h)
  for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v)
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD'
  const res = await fetch(new URL(src.pathname + src.search, targetOrigin), {
    method: req.method,
    headers,
    body: hasBody ? req.body : undefined,
    redirect: 'manual',
    ...(hasBody ? { duplex: 'half' } : {}),
  } as RequestInit)
  // fetch decodes the body, so the encoding / length headers no longer apply
  const out = new Headers(res.headers)
  for (const h of ['content-encoding', 'content-length', 'transfer-encoding', 'connection']) out.delete(h)
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: out })
}
