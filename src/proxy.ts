import { serve } from '@hono/node-server'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:https'
import { PUBLIC_HOST_HEADER, forward } from './common/forward.js'

/**
 * Public front for one entity (deployment): every Azure Container App except the main one runs
 * this proxy. Its Azure-assigned host name is the entity's identifier; requests are forwarded to
 * the main container (UPSTREAM, internal ingress) with the public host name in a header, which the
 * main container uses to pick the entity.
 */
const upstream = process.env.UPSTREAM
const port = Number(process.env.PORT ?? 8080)
if (!upstream) {
  console.error('UPSTREAM (URL of the main container) is required')
  process.exit(1)
}

// Optional TLS (TLS_CERT / TLS_KEY files): only for running this topology outside Azure, where
// Container Apps ingress terminates TLS in front of the proxy.
const tls =
  process.env.TLS_CERT && process.env.TLS_KEY
    ? { createServer, serverOptions: { cert: readFileSync(process.env.TLS_CERT), key: readFileSync(process.env.TLS_KEY) } }
    : {}

serve(
  {
    ...tls,
    port,
    fetch: async (req) => {
      const host = (req.headers.get('x-forwarded-host') ?? req.headers.get('host') ?? '').split(',')[0].trim()
      try {
        return await forward(req, upstream, { [PUBLIC_HOST_HEADER]: host, 'x-forwarded-proto': 'https' })
      } catch (e) {
        return new Response(`upstream unavailable: ${(e as Error).message}`, { status: 502 })
      }
    },
  },
  () => console.log(`proxy :${port} -> ${upstream}`)
)
