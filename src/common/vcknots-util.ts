import { VcknotsError } from '@trustknots/vcknots/errors'

/** Maps an exception to an OAuth-style error response body + status. */
export const toErrorResponse = (err: unknown): { body: { error: string; error_description: string }; status: 400 | 500 } => {
  if (err instanceof VcknotsError) {
    return { body: { error: err.name, error_description: err.message }, status: 400 }
  }
  if (err && typeof err === 'object' && 'issues' in err) {
    return { body: { error: 'invalid_request', error_description: String((err as unknown as Error).message) }, status: 400 }
  }
  console.error(err)
  return {
    body: { error: 'internal_server_error', error_description: (err as Error)?.message ?? String(err) },
    status: 500,
  }
}
