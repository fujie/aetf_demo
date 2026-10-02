import { humanize } from './names.js'

/**
 * In-process event bus feeding the demo console timeline. Every entity emits what it does
 * (trust chain checks, issuance, presentation checks, status changes, registrations, ...).
 */
export type DemoEvent = {
  id: number
  at: string
  source: string
  level: 'ok' | 'info' | 'error'
  message: string
  detail?: string
}

const MAX_EVENTS = 500
const events: DemoEvent[] = []
let nextId = 1

export const emit = (source: string, level: DemoEvent['level'], message: string, detail?: string) => {
  events.push({
    id: nextId++,
    at: new Date().toISOString(),
    source,
    level,
    message: humanize(message),
    ...(detail ? { detail: humanize(detail) } : {}),
  })
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS)
}

export const eventsAfter = (id: number) => events.filter((e) => e.id > id)

export const clearEvents = () => {
  events.length = 0
}
