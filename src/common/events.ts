import { type Bi, type Lang, currentLang } from './i18n.js'
import { humanize } from './names.js'

/**
 * In-process event bus feeding the demo console timeline. Every entity emits what it does
 * (trust chain checks, issuance, presentation checks, status changes, registrations, ...).
 * Messages are kept in both languages and rendered in the viewer's language.
 */
type StoredEvent = {
  id: number
  at: string
  source: string
  level: 'ok' | 'info' | 'error'
  message: Bi
  detail?: Bi
}

/** Event as served to the demo console (in one language). */
export type DemoEvent = {
  id: number
  at: string
  /** Source key (stable, used for colours and filtering) */
  source: string
  /** Source display name */
  sourceLabel: string
  level: 'ok' | 'info' | 'error'
  message: string
  detail?: string
}

/** English display names of event sources (the source key is the Japanese name). */
const SOURCE_EN: Record<string, string> = {
  学認Issuer: 'GakuNin Issuer',
  機関IdP: 'Institution IdP',
  属性Provider: 'Attribute Provider',
  学認SP: 'GakuNin SP',
  'Federation 設定': 'Federation settings',
  デモコンソール: 'Demo console',
}

const MAX_EVENTS = 500
const events: StoredEvent[] = []
let nextId = 1

const both = (m: string | Bi): Bi =>
  typeof m === 'string' ? { ja: humanize(m, 'ja'), en: humanize(m, 'en') } : { ja: humanize(m.ja, 'ja'), en: humanize(m.en, 'en') }

export const emit = (source: string, level: StoredEvent['level'], message: string | Bi, detail?: string | Bi) => {
  events.push({
    id: nextId++,
    at: new Date().toISOString(),
    source,
    level,
    message: both(message),
    ...(detail ? { detail: both(detail) } : {}),
  })
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS)
}

export const eventsAfter = (id: number, lang: Lang = currentLang()): DemoEvent[] =>
  events
    .filter((e) => e.id > id)
    .map((e) => ({
      id: e.id,
      at: e.at,
      source: e.source,
      sourceLabel: lang === 'en' ? (SOURCE_EN[e.source] ?? e.source) : e.source,
      level: e.level,
      message: e.message[lang],
      ...(e.detail ? { detail: e.detail[lang] } : {}),
    }))

export const clearEvents = () => {
  events.length = 0
}
