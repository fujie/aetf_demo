import { ENTITY_NAMES } from '../config.js'
import { type Lang, currentLang } from './i18n.js'

/**
 * Display names for entity identifiers: UI messages show "GakuNin Issuer" (or its Japanese name) instead of
 * "http://localhost:8720". (Entity IDs stay as-is in protocol messages and on "Entity ID" fields.)
 */
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const ids = Object.keys(ENTITY_NAMES).sort((a, b) => b.length - a.length)
const encodedRe = new RegExp(ids.map((id) => escapeRe(encodeURIComponent(id))).join('|'), 'g')
/** entity ID (not followed by more port digits), optional trailing path */
const plainRe = new RegExp(`(${ids.map(escapeRe).join('|')})(?!\\d)((?:/[^\\s"'<>,;:)\\]]*)?)`, 'g')

/** Display names of all entities in the given language (default: current request's language). */
export const entityLabels = (lang: Lang = currentLang()): Record<string, string> =>
  Object.fromEntries(Object.entries(ENTITY_NAMES).map(([id, n]) => [id, n[lang]]))

export const nameOf = (id: string, lang: Lang = currentLang()) =>
  (ENTITY_NAMES[id] ?? ENTITY_NAMES[id.replace(/\/$/, '')])?.[lang] ?? id

/** Replaces entity identifiers (also URL-encoded ones and URLs under them) in a message with display names. */
export const humanize = (text: string, lang: Lang = currentLang()) => {
  const encoded = (s: string) => s.replace(encodedRe, (m) => nameOf(decodeURIComponent(m), lang))
  // entity URLs first (their paths may contain URL-encoded entity IDs), then remaining encoded IDs
  return encoded(
    String(text ?? '').replace(plainRe, (_m, id: string, path: string) =>
      path && path !== '/' ? `${nameOf(id, lang)} (${encoded(path)})` : nameOf(id, lang)
    )
  )
}
