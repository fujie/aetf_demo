import { ENTITY_LABELS } from '../config.js'

/**
 * Display names for entity identifiers: UI messages show "学認Issuer" instead of
 * "http://localhost:8720". (Entity IDs stay as-is in protocol messages and on "Entity ID" fields.)
 */
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const ids = Object.keys(ENTITY_LABELS).sort((a, b) => b.length - a.length)
const encodedRe = new RegExp(ids.map((id) => escapeRe(encodeURIComponent(id))).join('|'), 'g')
/** entity ID (not followed by more port digits), optional trailing path */
const plainRe = new RegExp(`(${ids.map(escapeRe).join('|')})(?!\\d)((?:/[^\\s"'<>,;:)\\]]*)?)`, 'g')

export const nameOf = (id: string) => ENTITY_LABELS[id] ?? ENTITY_LABELS[id.replace(/\/$/, '')] ?? id

/** Replaces entity identifiers (also URL-encoded ones and URLs under them) in a message with display names. */
export const humanize = (text: string) =>
  String(text ?? '')
    .replace(encodedRe, (m) => nameOf(decodeURIComponent(m)))
    .replace(plainRe, (_m, id: string, path: string) => (path && path !== '/' ? `${nameOf(id)} (${path})` : nameOf(id)))
