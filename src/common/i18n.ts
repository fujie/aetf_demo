import { AsyncLocalStorage } from 'node:async_hooks'

/**
 * UI language (Japanese / English).
 * The language is chosen with `?lang=ja|en` (stored in the `lang` cookie; cookies on localhost are
 * shared by all ports, so one switch applies to every entity and the web wallet), otherwise taken
 * from the cookie, otherwise from Accept-Language (default: Japanese).
 * The current request's language is kept in AsyncLocalStorage so that `t()` works anywhere while a
 * page is rendered.
 */
export type Lang = 'ja' | 'en'
export const LANGS: Lang[] = ['ja', 'en']
export const LANG_COOKIE = 'lang'

/** A message in both languages (e.g. demo console events, rendered later in the viewer's language). */
export type Bi = { ja: string; en: string }

const store = new AsyncLocalStorage<{ lang: Lang; url: string }>()

export const currentLang = (): Lang => store.getStore()?.lang ?? 'ja'
/** URL of the request being handled (for the language switcher). */
export const currentUrl = (): string | undefined => store.getStore()?.url

/** Runs `f` as if the current request were in `lang`. */
export const inLang = <T>(lang: Lang, f: () => T): T => store.run({ lang, url: currentUrl() ?? '' }, f)
/** Renders `f` in both languages (e.g. HTML built now but shown later to viewers of either language). */
export const inBoth = (f: () => string): Bi => ({ ja: inLang('ja', f), en: inLang('en', f) })

/** Picks the text for the current request's language. */
export const t = (ja: string, en: string) => (currentLang() === 'en' ? en : ja)
export const bi = (ja: string, en: string): Bi => ({ ja, en })
export const pick = (m: string | Bi | undefined, lang: Lang = currentLang()) =>
  m === undefined ? undefined : typeof m === 'string' ? m : m[lang]

const isLang = (v: unknown): v is Lang => v === 'ja' || v === 'en'

const cookieLang = (header: string | null) => {
  const m = /(?:^|;\s*)lang=(ja|en)(?:;|$)/.exec(header ?? '')
  return m ? (m[1] as Lang) : undefined
}

/** Language of a request: ?lang= > cookie > Accept-Language > Japanese. */
export const requestLang = (req: Request): { lang: Lang; fromQuery: boolean } => {
  const q = new URL(req.url).searchParams.get('lang')
  if (isLang(q)) return { lang: q, fromQuery: true }
  const c = cookieLang(req.headers.get('cookie'))
  if (c) return { lang: c, fromQuery: false }
  const al = (req.headers.get('accept-language') ?? '').trim().toLowerCase()
  return { lang: al.startsWith('en') ? 'en' : 'ja', fromQuery: false }
}

/**
 * Wraps a fetch handler: runs it with the request's language and, when the language was chosen
 * with `?lang=`, stores it in the cookie.
 */
export const withLang =
  <A extends unknown[]>(fetch: (req: Request, ...rest: A) => Response | Promise<Response>) =>
  async (req: Request, ...rest: A): Promise<Response> => {
    const { lang, fromQuery } = requestLang(req)
    const res = await store.run({ lang, url: req.url }, () => fetch(req, ...rest))
    if (!fromQuery) return res
    const out = new Response(res.body, res)
    out.headers.append('Set-Cookie', `${LANG_COOKIE}=${lang}; Path=/; Max-Age=31536000; SameSite=Lax`)
    return out
  }

/** Links to the current page in the other languages. */
export const langSwitcherHtml = (style = '') => {
  const url = new URL(currentUrl() ?? 'http://localhost/')
  return LANGS.map((l) => {
    url.searchParams.set('lang', l)
    const label = l === 'ja' ? '日本語' : 'English'
    return l === currentLang()
      ? `<b style="${style}">${label}</b>`
      : `<a href="${url.pathname}${url.search}" style="${style}">${label}</a>`
  }).join(' | ')
}
