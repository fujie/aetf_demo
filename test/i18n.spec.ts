import assert from 'node:assert/strict'
import { test } from 'node:test'
import { currentLang, inBoth, requestLang, t, withLang } from '../src/common/i18n.js'

const req = (url: string, headers: Record<string, string> = {}) => new Request(url, { headers })

test('requestLang: ?lang= > cookie > Accept-Language > Japanese', () => {
  assert.deepEqual(requestLang(req('http://localhost/?lang=en', { cookie: 'lang=ja' })), { lang: 'en', fromQuery: true })
  assert.deepEqual(requestLang(req('http://localhost/', { cookie: 'a=1; lang=en' })), { lang: 'en', fromQuery: false })
  assert.equal(requestLang(req('http://localhost/', { 'accept-language': 'en-US,en;q=0.9' })).lang, 'en')
  assert.equal(requestLang(req('http://localhost/', { 'accept-language': 'ja,en;q=0.8' })).lang, 'ja')
  assert.equal(requestLang(req('http://localhost/')).lang, 'ja')
})

test('withLang runs the handler in the request language and stores ?lang= in a cookie', async () => {
  const handler = withLang(async () => new Response(`${currentLang()}:${t('日本語', 'English')}`))
  const en = await handler(req('http://localhost/?lang=en'))
  assert.equal(await en.text(), 'en:English')
  assert.match(en.headers.get('set-cookie') ?? '', /^lang=en; Path=\//)
  const ja = await handler(req('http://localhost/', { cookie: 'lang=ja' }))
  assert.equal(await ja.text(), 'ja:日本語')
  assert.equal(ja.headers.get('set-cookie'), null)
})

test('inBoth renders a message in both languages', () => {
  assert.deepEqual(
    inBoth(() => t('検証成功', 'verified')),
    { ja: '検証成功', en: 'verified' }
  )
})
