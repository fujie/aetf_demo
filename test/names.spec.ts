import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ENTITY } from '../src/config.js'
import { humanize, nameOf } from '../src/common/names.js'

test('nameOf maps entity identifiers to display names', () => {
  assert.equal(nameOf(ENTITY.issuer), '学認Issuer')
  assert.equal(nameOf(`${ENTITY.issuer}/`), '学認Issuer')
  assert.equal(nameOf('https://example.com'), 'https://example.com')
})

test('humanize replaces identifiers, URLs under them and URL-encoded identifiers', () => {
  assert.equal(
    humanize(`no valid trust chain for ${ENTITY.issuer}: GET ${ENTITY.nii}/fetch?sub=${encodeURIComponent(ENTITY.issuer)} -> 404`),
    'no valid trust chain for 学認Issuer: GET NII (/fetch?sub=学認Issuer) -> 404'
  )
  assert.equal(humanize(`present at ${ENTITY.verifier}/callback: failed`), 'present at Verifier (/callback): failed')
  assert.equal(humanize(`${ENTITY.walletProvider} -> ${ENTITY.nii}`), 'Wallet Provider -> NII')
  // a longer port is a different origin
  assert.equal(humanize(`${ENTITY.issuer}1/x`), `${ENTITY.issuer}1/x`)
})
