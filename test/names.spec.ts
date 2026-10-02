import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ENTITY } from '../src/config.js'
import { humanize, nameOf } from '../src/common/names.js'

test('nameOf maps entity identifiers to display names in both languages', () => {
  assert.equal(nameOf(ENTITY.issuer, 'ja'), '学認Issuer')
  assert.equal(nameOf(`${ENTITY.issuer}/`, 'ja'), '学認Issuer')
  assert.equal(nameOf(ENTITY.issuer, 'en'), 'GakuNin Issuer')
  assert.equal(nameOf('https://example.com', 'en'), 'https://example.com')
})

test('humanize replaces identifiers, URLs under them and URL-encoded identifiers', () => {
  const msg = `no valid trust chain for ${ENTITY.issuer}: GET ${ENTITY.nii}/fetch?sub=${encodeURIComponent(ENTITY.issuer)} -> 404`
  assert.equal(humanize(msg, 'ja'), 'no valid trust chain for 学認Issuer: GET NII (/fetch?sub=学認Issuer) -> 404')
  // names containing spaces stay inside the path parentheses
  assert.equal(humanize(msg, 'en'), 'no valid trust chain for GakuNin Issuer: GET NII (/fetch?sub=GakuNin Issuer) -> 404')
  assert.equal(humanize(`present at ${ENTITY.verifier}/callback: failed`, 'en'), 'present at Verifier (/callback): failed')
  assert.equal(humanize(`${ENTITY.walletProvider} -> ${ENTITY.nii}`, 'ja'), 'Wallet Provider -> NII')
  // a longer port is a different origin
  assert.equal(humanize(`${ENTITY.issuer}1/x`, 'ja'), `${ENTITY.issuer}1/x`)
})
