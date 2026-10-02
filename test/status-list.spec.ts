import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { type Bits, StatusList, getStatusListReference, statusTypeName } from '../src/status-list/token-status-list.js'

type Vector = {
  bits: Bits
  size: number
  lst: string
  bytes?: number[]
  statuses?: Record<string, number>
}

// Examples (section 4.1 / 4.2) and test vectors (appendix) of draft-ietf-oauth-status-list
const vectors: Vector[] = JSON.parse(readFileSync(new URL('./status-list-vectors.json', import.meta.url), 'utf-8'))

for (const v of vectors) {
  const label = `${v.bits}-bit / ${v.size} entries`

  test(`decode draft vector (${label})`, () => {
    const list = StatusList.fromJson({ bits: v.bits, lst: v.lst })
    assert.equal(list.size, v.size)
    if (v.bytes) assert.deepEqual([...list.bytes], v.bytes)
    if (v.statuses) {
      for (let i = 0; i < list.size; i++) {
        assert.equal(list.get(i), v.statuses[String(i)] ?? 0, `status[${i}]`)
      }
    }
  })

  test(`encode -> decode round trip (${label})`, () => {
    const list = new StatusList(v.bits, v.size)
    if (v.bytes) list.bytes.set(v.bytes)
    for (const [idx, value] of Object.entries(v.statuses ?? {})) list.set(Number(idx), value)
    const decoded = StatusList.fromJson(list.toJson())
    assert.deepEqual(decoded.bytes, list.bytes)
  })
}

test('set() packs from the least significant bit (section 4.1 example)', () => {
  const list = new StatusList(1, 16)
  ;[1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1].forEach((s, i) => list.set(i, s))
  assert.deepEqual([...list.bytes], [0xb9, 0xa3])
})

test('values must fit into bits and index must be in bounds', () => {
  const list = new StatusList(1, 8)
  assert.throws(() => list.set(0, 2))
  assert.throws(() => list.get(8))
  assert.throws(() => new StatusList(3 as Bits, 8))
})

test('Referenced Token status claim validation', () => {
  assert.deepEqual(getStatusListReference({ status: { status_list: { idx: 3, uri: 'https://e.com/sl/1' } } }), {
    idx: 3,
    uri: 'https://e.com/sl/1',
  })
  assert.throws(() => getStatusListReference({}))
  assert.throws(() => getStatusListReference({ status: { status_list: { idx: -1, uri: 'https://e.com' } } }))
  assert.throws(() => getStatusListReference({ status: { status_list: { idx: 1, uri: 'not a uri' } } }))
})

test('status type names', () => {
  assert.equal(statusTypeName(0), 'VALID')
  assert.equal(statusTypeName(1), 'INVALID')
  assert.equal(statusTypeName(2), 'SUSPENDED')
  assert.match(statusTypeName(0x0c), /APPLICATION_SPECIFIC/)
})
