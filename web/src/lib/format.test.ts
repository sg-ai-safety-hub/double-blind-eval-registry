import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  formatDate, formatDateTime, formatSize, formatUnix, isHex64, metricValue, paramText, plural, reasons, short, shortRef,
} from './format.ts'

const HEX = '3bc3aabb8473df45e75ab91e624cca1a5588a3ff6e4a39215e7c0f6f8f96fd31'

test('a 64-hex id is lowercase hex, exactly 64 characters', () => {
  assert.equal(isHex64(HEX), true)
  assert.equal(isHex64(HEX.toUpperCase()), false)
  assert.equal(isHex64(HEX.slice(1)), false)
  assert.equal(isHex64(`sha256:${HEX}`), false)
})

test('a hash is shown by its first 7 characters, without an OCI sha256: prefix', () => {
  assert.equal(short(HEX), '3bc3aab')
  assert.equal(short(`sha256:${HEX}`), '3bc3aab')
})

test('a reference shortens only its hex revision', () => {
  assert.equal(shortRef('example-org/gamma@0a744a9fe1829e7a9a0bd91cb52203f87f1ff97a'), 'example-org/gamma@0a744a9')
  assert.equal(shortRef(HEX), '3bc3aab')
  assert.equal(shortRef('TinyLlama/TinyLlama-1.1B-Chat-v1.0'), 'TinyLlama/TinyLlama-1.1B-Chat-v1.0')
})

test('a non-integer metric is rounded to 3 significant digits, keeping its exact value', () => {
  assert.deepEqual(metricValue(3.9784453392028807), { text: '3.98', exact: '3.9784453392028807' })
  assert.deepEqual(metricValue(0.004), { text: '0.004' })
  assert.deepEqual(metricValue(0.6), { text: '0.6' })
  assert.deepEqual(metricValue(1234.5678), { text: '1235', exact: '1234.5678' })  // never drops integer digits
})

test('integers, strings and anything else are shown as given', () => {
  assert.deepEqual(metricValue(3), { text: '3' })
  assert.deepEqual(metricValue('0.79'), { text: '0.79' })
  assert.deepEqual(metricValue({ ece: 0.05, bins: 10 }), { text: '{"ece":0.05,"bins":10}' })
  assert.deepEqual(metricValue(null), { text: 'null' })
})

test('a param is shown as given: strings bare, everything else as JSON', () => {
  assert.equal(paramText('tinfoil'), 'tinfoil')
  assert.equal(paramText(0.8), '0.8')
  assert.equal(paramText(true), 'true')
  assert.equal(paramText(['\n']), '["\\n"]')
})

test('sizes are in bytes, kB or MB', () => {
  assert.equal(formatSize(512), '512 B')
  assert.equal(formatSize(147162), '147.2 kB')
  assert.equal(formatSize(1048576), '1.0 MB')
})

test('UTC times are written out, anything else is shown as given', () => {
  assert.equal(formatDate('2026-10-12T04:54:19Z'), '12 Oct 2026')
  assert.equal(formatDateTime('2026-10-12T04:54:19Z'), '12 Oct 2026, 04:54 UTC')
  assert.equal(formatDateTime('2026-10-07T10:12:10.436375Z', true), '7 Oct 2026, 10:12:10 UTC')
  assert.equal(formatDateTime('2026-10-07T10:12:10+00:00', true), '7 Oct 2026, 10:12:10 UTC')
  assert.equal(formatDateTime('2026-10-07T10:12:10+02:00', true), '2026-10-07T10:12:10+02:00')
  assert.equal(formatDateTime('whenever', true), 'whenever')
  assert.equal(formatDate('whenever'), 'whenever')
})

test("Rekor's integrated time is Unix seconds, in UTC", () => {
  assert.equal(formatUnix(1791368875), '7 Oct 2026, 10:27:55 UTC')
})

test("pending checks' reasons are listed once, dropping one that extends another", () => {
  assert.equal(reasons(['no hardware report in this receipt', 'no hardware report in this receipt',
    'no hardware report in this receipt, so it is not looked up on Rekor']), 'no hardware report in this receipt')
  assert.equal(reasons(['a', 'b', 'a']), 'a; b')
})

test('counts take a plural', () => {
  assert.equal(plural(1, 'record'), '1 record')
  assert.equal(plural(2, 'record'), '2 records')
  assert.equal(plural(0, 'model'), '0 models')
})
