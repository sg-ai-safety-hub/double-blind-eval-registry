import assert from 'node:assert/strict'
import { test } from 'node:test'
import { externalHref, hrefFor, lookupPage, parseRoute, searchHref } from './route.ts'

const HEX = 'a93b956ccd36eedcf5f0b3d40eb86f8e7ab7c0c4b320a88f9fbdf74f5ea3ff4c'

test('the list pages', () => {
  for (const hash of ['', '#', '#/']) assert.deepEqual(parseRoute(hash), { page: 'home' })
  assert.deepEqual(parseRoute('#/models'), { page: 'models' })
  assert.deepEqual(parseRoute('#/evals'), { page: 'evals' })
  assert.deepEqual(parseRoute('#/records'), { page: 'records' })
})

test('a detail page takes a 64-hex id', () => {
  for (const page of ['model', 'config', 'eval', 'record'] as const) {
    assert.deepEqual(parseRoute(`#/${page}/${HEX}`), { page, id: HEX })
  }
})

test('a search carries its query, encoded, and takes any text', () => {
  assert.deepEqual(parseRoute('#/search/alpha'), { page: 'search', query: 'alpha' })
  assert.deepEqual(parseRoute(searchHref('a/b c?<script>')), { page: 'search', query: 'a/b c?<script>' })
  assert.equal(searchHref('a b'), '#/search/a%20b')
  for (const hash of ['#/search/', '#/search/%E0%A4%A', '#/search']) assert.deepEqual(parseRoute(hash), { page: 'notfound' })
})

test('anything else is not found', () => {
  for (const hash of ['#/record/ABC', `#/record/${HEX.toUpperCase()}`, `#/record/${HEX}/x`, '#/record', '#/admin',
    `#/component/${HEX}`, '#/models/extra', `#/records/${HEX}`]) {
    assert.deepEqual(parseRoute(hash), { page: 'notfound' }, hash)
  }
})

test('links are built only from 64-hex ids', () => {
  assert.equal(hrefFor('record', HEX), `#/record/${HEX}`)
  assert.equal(hrefFor('model', `sha256:${HEX}`), `#/model/${HEX}`)  // an OCI digest, by its hex
  assert.equal(hrefFor('record', '../evil'), null)
  assert.equal(hrefFor('config', 'javascript:alert(1)'), null)
})

test('an outside link is only ever https', () => {
  assert.equal(externalHref('https://search.sigstore.dev/?logIndex=3129204433'),
    'https://search.sigstore.dev/?logIndex=3129204433')
  for (const url of ['javascript:alert(1)', 'http://example.org/', 'data:text/html,x', '//evil.example', 'not a url']) {
    assert.equal(externalHref(url), null, url)
  }
})

test('a lookup answer names the page to open; a component needs its systems first', () => {
  assert.equal(lookupPage('system'), 'config')
  assert.equal(lookupPage('eval'), 'eval')
  assert.equal(lookupPage('record'), 'record')
  assert.equal(lookupPage('model'), 'model')
  assert.equal(lookupPage('component'), null)
})
