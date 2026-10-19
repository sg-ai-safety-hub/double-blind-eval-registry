import assert from 'node:assert/strict'
import { test } from 'node:test'
import { PAGE_SIZE, pageOf } from './page.ts'

const rows = (n: number) => Array.from({ length: n }, (_, i) => i + 1)

test('a table shows ten rows to a page', () => {
  assert.equal(PAGE_SIZE, 10)
  assert.deepEqual(pageOf(rows(25), 0), { rows: rows(10), page: 0, pages: 3, from: 1, to: 10, total: 25 })
  assert.deepEqual(pageOf(rows(25), 1).rows, rows(20).slice(10))
})

test('the last page holds what is left', () => {
  assert.deepEqual(pageOf(rows(25), 2), { rows: [21, 22, 23, 24, 25], page: 2, pages: 3, from: 21, to: 25, total: 25 })
})

test('ten rows or fewer fit on one page, and eleven need two', () => {
  assert.equal(pageOf(rows(10), 0).pages, 1)
  assert.equal(pageOf(rows(11), 0).pages, 2)
  assert.deepEqual(pageOf(rows(11), 1).rows, [11])
})

test('an empty table is one empty page', () => {
  assert.deepEqual(pageOf([], 0), { rows: [], page: 0, pages: 1, from: 0, to: 0, total: 0 })
})

test('a page out of range shows the nearest one', () => {
  assert.equal(pageOf(rows(25), 7).page, 2)
  assert.deepEqual(pageOf(rows(25), 7).rows, [21, 22, 23, 24, 25])
  assert.equal(pageOf(rows(25), -1).page, 0)
})
