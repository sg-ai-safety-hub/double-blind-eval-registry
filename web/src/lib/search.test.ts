import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { EvalView, ModelView, RecordJson, State } from './api.ts'
import { byReceived, search } from './search.ts'

const hex = (c: string) => c.repeat(64)

function record(id: string, receivedAt: string, state: State, system: string, subject: string, evalDigest: string,
  evalName: string, model: string): RecordJson {
  return {
    recordId: id, receivedAt, state, systemDigest: system, subjectName: subject,
    eval: { digest: evalDigest, evalSet: { scheme: 'file-sha256/1', digest: evalDigest }, name: evalName },
    benchmarkOwner: { email: 'owner@example.org', display: 'Refusal evals owner' },
    components: [{ role: 'base', scheme: 'dirhash-sha256/1', digest: hex('1'), name: model,
      alsoKnownAs: [], params: null }],
  } as unknown as RecordJson
}

const OLD = record(hex('a'), '2026-10-01T00:00:00Z', 'verified', hex('5'), 'alpha-7b (greedy)', hex('e'), 'refusal-prompts',
  'alpha-7b')
const NEW = record(hex('b'), '2026-10-02T00:00:00Z', 'incomplete', hex('5'), 'alpha-7b (greedy)', hex('f'), 'bio-screen',
  'alpha-7b')
const MODELS = [{ digest: hex('1'), names: ['alpha-7b'], state: 'incomplete', records: [NEW, OLD] }] as unknown as ModelView[]
const EVALS = [
  { digest: hex('f'), names: ['bio-screen'], state: 'incomplete', records: [NEW] },
  { digest: hex('e'), names: ['refusal-prompts'], state: 'verified', records: [OLD] },
] as unknown as EvalView[]

test('a name matches anywhere, ignoring case', () => {
  const found = search('ALPHA', MODELS, EVALS)
  assert.deepEqual(found.models.map((m) => m.digest), [hex('1')])
  assert.deepEqual(found.systems.map((s) => s.digest), [hex('5')])
  assert.deepEqual(found.records.map((r) => r.recordId), [hex('b'), hex('a')]) // by their model's name
  assert.deepEqual(found.evals, [])
})

test('records come newest first, and a configuration takes the worst state of its records', () => {
  const found = search('alpha', MODELS, EVALS)
  assert.deepEqual(found.systems, [{ digest: hex('5'), subjectNames: ['alpha-7b (greedy)'], state: 'incomplete' }])
  assert.equal(found.records[0].recordId, hex('b'))
})

test('an ID is found by its first characters, as the tables show them', () => {
  assert.deepEqual(search('aaaaaaa', MODELS, EVALS).records.map((r) => r.recordId), [hex('a')])
  assert.deepEqual(search('eeee', MODELS, EVALS).evals.map((e) => e.digest), [hex('e')])
  assert.deepEqual(search('aaa', MODELS, EVALS).records, []) // under 4 characters is too short to be an ID
})

test('records sort by when they were received: newest first by default, ties by id, input untouched', () => {
  const tie = record(hex('c'), '2026-10-02T00:00:00Z', 'verified', hex('5'), 's', hex('e'), 'e', 'm')
  const input = [OLD, tie, NEW]
  assert.deepEqual(byReceived(input).map((r) => r.recordId), [hex('b'), hex('c'), hex('a')])
  assert.deepEqual(byReceived(input, false).map((r) => r.recordId), [hex('a'), hex('b'), hex('c')])
  assert.deepEqual(input.map((r) => r.recordId), [hex('a'), hex('c'), hex('b')])
})

test('a query that matches nothing finds nothing, and so does an empty one', () => {
  for (const query of ['zzz', '', '   ']) {
    const found = search(query, MODELS, EVALS)
    assert.equal(found.models.length + found.systems.length + found.evals.length + found.records.length, 0, query)
  }
})
