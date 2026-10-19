// Site-wide search over what the read API lists: models, configurations, evals and records. Pure, so tested.
import type { EvalView, ModelView, RecordJson, State, SystemSummary } from './api.ts'

export interface Found {
  models: ModelView[]
  systems: SystemSummary[] // configurations
  evals: EvalView[]
  records: RecordJson[]
}

const ID_PREFIX = /^[0-9a-f]{4,64}$/ // the start of an id, as the tables show it (7 characters)
const OCI_PREFIX = 'sha256:'
const WORST_FIRST: State[] = ['incomplete', 'verified']

/**
 * What `query` matches, by label (any part, ignoring case) or by the start of an id. Every record appears once
 * among the evals (each record has one eval), so `evals` also gives every record and configuration.
 */
export function search(query: string, models: ModelView[], evals: EvalView[]): Found {
  const q = query.trim().toLowerCase()
  if (!q) return { models: [], systems: [], evals: [], records: [] }
  const byId = ID_PREFIX.test(q)
  const hit = (id: string, labels: (string | null)[]) =>
    (byId && id.replace(OCI_PREFIX, '').startsWith(q)) || labels.some((label) => label?.toLowerCase().includes(q))

  const records = byReceived(evals.flatMap((e) => e.records))
  return {
    models: models.filter((m) => hit(m.digest, m.names)),
    systems: systemsOf(records).filter((s) => hit(s.digest, s.subjectNames)),
    evals: evals.filter((e) => hit(e.digest, e.names)),
    records: records.filter((r) => hit(r.recordId,
      [r.eval.name, r.subjectName, r.benchmarkOwner.display, ...r.components.map((c) => c.name)])),
  }
}

/** A sorted copy of `records`, by when this registry received them; records received together, by id. */
export function byReceived(records: RecordJson[], newestFirst = true): RecordJson[] {
  const direction = newestFirst ? -1 : 1
  return [...records].sort((a, b) =>
    direction * a.receivedAt.localeCompare(b.receivedAt) || a.recordId.localeCompare(b.recordId))
}

/** The configurations the records ran, in record order: their labels, and the worst state of their records. */
function systemsOf(records: RecordJson[]): SystemSummary[] {
  const systems = new Map<string, SystemSummary>()
  for (const r of records) {
    const s = systems.get(r.systemDigest) ?? { digest: r.systemDigest, subjectNames: [], state: r.state }
    if (r.subjectName && !s.subjectNames.includes(r.subjectName)) s.subjectNames.push(r.subjectName)
    if (WORST_FIRST.indexOf(r.state) < WORST_FIRST.indexOf(s.state)) s.state = r.state
    systems.set(r.systemDigest, s)
  }
  return [...systems.values()]
}
