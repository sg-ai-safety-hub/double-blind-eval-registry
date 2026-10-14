// The list pages: home, models, evals and records, and the tables they share with search results.
import { useApi, type EvalView, type ModelView } from '../lib/api.ts'
import { plural } from '../lib/format.ts'
import { hrefFor } from '../lib/route.ts'
import {
  Band, Hash, Link, Meta, PendingMark, RecordsTable, Section, Table, Waiting, distinctModels, idColumn, labelOf,
  usePages, useRegistry, type RecordColumn,
} from '../ui.tsx'

const RECORD_LIST: RecordColumn[] = ['eval', 'configuration', 'approvedBy', 'received'] // home and records

export function ModelsTable({ models }: { models: ModelView[] }) {
  const { rows, pager } = usePages(models)
  return (
    <Table columns={[idColumn('Model'), { label: 'Model' }, { label: 'Configurations', num: true },
      { label: 'Records', num: true }]} empty="No models." pager={pager}>
      {rows.map((m) => (
        <tr key={m.digest}>
          <td className="nowrap">
            <span className="idc"><Hash value={m.digest} href={hrefFor('model', m.digest)} quiet />
              <PendingMark state={m.state} /></span>
          </td>
          <td><Link href={hrefFor('model', m.digest)}>{labelOf(m.names, m.digest)}</Link></td>
          <td className="num">{m.systems.length}</td>
          <td className="num">{m.records.length}</td>
        </tr>
      ))}
    </Table>
  )
}

export function EvalsTable({ evals }: { evals: EvalView[] }) {
  const { modelRole } = useRegistry()
  const { rows, pager } = usePages(evals)
  return (
    <Table columns={[idColumn('Eval'), { label: 'Eval dataset' }, { label: 'Models', num: true },
      { label: 'Records', num: true }]} empty="No evals." pager={pager}>
      {rows.map((e) => (
        <tr key={e.digest}>
          <td className="nowrap">
            <span className="idc"><Hash value={e.digest} href={hrefFor('eval', e.digest)} quiet />
              <PendingMark state={e.state} /></span>
          </td>
          <td><Link href={hrefFor('eval', e.digest)}>{labelOf(e.names, e.digest)}</Link></td>
          <td className="num">{distinctModels(e.records, modelRole)}</td>
          <td className="num">{e.records.length}</td>
        </tr>
      ))}
    </Table>
  )
}

export function Home() {
  const models = useApi<{ models: ModelView[] }>('/api/models')
  const evals = useApi<{ evals: EvalView[] }>('/api/evals')
  if (models.status !== 'ok' || evals.status !== 'ok') return <Waiting loads={[models, evals]} />
  const records = evals.data.evals.flatMap((e) => e.records) // each record has one eval
  return (
    <>
      <Band>
        <h1>Evaluation records</h1>
        <p className="lede">Signed records of model evaluations run in AMD SEV-SNP enclaves.</p>
        <Meta items={[plural(records.length, 'record'), plural(models.data.models.length, 'model'),
          plural(evals.data.evals.length, 'eval dataset')]} />
      </Band>
      <main className="wrap page stack">
        <Section title="Models" aside={<a href="#/models">All models</a>}>
          <ModelsTable models={models.data.models} />
        </Section>
        <Section title="Records" aside={<a href="#/records">All records</a>}>
          <RecordsTable records={records} columns={RECORD_LIST} />
        </Section>
      </main>
    </>
  )
}

export function Models() {
  const load = useApi<{ models: ModelView[] }>('/api/models')
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const models = load.data.models
  const configurations = new Set(models.flatMap((m) => m.systems.map((s) => s.digest))).size
  const records = new Set(models.flatMap((m) => m.records.map((r) => r.recordId))).size
  return (
    <>
      <Band>
        <h1>Models</h1>
        <p className="lede">Grouped by the base model's weights.</p>
        <Meta items={[plural(models.length, 'model'), plural(configurations, 'configuration'),
          plural(records, 'record')]} />
      </Band>
      <main className="wrap page"><ModelsTable models={models} /></main>
    </>
  )
}

export function Evals() {
  const load = useApi<{ evals: EvalView[] }>('/api/evals')
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const evals = load.data.evals
  return (
    <>
      <Band>
        <h1>Evals</h1>
        <p className="lede">Grouped by eval dataset. The registry holds only the dataset's digest, never the prompts.</p>
        <Meta items={[plural(evals.length, 'eval dataset'),
          plural(evals.reduce((count, e) => count + e.records.length, 0), 'record')]} />
      </Band>
      <main className="wrap page"><EvalsTable evals={evals} /></main>
    </>
  )
}

export function Records() {
  const load = useApi<{ evals: EvalView[] }>('/api/evals')
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const records = load.data.evals.flatMap((e) => e.records) // each record has one eval
  return (
    <>
      <Band>
        <h1>Records</h1>
        <p className="lede">Every evaluation record this registry has accepted.</p>
        <Meta items={[plural(records.length, 'record')]} />
      </Band>
      <main className="wrap page"><RecordsTable records={records} columns={RECORD_LIST} /></main>
    </>
  )
}
