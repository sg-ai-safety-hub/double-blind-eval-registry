// One model, one configuration (a system) and one eval. `id` is a validated 64-hex id.
import { useApi, type EvalView, type ModelView, type SystemView } from '../lib/api.ts'
import { plural, shortRef } from '../lib/format.ts'
import { hrefFor } from '../lib/route.ts'
import {
  Band, ComponentsTable, CopyButton, Crumbs, Hash, Meta, RecordsTable, Section, SystemsTable, Waiting, distinctModels,
  labelOf, useRegistry,
} from '../ui.tsx'

export function Model({ id }: { id: string }) {
  const load = useApi<ModelView>(`/api/models/${id}`)
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const m = load.data
  const name = labelOf(m.names, m.digest)
  return (
    <>
      <Band>
        <Crumbs items={[{ label: 'Models', href: '#/models' }, { label: name }]} />
        <div className="title"><h1>{name}</h1><span className="tag">base model</span></div>
        <Meta items={[<>ID <Hash value={m.digest} /></>, plural(m.systems.length, 'configuration'),
          plural(m.records.length, 'record')]} />
        {m.alsoKnownAs.length > 0 && (
          <Meta items={['Also known as', ...m.alsoKnownAs.map((alias) => (
            <><span className="mono">{shortRef(alias.value)}</span>
              <CopyButton value={alias.value} label="Copy full reference" /></>
          ))]} />
        )}
      </Band>
      <main className="wrap page stack">
        <Section title="Records">
          <RecordsTable records={m.records} columns={['eval', 'configuration', 'approvedBy', 'received']} />
        </Section>
        <Section title="Configurations"><SystemsTable systems={m.systems} records={m.records} /></Section>
      </main>
    </>
  )
}

export function Config({ id }: { id: string }) {
  const { modelRole } = useRegistry()
  const load = useApi<SystemView>(`/api/systems/${id}`)
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const s = load.data
  const model = s.components.find((c) => c.role === modelRole)
  return (
    <>
      <Band>
        <Crumbs items={[{ label: 'Models', href: '#/models' },
          ...(model ? [{ label: labelOf(model.names, model.digest), href: hrefFor('model', model.digest) }] : []),
          { label: 'Configuration' }]} />
        <div className="title"><h1>{labelOf(s.subjectNames, s.digest)}</h1><span className="tag">configuration</span></div>
        <Meta items={[<>ID <Hash value={s.digest} /></>, plural(s.components.length, 'component'),
          plural(s.records.length, 'record')]} />
      </Band>
      <main className="wrap page stack">
        <Section title="Records">
          <RecordsTable records={s.records} columns={['eval', 'approvedBy', 'received']} />
        </Section>
        <Section title="Components">
          <ComponentsTable rows={s.components.map((c) => ({ ...c, labels: c.names }))} />
        </Section>
      </main>
    </>
  )
}

export function Eval({ id }: { id: string }) {
  const { modelRole } = useRegistry()
  const load = useApi<EvalView>(`/api/evals/${id}`)
  if (load.status !== 'ok') return <Waiting loads={[load]} />
  const e = load.data
  const name = labelOf(e.names, e.digest)
  return (
    <>
      <Band>
        <Crumbs items={[{ label: 'Evals', href: '#/evals' }, { label: name }]} />
        <div className="title"><h1>{name}</h1><span className="tag">eval dataset</span></div>
        <Meta items={[<>ID <Hash value={e.digest} /></>, plural(distinctModels(e.records, modelRole), 'model'),
          plural(e.records.length, 'record')]} />
      </Band>
      <main className="wrap page stack">
        <Section title="Records">
          <RecordsTable records={e.records} columns={['model', 'configuration', 'approvedBy', 'received']} />
        </Section>
      </main>
    </>
  )
}
