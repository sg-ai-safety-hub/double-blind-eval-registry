// Search results across the whole registry. `query` is the search box's text, shown only as text.
import { useApi, type EvalView, type ModelView } from '../lib/api.ts'
import { plural } from '../lib/format.ts'
import { search } from '../lib/search.ts'
import { Band, Meta, NotFound, RecordsTable, Section, SystemsTable, Waiting } from '../ui.tsx'
import { EvalsTable, ModelsTable } from './Lists.tsx'

export function Search({ query }: { query: string }) {
  const models = useApi<{ models: ModelView[] }>('/api/models')
  const evals = useApi<{ evals: EvalView[] }>('/api/evals')
  if (models.status !== 'ok' || evals.status !== 'ok') return <Waiting loads={[models, evals]} />
  const found = search(query, models.data.models, evals.data.evals)
  const count = found.models.length + found.systems.length + found.evals.length + found.records.length
  if (count === 0) return <NotFound query={query} />
  const allRecords = evals.data.evals.flatMap((e) => e.records)
  return (
    <>
      <Band>
        <h1>Search results</h1>
        <p className="lede">for “{query}”</p>
        <Meta items={[plural(found.models.length, 'model'), plural(found.systems.length, 'configuration'),
          plural(found.evals.length, 'eval dataset'), plural(found.records.length, 'record')]} />
      </Band>
      <main className="wrap page stack">
        {found.models.length > 0 && <Section title="Models"><ModelsTable models={found.models} /></Section>}
        {found.systems.length > 0 && (
          <Section title="Configurations"><SystemsTable systems={found.systems} records={allRecords} /></Section>
        )}
        {found.evals.length > 0 && <Section title="Evals"><EvalsTable evals={found.evals} /></Section>}
        {found.records.length > 0 && (
          <Section title="Records">
            <RecordsTable records={found.records} columns={['eval', 'configuration', 'approvedBy', 'received']} />
          </Section>
        )}
      </main>
    </>
  )
}
