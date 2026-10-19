// Shared pieces of every page: frame, IDs with copy, help tooltips and tables.
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { Load, Params, RecordJson, State, SystemSummary } from './lib/api.ts'
import { formatDate, isHex64, paramText, short } from './lib/format.ts'
import { pageOf } from './lib/page.ts'
import { hrefFor } from './lib/route.ts'
import { byReceived } from './lib/search.ts'

export interface Registry {
  dev: boolean
  modelRole: string // from /api/health: the component role that identifies a model
}

export const RegistryContext = createContext<Registry>({ dev: false, modelRole: '' })

export function useRegistry(): Registry {
  return useContext(RegistryContext)
}

export const TIPS = {
  configuration: 'The exact setup evaluated: model weights plus any adapters, classifiers and sampling settings.',
  approvedBy: 'Evaluator who approved the evaluation run.', // the UI says "evaluator" for the benchmark owner
  download: 'Download the original signed record, exactly as received, to verify it independently.',
  incomplete: 'Incomplete: some checks did not run.',
  copyId: 'Copy full ID',
  copyDigest: 'Copy full digest',
}

// --- icons: inline stroke SVGs, never emoji -----------------------------------

const ICONS = {
  search: <><circle cx="7" cy="7" r="4.5" /><path d="m10.4 10.4 3.1 3.1" /></>,
  copy: <><rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
    <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></>,
  info: <><circle cx="8" cy="8" r="6.25" /><path d="M8 7.3v3.7" /><path d="M8 5.1v.05" /></>,
  check: <><circle cx="8" cy="8" r="6.25" /><path d="M5.4 8.3l1.8 1.8 3.5-3.9" /></>,
  clock: <><circle cx="8" cy="8" r="6.25" /><path d="M8 4.8V8l2.2 1.3" /></>,
  download: <><path d="M8 2.5v8" /><path d="M4.75 7.5 8 10.75l3.25-3.25" /><path d="M2.5 13.5h11" /></>,
  down: <><path d="M8 3v10" /><path d="m4.5 9.5 3.5 3.5 3.5-3.5" /></>,
  up: <><path d="M8 13V3" /><path d="m4.5 6.5 3.5-3.5 3.5 3.5" /></>,
}

export function Icon({ name }: { name: keyof typeof ICONS }) {
  return (
    <svg className="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={1.6}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {ICONS[name]}
    </svg>
  )
}

function classes(...names: (string | false)[]): string {
  return names.filter(Boolean).join(' ')
}

// --- tooltips -------------------------------------------------------------------

const TIP_GAP = 8 // px between an element and its tooltip
const TIP_EDGE = 150 // px: half the tooltip's max width plus a margin, so a centred tooltip stays on screen
const TIP_ROOM = 64 // px: with less room above an element, its tooltip opens below

interface ShownTip {
  el: HTMLElement
  text: string
  x: number
  y: number
  transform: string
}

/** Where the tooltip of `el` goes, in window coordinates. `tip-b` opens it below; `tip-l` aligns its right edge. */
function placeTip(el: HTMLElement): ShownTip {
  const r = el.getBoundingClientRect()
  const below = el.classList.contains('tip-b') || r.top < TIP_ROOM
  const y = below ? r.bottom + TIP_GAP : r.top - TIP_GAP
  const lift = below ? '0' : '-100%'
  const text = el.dataset.tip ?? ''
  if (el.classList.contains('tip-l')) return { el, text, x: r.right, y, transform: `translate(-100%, ${lift})` }
  const x = Math.min(Math.max(r.left + r.width / 2, TIP_EDGE), window.innerWidth - TIP_EDGE)
  return { el, text, x, y, transform: `translate(-50%, ${lift})` }
}

/**
 * The one tooltip on the page, for whichever `[data-tip]` element is hovered or focused. It is drawn fixed to
 * the window, above everything, so no table or scrolling box can clip it.
 */
export function TooltipLayer() {
  const [shown, setShown] = useState<ShownTip | null>(null)
  useEffect(() => {
    const tipOf = (target: EventTarget | null) =>
      target instanceof Element ? target.closest<HTMLElement>('[data-tip]') : null
    const show = (e: Event) => {
      const el = tipOf(e.target)
      if (el) setShown(placeTip(el))
    }
    const hide = (e: Event) => {
      const el = tipOf(e.target)
      const to = (e as PointerEvent | FocusEvent).relatedTarget
      if (el && !(to instanceof Node && el.contains(to))) setShown(null) // not when moving within the element
    }
    const clear = () => setShown(null)
    const listeners: [EventTarget, string, (e: Event) => void, boolean][] = [
      [document, 'pointerover', show, false], [document, 'focusin', show, false],
      [document, 'pointerout', hide, false], [document, 'focusout', hide, false],
      [window, 'scroll', clear, true], [window, 'resize', clear, false], [window, 'hashchange', clear, false],
    ]
    listeners.forEach(([target, type, fn, capture]) => target.addEventListener(type, fn, capture))
    return () => listeners.forEach(([target, type, fn, capture]) => target.removeEventListener(type, fn, capture))
  }, [])
  useEffect(() => { // a copy button's tip turns to "Copied" while it shows
    if (!shown) return
    const observer = new MutationObserver(() => setShown(placeTip(shown.el)))
    observer.observe(shown.el, { attributes: true, attributeFilter: ['data-tip'] })
    return () => observer.disconnect()
  }, [shown])
  if (!shown?.text) return null
  return (
    <div className="tooltip" role="tooltip" style={{ left: shown.x, top: shown.y, transform: shown.transform }}>
      {shown.text}
    </div>
  )
}

// --- hashes, copy and help ----------------------------------------------------

export function CopyButton({ value, label, quiet = false, right = false }:
  { value: string; label: string; quiet?: boolean; right?: boolean }) {
  const [copied, setCopied] = useState(false)
  const copy = () => navigator.clipboard.writeText(value).then(() => {
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }, () => undefined)
  return (
    <button type="button" className={classes('copy', 'tip', quiet && 'quiet', right && 'tip-l')} aria-label={label}
      data-tip={copied ? 'Copied' : label} onClick={copy}>
      <Icon name="copy" />
    </button>
  )
}

/** A hash by its first 7 characters, linked when it has a page, with a copy button for the full value. */
export function Hash({ value, href = null, label = TIPS.copyId, quiet = false, right = false }:
  { value: string; href?: string | null; label?: string; quiet?: boolean; right?: boolean }) {
  return (
    <span className="idc">
      {href ? <a className="mono" href={href}>{short(value)}</a> : <span className="mono">{short(value)}</span>}
      <CopyButton value={value} label={label} quiet={quiet} right={right} />
    </span>
  )
}

export function Info({ tip, label, below = false, right = false }:
  { tip: string; label: string; below?: boolean; right?: boolean }) {
  return (
    <button type="button" className={classes('info', 'tip', below && 'tip-b', right && 'tip-l')} aria-label={label}
      data-tip={tip}>
      <Icon name="info" />
    </button>
  )
}

/** Dev mode only: the amber clock beside an incomplete row's ID. */
export function PendingMark({ state }: { state: State }) {
  const { dev } = useRegistry()
  if (!dev || state !== 'incomplete') return null
  return (
    <span className="pend-i tip" data-tip={TIPS.incomplete}>
      <Icon name="clock" /><span className="sr">Incomplete</span>
    </span>
  )
}

export function Link({ href, children }: { href: string | null; children: ReactNode }) {
  return href ? <a href={href}>{children}</a> : <>{children}</>
}

/** Every label records gave one thing, or its short hash when none did. */
export function labelOf(names: (string | null)[], digest: string): string {
  return names.filter((name): name is string => !!name).join(' / ') || short(digest)
}

// --- page frame ---------------------------------------------------------------

export function Band({ children }: { children: ReactNode }) {
  return <section className="band"><div className="wrap band-in">{children}</div></section>
}

export function Crumbs({ items }: { items: { label: string; href?: string | null }[] }) {
  return (
    <nav className="crumb" aria-label="Breadcrumb">
      {items.map((item, i) => (
        <span key={i} className="crumb-item">
          {i > 0 && <span aria-hidden="true">/</span>}
          {item.href ? <a href={item.href}>{item.label}</a> : <span>{item.label}</span>}
        </span>
      ))}
    </nav>
  )
}

export function Meta({ items }: { items: ReactNode[] }) {
  return <div className="meta">{items.map((item, i) => <span key={i}>{item}</span>)}</div>
}

export function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="sec">
      <div className="sec-h"><h2>{title}</h2>{aside}</div>
      {children}
    </section>
  )
}

/** A page's loads that haven't all arrived: an error, a 404, or still loading. */
export function Waiting({ loads }: { loads: Load<unknown>[] }) {
  const failed = loads.find((load) => load.status === 'error')
  if (failed?.status === 'error') return <main className="wrap page"><p>Registry API unreachable: {failed.message}</p></main>
  if (loads.some((load) => load.status === 'notfound')) return <NotFound />
  return <main className="wrap page"><p className="sub">Loading…</p></main>
}

/** The nothing page: an unknown address, an unknown digest, or a search that found nothing. */
export function NotFound({ query }: { query?: string }) {
  return (
    <main className="wrap page notfound">
      <h1>{query ? <>No results for “{query}”</> : 'Page not found'}</h1>
      <div className="links"><a href="#/records">Records</a><a href="#/models">Models</a><a href="#/evals">Evals</a></div>
    </main>
  )
}

// --- tables -------------------------------------------------------------------

export interface Column {
  label: ReactNode
  num?: boolean
  sort?: 'ascending' | 'descending' // a sorted column says so to screen readers
  id?: boolean
}

/** A table's first column: the row's ID, headed by what it identifies ("Model ID"). */
export function idColumn(kind: string): Column {
  return { label: `${kind} ID`, id: true }
}

export function Table({ columns, empty = 'Nothing here yet.', pager, children }:
  { columns: Column[]; empty?: string; pager?: ReactNode; children: ReactNode[] }) {
  // An ID column takes only the width its short hash needs; the rest goes to the names.
  const className = (c: Column) => classes(c.num === true && 'num', c.id === true && 'id') || undefined
  return (
    <div>
      <div className="tbl">
        <table>
          <thead><tr>{columns.map((c, i) => (
            <th key={i} className={className(c)} aria-sort={c.sort}>{c.label}</th>
          ))}</tr></thead>
          <tbody>
            {children.length ? children : <tr><td className="empty" colSpan={columns.length}>{empty}</td></tr>}
          </tbody>
        </table>
      </div>
      {pager}
    </div>
  )
}

/** `items` a page at a time: the rows to show, and the control under the table that moves between pages. */
export function usePages<T>(items: T[]) {
  const [page, setPage] = useState(0)
  const shown = pageOf(items, page)
  const pager = shown.pages > 1 && (
    <div className="pager">
      <span className="sub" aria-live="polite">{shown.from}–{shown.to} of {shown.total}</span>
      <button type="button" className="btn" disabled={shown.page === 0}
        onClick={() => setPage(shown.page - 1)}>Previous</button>
      <button type="button" className="btn" disabled={shown.page === shown.pages - 1}
        onClick={() => setPage(shown.page + 1)}>Next</button>
    </div>
  )
  return { rows: shown.rows, pager, toFirst: () => setPage(0) }
}

function HeaderInfo({ text, tip }: { text: string; tip: string }) {
  return <span className="th">{text}<Info tip={tip} label={`About ${text.toLowerCase()}`} below /></span>
}

export type RecordColumn = 'eval' | 'model' | 'configuration' | 'approvedBy' | 'received'

const RECORD_COLUMNS: Record<Exclude<RecordColumn, 'received'>, Column> = {
  eval: { label: 'Eval' },
  model: { label: 'Model' },
  configuration: { label: <HeaderInfo text="Configuration" tip={TIPS.configuration} /> },
  approvedBy: { label: <HeaderInfo text="Approved by" tip={TIPS.approvedBy} /> },
}

/** The Received header: a button that flips the order, newest first by default. */
function receivedColumn(newestFirst: boolean, flip: () => void): Column {
  const label = (
    <button type="button" className="sort" onClick={flip}
      aria-label={`Received, ${newestFirst ? 'newest' : 'oldest'} first. Sort ${newestFirst ? 'oldest' : 'newest'} first`}>
      Received<Icon name={newestFirst ? 'down' : 'up'} />
    </button>
  )
  return { label, sort: newestFirst ? 'descending' : 'ascending' }
}

export function modelOf(record: RecordJson, modelRole: string) {
  return record.components.find((c) => c.role === modelRole)
}

export function distinctModels(records: RecordJson[], modelRole: string): number {
  return new Set(records.map((r) => modelOf(r, modelRole)?.digest).filter(Boolean)).size
}

export function RecordsTable({ records, columns }: { records: RecordJson[]; columns: RecordColumn[] }) {
  const { modelRole } = useRegistry()
  const [newestFirst, setNewestFirst] = useState(true)
  const { rows, pager, toFirst } = usePages(byReceived(records, newestFirst))
  const flip = () => {
    setNewestFirst(!newestFirst)
    toFirst()
  }
  const header = (c: RecordColumn): Column => c === 'received' ? receivedColumn(newestFirst, flip) : RECORD_COLUMNS[c]
  const cell = (column: RecordColumn, r: RecordJson): ReactNode => {
    switch (column) {
      case 'eval':
        return <Link href={hrefFor('eval', r.eval.digest)}>{labelOf([r.eval.name], r.eval.digest)}</Link>
      case 'model': {
        const model = modelOf(r, modelRole)
        return model && <Link href={hrefFor('model', model.digest)}>{labelOf([model.name], model.digest)}</Link>
      }
      case 'configuration':
        return <Link href={hrefFor('config', r.systemDigest)}>{labelOf([r.subjectName], r.systemDigest)}</Link>
      case 'approvedBy':
        return r.benchmarkOwner.display
      case 'received':
        return formatDate(r.receivedAt)
    }
  }
  return (
    <Table columns={[idColumn('Record'), ...columns.map(header)]} empty="No records." pager={pager}>
      {rows.map((r) => (
        <tr key={r.recordId}>
          <td className="nowrap">
            <span className="idc"><Hash value={r.recordId} href={hrefFor('record', r.recordId)} quiet />
              <PendingMark state={r.state} /></span>
          </td>
          {columns.map((c) => <td key={c} className={c === 'received' ? 'nowrap' : undefined}>{cell(c, r)}</td>)}
        </tr>
      ))}
    </Table>
  )
}

export function SystemsTable({ systems, records }: { systems: SystemSummary[]; records: RecordJson[] }) {
  const { rows, pager } = usePages(systems)
  return (
    <Table columns={[idColumn('Configuration'), { label: 'Configuration' }, { label: 'Components', num: true },
      { label: 'Records', num: true }]} pager={pager}>
      {rows.map((s) => {
        const mine = records.filter((r) => r.systemDigest === s.digest)
        return (
          <tr key={s.digest}>
            <td className="nowrap">
              <span className="idc"><Hash value={s.digest} href={hrefFor('config', s.digest)} quiet />
                <PendingMark state={s.state} /></span>
            </td>
            <td><Link href={hrefFor('config', s.digest)}>{labelOf(s.subjectNames, s.digest)}</Link></td>
            <td className="num">{mine[0]?.components.length}</td>
            <td className="num">{mine.length}</td>
          </tr>
        )
      })}
    </Table>
  )
}

export interface ComponentRow {
  role: string
  digest: string
  labels: (string | null)[]
  params: Params
}

export function ComponentsTable({ rows }: { rows: ComponentRow[] }) {
  const { modelRole } = useRegistry()
  return (
    <Table columns={[idColumn('Component'), { label: 'Role' }, { label: 'Name' }, { label: 'Details' }]}>
      {rows.map((c, i) => {
        const href = c.role === modelRole ? hrefFor('model', c.digest) : null
        return (
          <tr key={i}>
            <td className="nowrap"><Hash value={c.digest} href={href} label={TIPS.copyDigest} quiet /></td>
            <td className="nowrap">{c.role}</td>
            <td><Link href={href}>{c.labels.filter(Boolean).join(' / ')}</Link></td>
            <td><ParamList params={c.params} /></td>
          </tr>
        )
      })}
    </Table>
  )
}

/** A component's params, as given: `key value` pairs, a nested value as JSON text, a 64-hex value shortened. */
export function ParamList({ params }: { params: Params }) {
  const entries = Object.entries(params ?? {})
  if (!entries.length) return null
  return (
    <div className="params">
      {entries.map(([key, value]) => (
        <span key={key}>
          <span className="pk">{key}</span>{' '}
          {typeof value === 'string' && isHex64(value)
            ? <span className="idc">{short(value)}<CopyButton value={value} label="Copy full value" /></span>
            : paramText(value)}
        </span>
      ))}
    </div>
  )
}
