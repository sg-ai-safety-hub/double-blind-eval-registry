// The frame every page shares (dev banner, header with search, footer), and hash routing.
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { getJson, useApi, type Health, type SystemSummary } from './lib/api.ts'
import { isHex64 } from './lib/format.ts'
import { hrefFor, lookupPage, parseRoute, searchHref, type Route } from './lib/route.ts'
import { Config, Eval, Model } from './pages/Details.tsx'
import { Evals, Home, Models, Records } from './pages/Lists.tsx'
import { RecordPage } from './pages/Record.tsx'
import { Search } from './pages/Search.tsx'
import { CopyButton, Icon, NotFound, RegistryContext, TooltipLayer, Waiting } from './ui.tsx'

const NAME = 'Double Blind Eval Registry'

function useRoute(): Route {
  const [route, setRoute] = useState(() => parseRoute(window.location.hash))
  useEffect(() => {
    const onChange = () => {
      setRoute(parseRoute(window.location.hash))
      window.scrollTo(0, 0)
    }
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return route
}

/** Where a 64-hex digest leads: its page, or for a component, the newest configuration that uses it. */
async function lookup(hex: string): Promise<string | null> {
  const found = await getJson<{ kind: string; id: string }>(`/api/lookup/${hex}`)
  if (found.status !== 'ok') return null
  const page = lookupPage(found.data.kind)
  if (page) return hrefFor(page, found.data.id)
  const component = await getJson<{ systems: SystemSummary[] }>(`/api/components/${hex}`)
  const newest = component.status === 'ok' ? component.data.systems[0] : undefined
  return newest ? hrefFor('config', newest.digest) : null
}

function Page({ route }: { route: Route }) {
  switch (route.page) {
    case 'home': return <Home />
    case 'models': return <Models />
    case 'evals': return <Evals />
    case 'records': return <Records />
    case 'model': return <Model id={route.id} />
    case 'config': return <Config id={route.id} />
    case 'eval': return <Eval id={route.id} />
    case 'record': return <RecordPage id={route.id} />
    case 'search': return <Search query={route.query} />
    case 'notfound': return <NotFound />
  }
}

export default function App() {
  const health = useApi<Health>('/api/health')
  const route = useRoute()
  const [query, setQuery] = useState('')
  const search = useRef<HTMLInputElement>(null)

  useEffect(() => { // the box shows the search a results page is for, e.g. after Back
    if (route.page === 'search') setQuery(route.query)
  }, [route])

  useEffect(() => { // "/" focuses the search box, unless the reader is typing somewhere
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement
      if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey) {
        e.preventDefault()
        search.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Search runs on Enter, the same from every page: a 64-hex digest opens its page; anything else, or a digest
  // on file nowhere, opens the results page, which shows the nothing page when nothing matches.
  const onSubmit = useCallback((e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const text = query.trim()
    if (!text) return
    const hex = text.toLowerCase()
    if (!isHex64(hex)) {
      window.location.hash = searchHref(text)
      return
    }
    lookup(hex).then((href) => {
      if (href) setQuery('')
      window.location.hash = href ?? searchHref(hex)
    })
  }, [query])

  if (health.status !== 'ok') return <Waiting loads={[health]} />
  const { mode, modelRole, policyHash, version } = health.data
  const dev = mode === 'dev'
  const nav = route.page === 'models' || route.page === 'model' || route.page === 'config' ? 'models'
    : route.page === 'evals' || route.page === 'eval' ? 'evals' : null

  return (
    <RegistryContext.Provider value={{ dev, modelRole }}>
      {dev && (
        <div className="dev">
          <div className="wrap dev-in"><strong>DEV MODE</strong>
            <span>Test data only. Nothing on this page is authoritative.</span></div>
        </div>
      )}
      <header className="top">
        <div className="wrap top-in">
          <a className="brand" href="#/">{NAME}</a>
          <form className="search-box" role="search" onSubmit={onSubmit}>
            <label htmlFor="q" className="sr">Search</label>
            <div className="search">
              <Icon name="search" />
              <input id="q" ref={search} type="search" placeholder="Search by name, or paste a SHA-256 digest"
                autoComplete="off" spellCheck={false} value={query} onChange={(e) => setQuery(e.target.value)} />
              <kbd>/</kbd>
            </div>
          </form>
          <nav className="nav" aria-label="Main">
            <a href="#/models" className={nav === 'models' ? 'on' : undefined}
              aria-current={route.page === 'models' ? 'page' : undefined}>Models</a>
            <a href="#/evals" className={nav === 'evals' ? 'on' : undefined}
              aria-current={route.page === 'evals' ? 'page' : undefined}>Evals</a>
          </nav>
        </div>
      </header>

      {/* A new address is a new page: its tables start again on page 1, newest first. */}
      <Page key={JSON.stringify(route)} route={route} />

      <footer>
        <div className="wrap foot-in">
          <span>{NAME} {version}</span>
          <span className="idc">Policy <span className="mono">{policyHash.slice(0, 7)}</span>
            <CopyButton value={policyHash} label="Copy the policy file's SHA-256" /></span>
        </div>
      </footer>
      <TooltipLayer />
    </RegistryContext.Provider>
  )
}
