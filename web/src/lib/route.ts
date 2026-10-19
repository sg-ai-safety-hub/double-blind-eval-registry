// Hash routes (no router library). A detail page's id must be 64 lowercase hex, so every link the UI
// builds comes from a validated id, never from receipt text.
import { isHex64 } from './format.ts'

export type ListPage = 'home' | 'models' | 'evals' | 'records'
export type DetailPage = 'model' | 'config' | 'eval' | 'record'
export type Route =
  | { page: ListPage }
  | { page: DetailPage; id: string }
  | { page: 'search'; query: string } // the search box's text, decoded: shown only as text, never linked
  | { page: 'notfound' }

const LISTS: Record<string, ListPage> = { '': 'home', models: 'models', evals: 'evals', records: 'records' }
const DETAILS: readonly DetailPage[] = ['model', 'config', 'eval', 'record']
const OCI_PREFIX = 'sha256:'
// What /api/lookup can answer, and the page for it. A component has no page: the UI opens a system that uses it.
const LOOKUP_PAGES: Record<string, DetailPage | null> = {
  system: 'config', eval: 'eval', record: 'record', model: 'model', component: null,
}

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, '').split('/')
  if (parts.length === 1 && parts[0] in LISTS) return { page: LISTS[parts[0]] }
  const [page, id] = parts
  if (parts.length === 2 && page === 'search' && id) {
    try {
      return { page: 'search', query: decodeURIComponent(id) }
    } catch {
      return { page: 'notfound' } // malformed %-encoding
    }
  }
  if (parts.length === 2 && (DETAILS as readonly string[]).includes(page) && isHex64(id)) {
    return { page: page as DetailPage, id }
  }
  return { page: 'notfound' }
}

/** The link to a detail page, or null if `id` (bare hex, or an OCI digest) isn't a 64-hex id. */
export function hrefFor(page: DetailPage, id: string): string | null {
  const hex = id.startsWith(OCI_PREFIX) ? id.slice(OCI_PREFIX.length) : id
  return isHex64(hex) ? `#/${page}/${hex}` : null
}

export function searchHref(query: string): string {
  return `#/search/${encodeURIComponent(query)}`
}

/** A link off this site (Rekor's entry page, which the API gives), only if it is plain https. */
export function externalHref(url: string): string | null {
  if (!url.startsWith('https://')) return null
  try {
    return new URL(url).protocol === 'https:' ? url : null
  } catch {
    return null
  }
}

export function lookupPage(kind: string): DetailPage | null {
  return LOOKUP_PAGES[kind] ?? null
}
