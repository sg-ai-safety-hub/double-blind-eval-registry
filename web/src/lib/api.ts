// The registry's read API, as the UI uses it. Paths are built only from validated hex ids.
import { useEffect, useState } from 'react'

export type State = 'verified' | 'incomplete'

export interface Health {
  mode: string
  policyHash: string
  version: string
  modelRole: string // the component role that identifies a model
}

export interface Check {
  id: string
  status: string // PASS or PENDING on an accepted record
  detail: string
}

export interface Alias {
  scheme: string
  value: string
}

export type Params = Record<string, unknown> | null

export interface Component {
  role: string
  scheme: string
  digest: string
  name: string | null
  alsoKnownAs: Alias[]
  params: Params
}

export interface Enclave {
  type: string
  measurement: string
  repo: string
  releaseTag: string
  releaseDigest: string
}

export interface Publication {
  uuid: string
  logIndex: number
  integratedTime: number // Rekor's clock, Unix seconds
  url: string
}

export interface RecordJson {
  recordId: string
  size: number
  receivedAt: string
  state: State
  checks: Check[]
  enclave: Enclave | null
  publication: Publication | null
  benchmarkOwner: { email: string; display: string }
  subjectName: string | null
  systemDigest: string
  components: Component[]
  eval: { digest: string; evalSet: { scheme: string; digest: string }; name: string | null }
  results: { metrics: unknown[]; counts: { submitted: number; completed: number; failed: number } | null }
  reported: {
    platform: string | null
    cvmVersion: string | null
    runId: string | null
    configDigest: string | null
    startedAt: string | null
    finishedAt: string | null
  }
}

export interface SystemSummary {
  digest: string
  subjectNames: string[]
  state: State
}

export interface ModelView {
  digest: string
  names: string[]
  alsoKnownAs: Alias[]
  state: State
  systems: SystemSummary[]
  records: RecordJson[]
}

export interface SystemComponent {
  role: string
  scheme: string
  digest: string
  names: string[]
  params: Params
}

export interface SystemView {
  digest: string
  subjectNames: string[]
  state: State
  components: SystemComponent[]
  records: RecordJson[]
}

export interface EvalView {
  digest: string
  evalSet: { scheme: string; digest: string }
  names: string[]
  state: State
  records: RecordJson[]
}

export type Load<T> =
  | { status: 'loading' }
  | { status: 'ok'; data: T }
  | { status: 'notfound' }
  | { status: 'error'; message: string }

/** GET `path` (one of the API's, built from validated ids) and track its result. */
export function useApi<T>(path: string): Load<T> {
  const [load, setLoad] = useState<{ path: string; load: Load<T> }>({ path, load: { status: 'loading' } })
  useEffect(() => {
    const controller = new AbortController()
    getJson<T>(path, controller.signal).then((result) => {
      if (!controller.signal.aborted) setLoad({ path, load: result })
    })
    return () => controller.abort()
  }, [path])
  return load.path === path ? load.load : { status: 'loading' } // never show the previous page's data
}

export async function getJson<T>(path: string, signal?: AbortSignal): Promise<Load<T>> {
  try {
    const response = await fetch(path, { signal })
    if (response.status === 404) return { status: 'notfound' }
    if (!response.ok) return { status: 'error', message: `HTTP ${response.status}` }
    return { status: 'ok', data: (await response.json()) as T }
  } catch (e) {
    return { status: 'error', message: e instanceof Error ? e.message : String(e) }
  }
}
