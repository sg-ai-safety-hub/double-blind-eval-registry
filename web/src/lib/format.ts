// How values are written on the page. Pure functions, tested with `pnpm test`.

const HEX64 = /^[0-9a-f]{64}$/
const OCI_PREFIX = 'sha256:'
const SHORT = 7 // characters of a hash shown, as git shows a commit
const REF_REVISION = /^(.*@)([0-9a-f]{40,64})$/ // e.g. a Hugging Face reference: org/name@<commit>
const BARE_HASH = /^[0-9a-f]{40,}$/
const SIGNIFICANT = 3
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
// Only UTC times are written out; any other string is shown as given (reported times can be anything).
const UTC_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|\+00:00)$/

export function isHex64(value: string): boolean {
  return HEX64.test(value)
}

export function short(digest: string): string {
  return (digest.startsWith(OCI_PREFIX) ? digest.slice(OCI_PREFIX.length) : digest).slice(0, SHORT)
}

export function shortRef(value: string): string {
  if (BARE_HASH.test(value)) return short(value)
  const ref = REF_REVISION.exec(value)
  return ref ? ref[1] + short(ref[2]) : value
}

/** A metric value as shown, and its exact value when rounding changed it. */
export function metricValue(value: unknown): { text: string; exact?: string } {
  if (typeof value === 'number' && !Number.isInteger(value)) {
    const integerDigits = Math.max(1, Math.floor(Math.log10(Math.abs(value))) + 1)
    const text = String(Number(value.toPrecision(Math.max(SIGNIFICANT, integerDigits))))
    return text === String(value) ? { text } : { text, exact: String(value) }
  }
  return { text: typeof value === 'string' ? value : JSON.stringify(value) }
}

export function paramText(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value)
}

export function formatSize(bytes: number): string {
  if (bytes < 1000) return `${bytes} B`
  if (bytes < 1_000_000) return `${(bytes / 1000).toFixed(1)} kB`
  return `${(bytes / 1_000_000).toFixed(1)} MB`
}

export function formatDate(iso: string): string {
  const t = UTC_TIME.exec(iso)
  return t ? `${Number(t[3])} ${MONTHS[Number(t[2]) - 1]} ${t[1]}` : iso
}

export function formatDateTime(iso: string, seconds = false): string {
  const t = UTC_TIME.exec(iso)
  if (!t) return iso
  return `${formatDate(iso)}, ${t[4]}:${t[5]}${seconds ? `:${t[6]}` : ''} UTC`
}

export function formatUnix(seconds: number): string {
  return formatDateTime(new Date(seconds * 1000).toISOString(), true)
}

/** Pending checks' reasons, each once, without one that only extends another ("…, so it is not looked up"). */
export function reasons(details: string[]): string {
  const distinct = [...new Set(details)]
  return distinct.filter((d) => !distinct.some((other) => other !== d && d.startsWith(other))).join('; ')
}

export function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}
