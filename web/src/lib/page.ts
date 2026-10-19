// Tables show their rows a page at a time. Pure, so tested.

export const PAGE_SIZE = 10

export interface Page<T> {
  rows: T[]
  page: number // from 0
  pages: number // at least 1, so an empty table is one empty page
  from: number // the rows shown, counted from 1, for "11–20 of 37"
  to: number
  total: number
}

/** Page `page` of `items`; a page out of range shows the nearest one (e.g. after the rows change). */
export function pageOf<T>(items: T[], page: number): Page<T> {
  const pages = Math.max(1, Math.ceil(items.length / PAGE_SIZE))
  const shown = Math.min(Math.max(page, 0), pages - 1)
  const start = shown * PAGE_SIZE
  const rows = items.slice(start, start + PAGE_SIZE)
  return { rows, page: shown, pages, from: rows.length ? start + 1 : 0, to: start + rows.length, total: items.length }
}
