import type { RequestRecord } from './types'

// RequestFilters is the per-column filter state of the request inspector. Every
// field is raw text as typed; the parsers below turn it into a predicate. An
// empty field means that column is not filtered.
export interface RequestFilters {
  method: string
  status: string
  url: string
  size: string
  time: string
  sent: string
}

export const EMPTY_REQUEST_FILTERS: RequestFilters = {
  method: '',
  status: '',
  url: '',
  size: '',
  time: '',
  sent: '',
}

export type RecordPredicate = (r: RequestRecord) => boolean

// Unit multipliers for the size and time columns. A bare number is taken in
// the column's base unit (bytes for size, milliseconds for time).
const SIZE_UNITS: Record<string, number> = {
  '': 1,
  b: 1,
  k: 1024,
  kb: 1024,
  m: 1024 * 1024,
  mb: 1024 * 1024,
}
const TIME_UNITS: Record<string, number> = { '': 1, ms: 1, s: 1000 }

// numberPredicate parses a comparison such as "200", ">=400", "<1kb" or "10mb"
// into a test on a number. Returns null when the text is blank or does not
// parse, so the caller can tell "no filter" apart from "bad filter" by checking
// whether the text is empty.
export function numberPredicate(text: string, units: Record<string, number>): ((n: number) => boolean) | null {
  const m = text.trim().toLowerCase().match(/^(>=|<=|>|<|=)?\s*(\d+(?:\.\d+)?)\s*([a-z]*)$/)
  if (!m) return null
  // A unit we don't know makes the whole filter invalid rather than silently
  // ignoring it, so "5gb" can't be mistaken for "5".
  if (!(m[3] in units)) return null
  const value = parseFloat(m[2]) * units[m[3]]
  switch (m[1] ?? '=') {
    case '>':
      return (n) => n > value
    case '>=':
      return (n) => n >= value
    case '<':
      return (n) => n < value
    case '<=':
      return (n) => n <= value
    default:
      return (n) => n === value
  }
}

// statusPredicate handles the status column. Besides plain codes and
// comparisons, it accepts a class such as "2xx" and the word "error" for
// transport failures, which have no status code of their own.
export function statusPredicate(text: string): RecordPredicate | null {
  const t = text.trim().toLowerCase()
  if (t === 'error') return (r) => !!r.error
  const cls = t.match(/^([1-5])xx$/)
  if (cls) {
    const digit = Number(cls[1])
    return (r) => !r.error && Math.floor(r.statusCode / 100) === digit
  }
  const test = numberPredicate(t, { '': 1 })
  if (!test) return null
  // Errors carry no real status code, so a numeric status filter never matches them.
  return (r) => !r.error && test(r.statusCode)
}

// timeOfDaySeconds parses "14:03" or "14:03:22" into seconds since local
// midnight, or returns null when the text is not a clock time.
function timeOfDaySeconds(text: string): number | null {
  const m = text.trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/)
  if (!m) return null
  const h = Number(m[1])
  const min = Number(m[2])
  const s = m[3] === undefined ? 0 : Number(m[3])
  if (h > 23 || min > 59 || s > 59) return null
  return h * 3600 + min * 60 + s
}

// sentPredicate filters on when a request was sent, by local time of day. A
// single time ("14:03") matches requests sent at or after it. A range
// ("14:00-14:05") matches requests sent within it, inclusive at both ends.
export function sentPredicate(text: string): RecordPredicate | null {
  const parts = text.split('-')
  if (parts.length > 2) return null
  const from = timeOfDaySeconds(parts[0])
  if (from === null) return null
  const secondsOf = (r: RequestRecord) => {
    const d = new Date(r.timestamp)
    return d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds()
  }
  if (parts.length === 1) return (r) => secondsOf(r) >= from
  const to = timeOfDaySeconds(parts[1])
  if (to === null) return null
  return (r) => {
    const s = secondsOf(r)
    return s >= from && s <= to
  }
}

// buildPredicates turns the filter state into one predicate per active column.
// A column whose text is blank or invalid contributes nothing, so a half-typed
// filter doesn't hide everything.
export function buildPredicates(f: RequestFilters): RecordPredicate[] {
  const preds: RecordPredicate[] = []
  if (f.method) {
    const method = f.method
    preds.push((r) => r.method === method)
  }
  const url = f.url.trim().toLowerCase()
  if (url) preds.push((r) => r.url.toLowerCase().includes(url))
  const status = statusPredicate(f.status)
  if (status) preds.push(status)
  const size = numberPredicate(f.size, SIZE_UNITS)
  if (size) preds.push((r) => size(r.size))
  // An errored request has no response time, so any time filter excludes it.
  const time = numberPredicate(f.time, TIME_UNITS)
  if (time) preds.push((r) => !r.error && time(r.ttfbMs))
  const sent = sentPredicate(f.sent)
  if (sent) preds.push(sent)
  return preds
}

// isInvalidFilter reports whether a column has text that didn't parse, so the
// input can show that instead of silently ignoring what the user typed.
export function isInvalidFilter(column: keyof RequestFilters, text: string): boolean {
  if (!text.trim()) return false
  switch (column) {
    case 'status':
      return statusPredicate(text) === null
    case 'size':
      return numberPredicate(text, SIZE_UNITS) === null
    case 'time':
      return numberPredicate(text, TIME_UNITS) === null
    case 'sent':
      return sentPredicate(text) === null
    default:
      return false
  }
}

// hasActiveFilters reports whether any column has text in it, so the view can
// offer a single "clear" action only when there is something to clear.
export function hasActiveFilters(f: RequestFilters): boolean {
  return Object.values(f).some((v) => v.trim() !== '')
}

// SortKey names a column the inspector can sort by. Every column has one.
export type SortKey = 'method' | 'status' | 'url' | 'size' | 'time' | 'sent'

// SortState is the active sort: which column, and which way.
export interface SortState {
  key: SortKey
  dir: 'asc' | 'desc'
}

// sortValue returns the value a row sorts by in one column. Errored rows have
// no status or response time, so they take -1 and group at the start of an
// ascending sort instead of being mixed in with real values.
function sortValue(r: RequestRecord, key: SortKey): number | string {
  switch (key) {
    case 'method':
      return r.method
    case 'status':
      return r.error ? -1 : r.statusCode
    case 'url':
      return r.url.toLowerCase()
    case 'size':
      return r.size
    case 'time':
      return r.error ? -1 : r.ttfbMs
    case 'sent':
      return new Date(r.timestamp).getTime()
  }
}

// sortRecords returns a sorted copy of records. Rows that compare equal keep
// their log order, because Array.prototype.sort is stable, so a sort on a column
// with many ties still reads in the order the requests were sent.
export function sortRecords(records: RequestRecord[], sort: SortState | null): RequestRecord[] {
  if (!sort) return records
  const sign = sort.dir === 'asc' ? 1 : -1
  return [...records].sort((a, b) => {
    const x = sortValue(a, sort.key)
    const y = sortValue(b, sort.key)
    // Comparison with < and > works for both numbers and strings, which is why
    // sortValue can return either.
    if (x < y) return -sign
    if (x > y) return sign
    return 0
  })
}

// nextSort steps a column header through its three states: unsorted, then
// ascending, then descending, then back to unsorted. Clicking a different
// column starts it ascending.
export function nextSort(current: SortState | null, key: SortKey): SortState | null {
  if (!current || current.key !== key) return { key, dir: 'asc' }
  if (current.dir === 'asc') return { key, dir: 'desc' }
  return null
}
