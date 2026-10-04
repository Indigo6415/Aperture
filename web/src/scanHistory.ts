import { api } from './api'
import type { CaseScan, ScanTool } from './types'

// RestoredScan is one persisted run, decoded back into the response shape
// the tool that produced it already knows how to render (T is that tool's
// own *Response type, e.g. ProbeScanResponse).
export interface RestoredScan<T> {
  scan: CaseScan
  data: T
}

// loadCaseScans fetches every scan persisted for one tool in this case,
// most recent first (matching store.ListCaseScans), with each row's raw
// data payload already parsed -- the shared plumbing every scan tool tab
// uses both to restore its live results on reload and to populate its
// "Scans" history tab. Rows whose data fails to parse (or fails to fetch)
// are skipped rather than failing the whole restore.
export async function loadCaseScans<T>(caseId: string, tool: ScanTool): Promise<RestoredScan<T>[]> {
  const page = await loadCaseScansPage<T>(caseId, tool)
  return page.items
}

// CaseScansPage is one slice of a case's scan history: the parsed rows that
// were fetched in full, plus how many rows the case has for that tool in
// total, so a caller can show "N of total" and offer to load the rest.
export interface CaseScansPage<T> {
  items: RestoredScan<T>[]
  total: number
}

// loadCaseScansPage is loadCaseScans with an optional limit. The list call
// is one cheap request that already returns every row's metadata, but each
// row's full record costs its own GET -- so when limit is set, only the
// newest `limit` rows get that per-row fetch. Omit limit to fetch them all.
export async function loadCaseScansPage<T>(caseId: string, tool: ScanTool, limit?: number): Promise<CaseScansPage<T>> {
  if (!caseId) return { items: [], total: 0 }
  const list = await api.listCaseScans(caseId, tool)
  // list is most recent first, so slicing keeps the newest rows.
  const wanted = limit === undefined ? list : list.slice(0, limit)
  const full = await Promise.all(
    wanted.map(async (s) => {
      try {
        return await api.getCaseScan(s.id)
      } catch {
        return null
      }
    }),
  )
  const items: RestoredScan<T>[] = []
  for (const f of full) {
    if (!f || !f.data) continue
    try {
      items.push({ scan: f, data: JSON.parse(f.data) as T })
    } catch {
      // skip an unparseable row rather than breaking the whole restore
    }
  }
  return { items, total: list.length }
}

// latestByTarget keeps only the newest row per distinct target value --
// scans is already most-recent-first (from loadCaseScans), so the first
// occurrence of a target wins. Used to seed a tool's live per-target map on
// mount, where only the latest run per target is shown.
export function latestByTarget<T>(scans: RestoredScan<T>[]): RestoredScan<T>[] {
  const seen = new Set<string>()
  const out: RestoredScan<T>[] = []
  for (const s of scans) {
    if (seen.has(s.scan.target)) continue
    seen.add(s.scan.target)
    out.push(s)
  }
  return out
}

// historyLabel is the composite display name a "Scans" history tab uses
// for one past run -- BatchResultsPanel shows this string as both the row's
// key and its rendered target, so a target's several past runs (which would
// otherwise collide on the same key) each get their own label.
export function historyLabel(scan: CaseScan): string {
  return `${scan.target} — ${new Date(scan.createdAt).toLocaleString()}`
}
