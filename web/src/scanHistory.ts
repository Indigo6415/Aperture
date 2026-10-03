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
  if (!caseId) return []
  const list = await api.listCaseScans(caseId, tool)
  const full = await Promise.all(
    list.map(async (s) => {
      try {
        return await api.getCaseScan(s.id)
      } catch {
        return null
      }
    }),
  )
  const out: RestoredScan<T>[] = []
  for (const f of full) {
    if (!f || !f.data) continue
    try {
      out.push({ scan: f, data: JSON.parse(f.data) as T })
    } catch {
      // skip an unparseable row rather than breaking the whole restore
    }
  }
  return out
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
