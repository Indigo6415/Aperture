import { useEffect, useState } from 'react'
import type { ScanTool } from '../types'
import { historyLabel, loadCaseScans, type RestoredScan } from '../scanHistory'
import { BatchResultsPanel, type BatchResultSummary } from './BatchResultsPanel'

// ScanHistoryPanel is a tool tab's "Scans" view: every run persisted for
// this case+tool (see store.SaveCaseScan), most recent first, reusing that
// tool's own getSummary/renderCard -- the same functions it already passes
// to its live BatchResultsPanel -- so a past run renders exactly the way it
// did the moment it finished. Unlike the live view (latest run per target
// only), every past run shows up here, each labelled with its own
// timestamp so re-running the same target repeatedly doesn't hide earlier
// results.
export function ScanHistoryPanel<T, S>({
  caseId,
  tool,
  toState,
  getSummary,
  renderCard,
}: {
  caseId: string
  tool: ScanTool
  // toState wraps one run's raw decoded response into the same "done" state
  // shape that tool's live scans map already uses (e.g. adding a
  // testStatus: {} for a tool whose card also shows live per-module
  // progress while running).
  toState: (data: T) => S
  getSummary: (s: S) => BatchResultSummary
  renderCard: (target: string, s: S) => React.ReactNode
}) {
  const [loading, setLoading] = useState(true)
  const [entries, setEntries] = useState<[string, S][]>([])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    loadCaseScans<T>(caseId, tool).then((list: RestoredScan<T>[]) => {
      if (cancelled) return
      // A saved scan's ID is the ID its requests were logged under, so a
      // restored row gets the same Inspect requests menu as a live one.
      setEntries(list.map((r) => [historyLabel(r.scan), { ...toState(r.data), scanId: r.scan.id }]))
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, tool])

  if (loading) {
    return <div className="flex h-64 items-center justify-center text-sm text-neutral-600">Loading scan history…</div>
  }
  if (entries.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
        No saved scans yet -- runs launched with this case selected will show up here.
      </div>
    )
  }
  return <BatchResultsPanel entries={entries} getSummary={getSummary} renderCard={renderCard} />
}
