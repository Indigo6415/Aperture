import { ApiError, watchScan } from './api'
import type { RunEvent, ScanCheckInfo } from './types'

// CheckState is one check's place in a running scan: idle (queued, not yet
// started -- shown grey), running (in flight -- orange), or done (finished,
// with or without findings -- green). See CheckMatrix in ScanCheckCard.tsx.
export type CheckState = 'idle' | 'running' | 'done'

// ScanCheck is one registered check plus how far along it has got.
export interface ScanCheck extends ScanCheckInfo {
  state: CheckState
  findings: number
  error?: string
}

// ScanProgress is one streamed scan's live state: every check it has
// registered so far (the list grows as a scan discovers more work, which is
// why a total is only ever what's been committed to), the latest scan-wide
// phase line, and running totals. An empty ScanProgress is what a scan that
// streams nothing (or a restored history entry) carries.
export interface ScanProgress {
  checks: ScanCheck[]
  phase?: string
  startedAt?: number
  lastDone?: string
  findings: number
}

export function emptyProgress(): ScanProgress {
  return { checks: [], findings: 0 }
}

// applyScanEvent folds one streamed event into progress, returning a new
// ScanProgress (never mutating the old one -- React needs a fresh reference
// to re-render). Non-progress events (the terminal "done", or a finding
// event from an engine job that happens to share the socket type) leave
// progress unchanged.
export function applyScanEvent(p: ScanProgress, ev: RunEvent): ScanProgress {
  const startedAt = p.startedAt ?? Date.now()
  switch (ev.type) {
    case 'plan': {
      // Adds checks not already known, in the order they were registered.
      // A repeated plan for an existing ID is ignored rather than resetting
      // its state, so a late re-announcement can't un-finish a check.
      const known = new Set(p.checks.map((c) => c.id))
      const added: ScanCheck[] = (ev.checks ?? [])
        .filter((c) => !known.has(c.id))
        .map((c) => ({ id: c.id, label: c.label, group: c.group, state: 'idle', findings: 0 }))
      if (added.length === 0) return { ...p, startedAt }
      return { ...p, startedAt, checks: [...p.checks, ...added] }
    }
    case 'checkStart': {
      if (!ev.checkId) return p
      return { ...p, startedAt, checks: updateCheck(p.checks, ev.checkId, ev.checkId, (c) => ({ ...c, state: 'running' })) }
    }
    case 'checkDone': {
      if (!ev.checkId) return p
      const id = ev.checkId
      const checks = updateCheck(p.checks, id, id, (c) => ({
        ...c,
        state: 'done',
        findings: ev.findings ?? 0,
        error: ev.message || undefined,
      }))
      const label = checks.find((c) => c.id === id)?.label
      return {
        ...p,
        startedAt,
        checks,
        lastDone: label ?? p.lastDone,
        findings: checks.reduce((n, c) => n + c.findings, 0),
      }
    }
    case 'phase':
      return { ...p, startedAt, phase: ev.message || undefined }
    default:
      return p
  }
}

// updateCheck applies fn to the check with id, adding it first (labelled
// label) if it's somehow not registered yet -- a start/done arriving before
// its plan shouldn't silently vanish from the grid.
function updateCheck(checks: ScanCheck[], id: string, label: string, fn: (c: ScanCheck) => ScanCheck): ScanCheck[] {
  if (!checks.some((c) => c.id === id)) {
    return [...checks, fn({ id, label, state: 'idle', findings: 0 })]
  }
  return checks.map((c) => (c.id === id ? fn(c) : c))
}

// finishProgress settles a scan's progress once its terminal "done" event
// has landed: every check still idle or running is marked done, since the
// scan has finished and nothing further will report on them. Without this a
// check whose own completion event was dropped (a slow socket, say) would
// stay orange forever on a card whose scan is actually over.
export function finishProgress(p: ScanProgress): ScanProgress {
  const checks = p.checks.map((c) => (c.state === 'done' ? c : { ...c, state: 'done' as const }))
  return { ...p, checks, phase: undefined, findings: checks.reduce((n, c) => n + c.findings, 0) }
}

// TrackedScan is one target's whole lifecycle in a streamed batch: status
// drives the card's badge, progress drives its grid, and result/error are
// set once the scan finishes. Matches the shape each scanner's existing
// per-target state already used -- progress is just the new live part.
export interface TrackedScan<R> {
  status: 'running' | 'done' | 'error'
  progress?: ScanProgress
  result?: R
  error?: string
}

// runTrackedScan starts one scan via start (whose POST returns the scan ID),
// then streams its progress into the caller's state through update until the
// terminal event arrives, and resolves with the outcome. update receives a function from the scan's previous
// state to its next -- the caller decides where that lands (typically a
// setState keyed by target), so one runner serves every scanner.
export async function runTrackedScan<R>(
  start: () => Promise<{ scanId: string }>,
  update: (fn: (prev: TrackedScan<R>) => TrackedScan<R>) => void,
): Promise<{ result?: R; error?: string }> {
  try {
    const { scanId } = await start()
    update((prev) => ({ ...prev, status: 'running', progress: prev.progress ?? emptyProgress() }))
    const result = await streamResult<R>(scanId, (ev) => {
      update((prev) => ({ ...prev, progress: applyScanEvent(prev.progress ?? emptyProgress(), ev) }))
    })
    update((prev) => ({ ...prev, status: 'done', result, progress: finishProgress(prev.progress ?? emptyProgress()) }))
    return { result }
  } catch (err) {
    const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
    update((prev) => ({ ...prev, status: 'error', error: message }))
    return { error: message }
  }
}

// streamResult watches scanId until its terminal "done" event, forwarding
// every progress event to onProgress, and resolves with the result. Rejects
// on a failed scan, or if the socket closes before any "done" arrives.
function streamResult<R>(scanId: string, onProgress: (ev: RunEvent) => void): Promise<R> {
  return new Promise<R>((resolve, reject) => {
    let settled = false
    const stop = watchScan(
      scanId,
      (ev) => {
        if (ev.type !== 'done') {
          onProgress(ev)
          return
        }
        settled = true
        stop()
        if (ev.status === 'failed') reject(new Error(ev.message || 'Scan failed'))
        else resolve(ev.result as R)
      },
      () => {
        if (!settled) reject(new Error('Lost the connection before the scan finished'))
      },
    )
  })
}
