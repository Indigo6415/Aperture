import { useRef } from 'react'
import { ApiError, api, watchScan } from './api'
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
  status: 'running' | 'done' | 'error' | 'cancelled'
  // scanId is set once the scan has started, so its card's Stop button can
  // cancel it (see stopTrackedScan).
  scanId?: string
  progress?: ScanProgress
  result?: R
  error?: string
}

// ScanStoppedError is what streamResult rejects with when the user stopped the
// scan. It isn't a failure, so runTrackedScan records it as cancelled rather
// than as an error.
export class ScanStoppedError extends Error {}

// runTrackedScan starts one scan via start (whose POST returns the scan ID),
// then streams its progress into the caller's state through update until the
// terminal event arrives, and resolves with the outcome. update receives a function from the scan's previous
// state to its next -- the caller decides where that lands (typically a
// setState keyed by target), so one runner serves every scanner.
// signal, when given, is a batch's stop signal (see useScanBatch). A target
// that hasn't started yet is never started once it fires, and one whose start
// request is still in flight is stopped the moment that request returns.
export async function runTrackedScan<R>(
  start: () => Promise<{ scanId: string }>,
  update: (fn: (prev: TrackedScan<R>) => TrackedScan<R>) => void,
  signal?: AbortSignal,
): Promise<{ result?: R; error?: string }> {
  try {
    // Stopped before it began: nothing is sent to the server at all.
    if (signal?.aborted) throw new ScanStoppedError('Scan stopped')
    const { scanId } = await start()
    update((prev) => ({ ...prev, status: 'running', scanId, progress: prev.progress ?? emptyProgress() }))
    // The batch was stopped while the start request was in flight. Cancel it
    // here, since the stop-all click couldn't see its scan ID yet.
    if (signal?.aborted) {
      stopTrackedScan({ scanId })
      throw new ScanStoppedError('Scan stopped')
    }
    const result = await streamResult<R>(
      scanId,
      (ev) => {
        update((prev) => ({ ...prev, progress: applyScanEvent(prev.progress ?? emptyProgress(), ev) }))
      },
      signal,
    )
    update((prev) => ({ ...prev, status: 'done', result, progress: finishProgress(prev.progress ?? emptyProgress()) }))
    return { result }
  } catch (err) {
    // A stopped scan keeps its progress so far but drops the error text, and
    // it is not reported as an error.
    if (err instanceof ScanStoppedError) {
      update((prev) => ({ ...prev, status: 'cancelled', progress: finishProgress(prev.progress ?? emptyProgress()) }))
      return {}
    }
    const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
    update((prev) => ({ ...prev, status: 'error', error: message }))
    return { error: message }
  }
}

// stopTrackedScan asks the server to stop a tracked scan. The card then
// settles itself when the terminal event arrives, so this only sends the
// request. A failed request leaves the scan running, which the card still
// shows, so the error is not surfaced here.
export function stopTrackedScan(scan?: { scanId?: string }) {
  if (!scan?.scanId) return
  void api.cancelScan(scan.scanId).catch(() => undefined)
}

// streamResult watches scanId until its terminal "done" event, forwarding
// every progress event to onProgress, and resolves with the result. Rejects
// on a failed scan, with ScanStoppedError on a stopped one, or if the socket
// closes before any "done" arrives.
function streamResult<R>(scanId: string, onProgress: (ev: RunEvent) => void, signal?: AbortSignal): Promise<R> {
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
        if (ev.status === 'cancelled') reject(new ScanStoppedError('Scan stopped'))
        else if (ev.status === 'failed') reject(new Error(ev.message || 'Scan failed'))
        else resolve(ev.result as R)
      },
      () => {
        if (settled) return
        // A socket that drops after a stop was requested is the stop, not a fault.
        if (signal?.aborted) reject(new ScanStoppedError('Scan stopped'))
        else reject(new Error('Lost the connection before the scan finished'))
      },
    )
  })
}

// MAX_CONCURRENT_SCANS caps how many targets in one batch run are in flight at
// once. Each started scan holds a WebSocket and a request budget, so starting
// a large batch all at once can exhaust the browser's connection resources.
export const MAX_CONCURRENT_SCANS = 4

// runBatch starts run for every item, keeping at most limit of them in flight.
// Each run settles its own card through runTrackedScan, so this only paces
// when the next one starts. Once signal fires, no further item is started.
export function runBatch<T>(items: T[], run: (item: T) => Promise<unknown>, limit = MAX_CONCURRENT_SCANS, signal?: AbortSignal): void {
  let next = 0
  // worker starts items one after another until none are left (or the batch
  // is stopped), so each of the limit workers has at most one scan in flight.
  const worker = async () => {
    while (next < items.length && !signal?.aborted) {
      const item = items[next]
      next++
      await run(item)
    }
  }
  // Start up to limit workers, never more than there are items.
  for (let i = 0; i < Math.min(limit, items.length); i++) void worker()
}

// ScanBatch is the stop signal shared by one batch run's targets. A batch
// begins with a fresh signal, and stop fires it, so every target that hasn't
// started yet is skipped and every one in flight is cancelled.
export interface ScanBatch {
  // begin starts a new batch and returns its signal, for runBatch and each
  // target's run.
  begin: () => AbortSignal
  // current returns the signal a single retry should use: the live batch's, or
  // a fresh one if the last batch was stopped. A retry after a stop then runs.
  current: () => AbortSignal
  // stop cancels the batch. Pair it with stopAllScans to update the cards.
  stop: () => void
}

// useScanBatch holds the current batch's abort controller for a scanner view.
export function useScanBatch(): ScanBatch {
  const controller = useRef<AbortController | null>(null)
  return {
    begin: () => {
      controller.current = new AbortController()
      return controller.current.signal
    },
    current: () => {
      if (!controller.current || controller.current.signal.aborted) controller.current = new AbortController()
      return controller.current.signal
    },
    stop: () => controller.current?.abort(),
  }
}

// TrackedLike is the part of a target's scan state that stopAllScans reads: its
// status, its scan ID for cancelling, and its live progress.
interface TrackedLike {
  status: string
  scanId?: string
  progress?: ScanProgress
}

// stopAllScans is the state update for the batch-wide Stop button. Every target
// still running is cancelled on the server and shown as stopped at once. Each
// card then settles to its final state when the server's terminal event lands.
// Targets that already finished are left as they are.
export function stopAllScans<T extends TrackedLike>(scans: Record<string, T>): Record<string, T> {
  const next: Record<string, T> = {}
  for (const [key, scan] of Object.entries(scans)) {
    if (scan.status !== 'running') {
      next[key] = scan
      continue
    }
    stopTrackedScan(scan)
    next[key] = { ...scan, status: 'cancelled', progress: finishProgress(scan.progress ?? emptyProgress()) }
  }
  return next
}
