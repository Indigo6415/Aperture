import { useEffect, useMemo, useRef, useState } from 'react'
import { inputBase } from '../formStyles'
import { formatDuration } from '../eta'
import type { ScanProgress } from '../scanProgress'
import { ScanTargetCard } from './ScanTargetCard'

export type ResultTone = 'danger' | 'warn' | 'clean' | 'neutral'

export interface BatchResultSummary {
  label: string
  tone: ResultTone
  // running is true while this target's scan is still in flight: its card
  // shows live progress, and its full results stay hidden until they land.
  running?: boolean
  // hasIssues says whether this target has anything worth a look, for the
  // "Issues only" toggle. Left unset, it falls back to the tone (danger or
  // warn means issues). Set it explicitly where tone alone isn't enough --
  // e.g. a neutral-toned nuclei host that only has info-severity findings.
  hasIssues?: boolean
}

// hasIssuesOf decides whether a finished target belongs in the "Issues only"
// view: an explicit hasIssues flag wins, otherwise a danger or warn tone
// counts as an issue and clean/neutral ones (no findings, not applicable) don't.
function hasIssuesOf(summary: BatchResultSummary): boolean {
  if (summary.hasIssues !== undefined) return summary.hasIssues
  return summary.tone === 'danger' || summary.tone === 'warn'
}

// MIN_CARD_WIDTH is the narrowest a domain card can get and still fit its
// check grid beside its text. The column count is however many of these fit
// across the panel, clamped to [1, MAX_COLUMNS] -- so a wide window shows up
// to six domains across, and a narrow one drops down to a single column.
const MIN_CARD_WIDTH = 300
const MAX_COLUMNS = 6
const GRID_GAP = 12

// ScanView is how the cards are arranged: 'grid' (cards in columns) or 'list'
// (one wide row per target). Both show the same content; see ScanTargetCard.
type ScanView = 'grid' | 'list'

const VIEW_STORAGE_KEY = 'aperture.scanView'

// readStoredView restores the last-chosen layout. Storage can be blocked or
// full, and the view is cosmetic, so any failure just falls back to the grid.
function readStoredView(): ScanView {
  try {
    return localStorage.getItem(VIEW_STORAGE_KEY) === 'list' ? 'list' : 'grid'
  } catch {
    return 'grid'
  }
}

// writeStoredView remembers the chosen layout for next time, best-effort.
function writeStoredView(view: ScanView) {
  try {
    localStorage.setItem(VIEW_STORAGE_KEY, view)
  } catch {
    // Not remembering the choice is fine; the toggle still works this session.
  }
}

// BatchResultsPanel is the shared "many targets, one batch run" layout for
// every scanner and for their history views. Each target is a card in a
// responsive grid -- its domain, live tallies, and a grid of every check it
// is running (see ScanTargetCard). Clicking a card opens that target's full
// results in a panel below the grid, so the cards stay a compact overview no
// matter how many results there are to read. A target with a single entry
// opens straight away.
export function BatchResultsPanel<T>({
  entries,
  getSummary,
  getProgress,
  renderCard,
}: {
  entries: [string, T][]
  getSummary: (state: T) => BatchResultSummary
  // getProgress returns a target's live per-check progress, when its scanner
  // streams it (see scanProgress.ts). Entries without it -- history rows, or
  // a scanner that doesn't stream yet -- still get a card, just without a grid.
  getProgress?: (state: T) => ScanProgress | undefined
  renderCard: (target: string, state: T) => React.ReactNode
}) {
  const [filter, setFilter] = useState('')
  // issuesOnly hides finished targets that came back clean. Running targets
  // always stay visible, since they may still turn something up.
  const [issuesOnly, setIssuesOnly] = useState(false)
  // undefined means "nothing chosen yet" (a lone target then auto-opens),
  // null means the user closed the detail, a string is the open target.
  const [openTarget, setOpenTarget] = useState<string | null | undefined>(undefined)
  const [view, setViewState] = useState<ScanView>(readStoredView)
  const setView = (next: ScanView) => {
    setViewState(next)
    writeStoredView(next)
  }
  const [gridRef, columns] = useColumnCount()

  const summaries = useMemo(() => new Map(entries.map(([t, s]) => [t, getSummary(s)])), [entries, getSummary])

  // filtered applies both filters: the text box (a substring match on the
  // target name) and the Issues only toggle.
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return entries.filter(([t]) => {
      if (q && !t.toLowerCase().includes(q)) return false
      if (!issuesOnly) return true
      const summary = summaries.get(t)
      return Boolean(summary?.running) || (summary !== undefined && hasIssuesOf(summary))
    })
  }, [entries, filter, issuesOnly, summaries])

  // keepTarget is the same visibility test as filtered, for a single target.
  const keepTarget = (t: string) => filtered.some(([x]) => x === t)

  const anyRunning = [...summaries.values()].some((s) => s.running)
  const now = useNow(anyRunning)

  // Totals across every target that's streaming progress -- they feed the
  // summary strip above the grid, so the overall shape of the run is visible
  // without adding up the cards by hand.
  const totals = useMemo(() => {
    let checks = 0
    let done = 0
    let findings = 0
    let finished = 0
    let startedAt: number | undefined
    for (const [t, s] of entries) {
      const p = getProgress?.(s)
      for (const c of p?.checks ?? []) {
        checks++
        if (c.state === 'done') done++
      }
      findings += p?.findings ?? 0
      if (!summaries.get(t)?.running) finished++
      if (p?.startedAt !== undefined && (startedAt === undefined || p.startedAt < startedAt)) startedAt = p.startedAt
    }
    return { checks, done, findings, finished, startedAt }
  }, [entries, getProgress, summaries])

  // A single target has nothing to pick between, so its detail opens by
  // default; with several, the detail waits for a click.
  const shownTarget = openTarget === undefined ? (entries.length === 1 ? entries[0][0] : null) : openTarget
  // An open detail for a target the Issues only view has hidden stays closed,
  // so the panel never shows results for a card that isn't in the grid.
  const shownEntry = shownTarget !== null ? entries.find(([t]) => t === shownTarget && keepTarget(t)) : undefined
  const showDetail = shownEntry !== undefined && !summaries.get(shownEntry[0])?.running

  return (
    <div className="space-y-4">
      {totals.checks > 0 && (
        <SummaryStrip
          domains={entries.length}
          finished={totals.finished}
          checks={totals.checks}
          done={totals.done}
          findings={totals.findings}
          elapsedSeconds={anyRunning && totals.startedAt !== undefined ? (now - totals.startedAt) / 1000 : null}
        />
      )}

      {entries.length > 0 && (
        <div className="flex items-center gap-2">
          {entries.length > 1 && (
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder={`Filter ${entries.length} targets…`}
              className={`${inputBase} text-xs`}
            />
          )}
          <button
            type="button"
            aria-pressed={issuesOnly}
            onClick={() => setIssuesOnly((v) => !v)}
            title="Hide targets that finished with no issues"
            className={`shrink-0 whitespace-nowrap rounded border px-2.5 py-1 text-xs transition-colors ${
              issuesOnly
                ? 'border-red-700 bg-red-950/40 text-red-300'
                : 'border-neutral-700 bg-neutral-950 text-neutral-400 hover:border-neutral-500 hover:text-neutral-200'
            }`}
          >
            Issues only
          </button>
          {entries.length > 1 && (
            <span className="shrink-0 whitespace-nowrap text-[11px] text-neutral-500">
              {filtered.length} of {entries.length} shown
            </span>
          )}
          <div className="ml-auto flex shrink-0 overflow-hidden rounded border border-neutral-700" role="group" aria-label="Layout">
            <ViewToggleButton label="Grid view" active={view === 'grid'} onClick={() => setView('grid')}>
              <GridIcon />
            </ViewToggleButton>
            <ViewToggleButton label="List view" active={view === 'list'} onClick={() => setView('list')}>
              <ListIcon />
            </ViewToggleButton>
          </div>
        </div>
      )}

      {view === 'list' ? (
        <div className="space-y-2">
          {filtered.map(([t, s]) => (
            <ScanTargetCard
              key={t}
              target={t}
              layout="list"
              summary={summaries.get(t) ?? { label: '', tone: 'neutral' }}
              progress={getProgress?.(s)}
              selected={shownTarget === t}
              onSelect={() => setOpenTarget(shownTarget === t ? null : t)}
            />
          ))}
        </div>
      ) : (
        <div
          ref={gridRef}
          className="grid"
          style={{ gridTemplateColumns: `repeat(${Math.min(columns, Math.max(1, filtered.length))}, minmax(0, 1fr))`, gap: GRID_GAP }}
        >
          {filtered.map(([t, s]) => (
            <ScanTargetCard
              key={t}
              target={t}
              summary={summaries.get(t) ?? { label: '', tone: 'neutral' }}
              progress={getProgress?.(s)}
              selected={shownTarget === t}
              onSelect={() => setOpenTarget(shownTarget === t ? null : t)}
            />
          ))}
        </div>
      )}
      {filtered.length === 0 && (
        <p className="p-3 text-center text-xs text-neutral-600">
          {filter.trim() ? `No targets match "${filter}".` : 'No targets with issues.'}
        </p>
      )}

      {showDetail && shownEntry && (
        <div className="space-y-2">
          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => setOpenTarget(null)}
              className="rounded border border-neutral-800 px-2 py-0.5 text-[11px] text-neutral-500 hover:border-neutral-600 hover:text-neutral-300"
            >
              Close results
            </button>
          </div>
          {renderCard(shownEntry[0], shownEntry[1])}
        </div>
      )}
    </div>
  )
}

// ViewToggleButton is one half of the grid/list switch. Its pressed state
// shows which layout is active.
function ViewToggleButton({ label, active, onClick, children }: { label: string; active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      aria-pressed={active}
      title={label}
      onClick={onClick}
      className={`flex h-7 w-8 items-center justify-center transition-colors ${
        active ? 'bg-neutral-700 text-neutral-100' : 'bg-neutral-950 text-neutral-500 hover:text-neutral-200'
      }`}
    >
      {children}
    </button>
  )
}

// GridIcon and ListIcon are the two layout glyphs for the view toggle.
function GridIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" fill="currentColor">
      <rect x="1" y="1" width="5" height="5" rx="1" />
      <rect x="8" y="1" width="5" height="5" rx="1" />
      <rect x="1" y="8" width="5" height="5" rx="1" />
      <rect x="8" y="8" width="5" height="5" rx="1" />
    </svg>
  )
}

function ListIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" fill="currentColor">
      <rect x="1" y="2" width="12" height="2.5" rx="1" />
      <rect x="1" y="5.75" width="12" height="2.5" rx="1" />
      <rect x="1" y="9.5" width="12" height="2.5" rx="1" />
    </svg>
  )
}

// SummaryStrip is the run-wide line above the grid: how many domains have
// finished, how many checks have completed out of the total registered so
// far, findings so far, and elapsed time while anything is still running.
function SummaryStrip({
  domains,
  finished,
  checks,
  done,
  findings,
  elapsedSeconds,
}: {
  domains: number
  finished: number
  checks: number
  done: number
  findings: number
  elapsedSeconds: number | null
}) {
  const pct = checks > 0 ? Math.round((done / checks) * 100) : 0
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-lg border border-neutral-800 bg-neutral-950/60 px-3 py-2 text-xs text-neutral-400">
      <span>
        <span className="font-mono text-neutral-200">{finished}</span> / {domains} domain{domains === 1 ? '' : 's'} finished
      </span>
      <span>
        <span className="font-mono text-neutral-200">{done}</span> / {checks} checks
      </span>
      <span>
        <span className="font-mono text-neutral-200">{findings}</span> finding{findings === 1 ? '' : 's'}
      </span>
      {elapsedSeconds !== null && <span className="text-neutral-500">{formatDuration(elapsedSeconds)} elapsed</span>}
      <div className="ml-auto h-1.5 w-40 overflow-hidden rounded-full bg-neutral-800">
        <div className="h-full rounded-full bg-emerald-500 transition-[width] duration-500 ease-out" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

// useColumnCount measures the grid's own width and returns how many cards
// fit across it, clamped to [1, MAX_COLUMNS]. A ResizeObserver rather than a
// window resize listener, so it also tracks the panel itself narrowing or
// widening (a sidebar opening, say) and browser zoom, which changes the CSS
// width available without resizing the window.
function useColumnCount(): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement | null>(null)
  const [columns, setColumns] = useState(3)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => {
      const fit = Math.floor((el.clientWidth + GRID_GAP) / (MIN_CARD_WIDTH + GRID_GAP))
      setColumns(Math.min(MAX_COLUMNS, Math.max(1, fit)))
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  return [ref, columns]
}

// useNow returns the current time, re-rendering once a second while active
// -- so an elapsed-time readout keeps moving even when no progress event has
// arrived to force a render on its own. Idle when nothing is running.
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [active])
  return now
}
