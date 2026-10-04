import type { BatchResultSummary, ResultTone } from './BatchResultsPanel'
import type { CheckState, ScanCheck, ScanProgress } from '../scanProgress'

// TONE_STYLES colors a target's status pill. Matches the pills
// BatchResultsPanel has always used, so a card's badge reads the same as
// the one-line rows it replaces.
const TONE_STYLES: Record<ResultTone, string> = {
  danger: 'border-red-700 bg-red-950/60 text-red-300',
  warn: 'border-amber-700 bg-amber-950/60 text-amber-300',
  clean: 'border-emerald-700 bg-emerald-950/60 text-emerald-300',
  neutral: 'border-neutral-700 bg-neutral-900 text-neutral-500',
}

// TONE_BORDERS tints a card's own border by its outcome, so a grid of
// finished scans reads at a glance without opening any of them.
const TONE_BORDERS: Record<ResultTone, string> = {
  danger: 'border-red-900',
  warn: 'border-amber-900',
  clean: 'border-neutral-800',
  neutral: 'border-neutral-800',
}

// MAX_SQUARES is the most squares a card ever draws. A scan with more checks
// than this packs consecutive checks into each square (see bundleChecks), so a
// card stays the same footprint whether a scan registers 10 checks or 500.
const MAX_SQUARES = 36

// SQUARE_STATE maps each check's state onto the app's existing status colors
// -- the same amber-while-running / emerald-when-done pair Probe's test pills
// use -- with the queued grey coming from the themed neutral tokens so it
// follows whichever palette is active. The `check-*` classes are the
// animations defined in index.css (they switch off under reduced motion).
const SQUARE_STATE: Record<CheckState, string> = {
  idle: 'bg-neutral-800 ring-1 ring-inset ring-neutral-600',
  running: 'bg-amber-400 check-running',
  done: 'bg-emerald-500 check-pop',
}

const STATE_LABEL: Record<CheckState, string> = {
  idle: 'queued',
  running: 'testing',
  done: 'finished',
}

// Bundle is one square's worth of checks: a single check, or a run of
// consecutive checks once a scan outgrows MAX_SQUARES. `start` is the 0-based
// position of its first check in the whole scan, for hover text.
interface Bundle {
  checks: ScanCheck[]
  start: number
}

// ScanTargetCard is one target's live view: its domain, running tallies, and
// a square for every check it has registered (bundled into at most
// MAX_SQUARES squares). The same content appears in every view; `layout` only
// changes how it's arranged: 'grid' stacks it into a card, 'list' lays it out
// as one wide row, and 'split' is a compact row for the split view's list
// column -- name, badge, tallies and progress, without the squares, so it fits
// a narrow column. Clicking it opens the target's full results (handled by
// BatchResultsPanel).
export function ScanTargetCard({
  target,
  summary,
  progress,
  selected,
  onSelect,
  onRetry,
  onStop,
  layout = 'grid',
}: {
  target: string
  summary: BatchResultSummary
  progress?: ScanProgress
  selected: boolean
  onSelect: () => void
  // onRetry restarts this target's scan. Shown as a Retry button only when the
  // target failed (summary.failed) -- a failure can be just load, so it's worth
  // a second go without restarting the whole batch.
  onRetry?: () => void
  // onStop stops this target's running scan. Shown as a Stop button only while
  // the scan is in flight, so a finished card never offers to stop nothing.
  onStop?: () => void
  layout?: 'grid' | 'list' | 'split'
}) {
  const checks = progress?.checks ?? []
  const total = checks.length
  const done = checks.filter((c) => c.state === 'done').length
  const findings = progress?.findings ?? 0
  const running = Boolean(summary.running)
  const pct = total > 0 ? Math.round((done / total) * 100) : null

  // While running, the ticker shows what the scan says it's doing right now;
  // once a check finishes it shows that check's name, so the line keeps
  // moving even through a phase that hasn't changed.
  const ticker = running ? progress?.phase ?? (progress?.lastDone ? `Last: ${progress.lastDone}` : undefined) : undefined

  // tickerLine is the ticker as text. Its key is the text itself, so each new
  // line fades in rather than snapping.
  const tickerLine = ticker ? (
    <p key={ticker} className="check-ticker truncate text-[11px] text-neutral-500">
      {ticker}
    </p>
  ) : null

  // badge is the target's status pill, shared by both layouts.
  const badge = (
    <span className={`w-fit shrink-0 rounded border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide ${TONE_STYLES[summary.tone]}`}>
      {summary.label}
    </span>
  )

  // retryButton restarts a failed target's scan. It stops propagation so the
  // click (and the Enter/Space key that clicks it) doesn't also select the card.
  const retryButton =
    summary.failed && onRetry ? (
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation()
          onRetry()
        }}
        onKeyDown={(e) => e.stopPropagation()}
        className="shrink-0 rounded border border-red-800 px-2 py-px text-[10px] font-semibold uppercase tracking-wide text-red-300 transition-colors hover:border-red-600 hover:text-red-100"
      >
        Retry
      </button>
    ) : null

  // stopButton stops a running scan. It stops propagation for the same reason
  // as retryButton: the click shouldn't also select the card.
  const stopButton =
    running && onStop ? (
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation()
          onStop()
        }}
        onKeyDown={(e) => e.stopPropagation()}
        className="shrink-0 rounded border border-red-900 px-2 py-px text-[10px] font-semibold uppercase tracking-wide text-red-400 transition-colors hover:border-red-500 hover:text-red-300"
      >
        Stop
      </button>
    ) : null

  // gridInfo is the text side of a grid card: one line per fact, stacked.
  const gridInfo = (
    <div className="flex min-w-0 flex-1 flex-col gap-1.5">
      <div className="flex min-w-0 items-center gap-2">
        {running && <LiveDot />}
        <span className="min-w-0 truncate font-mono text-sm text-neutral-100" title={target}>
          {target}
        </span>
      </div>
      <div className="flex min-w-0 items-center gap-2">
        {badge}
        {retryButton}
        {stopButton}
      </div>
      {total > 0 && (
        <p className="text-xs text-neutral-400">
          <span className="font-mono text-neutral-200">{done}</span> / {total} checks completed
        </p>
      )}
      {total > 0 && findings > 0 && (
        <p className="text-xs text-neutral-400">
          <span className="font-mono text-neutral-200">{findings}</span> finding{findings === 1 ? '' : 's'}
        </p>
      )}
      {tickerLine}
    </div>
  )

  // listInfo is the text side of a list row, squeezed to two lines: the domain
  // with its badge, then the tallies. The ticker sits beside the squares instead.
  const listInfo = (
    <div className="flex w-72 shrink-0 flex-col gap-0.5">
      <div className="flex min-w-0 items-center gap-2">
        {running && <LiveDot />}
        <span className="min-w-0 truncate font-mono text-sm text-neutral-100" title={target}>
          {target}
        </span>
        {badge}
        {retryButton}
        {stopButton}
      </div>
      {total > 0 && (
        <p className="truncate text-xs text-neutral-400">
          <span className="font-mono text-neutral-200">{done}</span> / {total} checks completed
          {findings > 0 && (
            <>
              {' · '}
              <span className="font-mono text-neutral-200">{findings}</span> finding{findings === 1 ? '' : 's'}
            </>
          )}
        </p>
      )}
    </div>
  )

  // visual is the square side: one square per bundle of checks, in a grid for
  // the grid view and a single line for the list view.
  const visual = total > 0 ? (layout === 'list' ? <CheckRow checks={checks} /> : <CheckMatrix checks={checks} />) : null

  // splitBody is the split layout's text-only card. Name and badge sit on their
  // own lines so a long domain can truncate without pushing the badge off.
  const splitBody = (
    <>
      <div className="flex min-w-0 items-center gap-2">
        {running && <LiveDot />}
        <span className="min-w-0 truncate font-mono text-xs text-neutral-100" title={target}>
          {target}
        </span>
      </div>
      <div className="flex min-w-0 items-center gap-2">
        {badge}
        {retryButton}
        {stopButton}
        {total > 0 && (
          <span className="truncate text-[11px] text-neutral-400">
            <span className="font-mono text-neutral-200">{done}</span> / {total}
            {findings > 0 && (
              <>
                {' · '}
                <span className="font-mono text-neutral-200">{findings}</span> finding{findings === 1 ? '' : 's'}
              </>
            )}
          </span>
        )}
      </div>
      {pct !== null && <ProgressBar pct={pct} running={running} />}
    </>
  )

  return (
    <div
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onSelect()
        }
      }}
      className={`cursor-pointer rounded-lg border bg-neutral-900 transition-colors hover:border-neutral-600 focus:outline-none focus-visible:border-sky-500 ${
        selected ? 'border-sky-500 ring-1 ring-sky-500/40' : running ? 'border-amber-800' : TONE_BORDERS[summary.tone]
      } ${
        layout === 'split' ? 'flex flex-col gap-1.5 px-2.5 py-2' : layout === 'list' ? 'flex items-center gap-4 px-3 py-2' : 'flex flex-col gap-3 p-3'
      }`}
    >
      {layout === 'split' ? (
        splitBody
      ) : layout === 'list' ? (
        <>
          {listInfo}
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            {(visual || tickerLine) && (
              <div className="flex min-w-0 items-center gap-3">
                {visual}
                {tickerLine && <div className="min-w-0 flex-1">{tickerLine}</div>}
              </div>
            )}
            {pct !== null && <ProgressBar pct={pct} running={running} />}
          </div>
        </>
      ) : (
        <>
          <div className="flex min-w-0 gap-3">
            {gridInfo}
            {visual && <div className="shrink-0">{visual}</div>}
          </div>
          {pct !== null && <ProgressBar pct={pct} running={running} />}
        </>
      )}
    </div>
  )
}

// bundleChecks turns a scan's checks into the squares to draw. Up to
// MAX_SQUARES checks each get their own square; past that, consecutive checks
// are packed together, with the bundle size recomputed as the scan grows, so
// there are never more than MAX_SQUARES squares.
function bundleChecks(checks: ScanCheck[]): Bundle[] {
  const size = Math.max(1, Math.ceil(checks.length / MAX_SQUARES))
  const bundles: Bundle[] = []
  // Cut the checks, in registration order, into runs of `size`.
  for (let i = 0; i < checks.length; i += size) {
    bundles.push({ checks: checks.slice(i, i + size), start: i })
  }
  return bundles
}

// bundleState is the state a square shows for its checks: running while any
// of them is in flight, done once all of them have finished, otherwise queued.
function bundleState(checks: ScanCheck[]): CheckState {
  if (checks.some((c) => c.state === 'running')) return 'running'
  if (checks.every((c) => c.state === 'done')) return 'done'
  return 'idle'
}

// CheckMatrix lays out one square per bundle in a near-square grid -- columns
// are ceil(sqrt(n)), so 9 squares is 3x3 and 36 is 6 wide. Each square's key
// includes its state, so a change of state remounts it and replays its
// animation (a pop when it finishes, a pulse while it runs).
export function CheckMatrix({ checks }: { checks: ScanCheck[] }) {
  const bundles = bundleChecks(checks)
  const cols = Math.max(1, Math.ceil(Math.sqrt(bundles.length)))
  return (
    <div className="grid content-start gap-[3px]" style={{ gridTemplateColumns: `repeat(${cols}, 0.625rem)` }}>
      {bundles.map((b) => (
        <CheckSquare key={`${b.start}:${bundleState(b.checks)}`} bundle={b} />
      ))}
    </div>
  )
}

// CheckRow is the list view's squares: one line, left to right, in check order.
// It only wraps when a scan has more squares than the row has width for, so a
// row stays one line tall however many checks the scan registers.
export function CheckRow({ checks }: { checks: ScanCheck[] }) {
  const bundles = bundleChecks(checks)
  return (
    <div className="flex flex-wrap items-center gap-[3px]">
      {bundles.map((b) => (
        <CheckSquare key={`${b.start}:${bundleState(b.checks)}`} bundle={b} />
      ))}
    </div>
  )
}

// CheckSquare is one square. A single check is coloured by its own state. A
// bundle is coloured by bundleState, and while it is still queued it fills
// from the bottom as its checks finish, so partial progress stays visible.
function CheckSquare({ bundle }: { bundle: Bundle }) {
  const { checks } = bundle
  const state = bundleState(checks)
  const errored = checks.some((c) => c.error)

  // A bundle with some checks finished but none in flight is still "queued"
  // overall, so it gets a fill instead of the plain grey.
  const doneCount = checks.filter((c) => c.state === 'done').length
  const fillPct = (doneCount / checks.length) * 100
  const partial = checks.length > 1 && state === 'idle' && doneCount > 0

  const title = checks.length === 1 ? squareTitle(checks[0]) : bundleTitle(bundle)
  const ring = errored ? 'ring-2 ring-red-500' : ''

  if (partial) {
    return (
      <span title={title} className={`relative h-2.5 w-2.5 overflow-hidden rounded-[2px] bg-neutral-800 ring-1 ring-inset ring-neutral-600 ${ring}`}>
        <span className="absolute inset-x-0 bottom-0 bg-emerald-500 transition-[height] duration-500 ease-out" style={{ height: `${fillPct}%` }} />
      </span>
    )
  }

  return <span title={title} className={`h-2.5 w-2.5 rounded-[2px] ${SQUARE_STATE[state]} ${ring}`} />
}

// squareTitle is a single check's hover text: its group and label, where it is
// in the run, and what it turned up (or the error it hit).
function squareTitle(c: ScanCheck): string {
  const head = c.group ? `${c.group} · ${c.label}` : c.label
  const parts = [`${head} — ${STATE_LABEL[c.state]}`]
  if (c.state === 'done' && c.findings > 0) parts.push(`${c.findings} finding${c.findings === 1 ? '' : 's'}`)
  if (c.error) parts.push(`error: ${c.error}`)
  return parts.join(' · ')
}

// bundleTitle is a bundled square's hover text: which checks it stands for,
// the groups they come from, how far through they are, and anything they turned
// up or any error they hit.
function bundleTitle(b: Bundle): string {
  const { checks, start } = b
  const first = start + 1
  const last = start + checks.length
  const groups = [...new Set(checks.map((c) => c.group).filter(Boolean))]
  const done = checks.filter((c) => c.state === 'done').length
  const running = checks.filter((c) => c.state === 'running').length
  const findings = checks.reduce((n, c) => n + c.findings, 0)
  const error = checks.find((c) => c.error)

  const parts = [`Checks ${first}–${last}${groups.length ? ` (${groups.join(', ')})` : ''}`]
  parts.push(`${done} of ${checks.length} finished`)
  if (running > 0) parts.push(`${running} testing`)
  if (findings > 0) parts.push(`${findings} finding${findings === 1 ? '' : 's'}`)
  if (error) parts.push(`error: ${error.error}`)
  return parts.join(' · ')
}

// LiveDot is the pulsing marker on a card whose scan is still in flight.
function LiveDot() {
  return (
    <span className="relative flex h-2 w-2 shrink-0">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
      <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400" />
    </span>
  )
}

// ProgressBar fills to the share of checks finished, in the same emerald as
// a finished square.
export function ProgressBar({ pct, running }: { pct: number; running: boolean }) {
  return (
    <div className="h-1 overflow-hidden rounded-full bg-neutral-800" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
      <div
        className={`h-full rounded-full transition-[width] duration-500 ease-out ${running ? 'bg-amber-400' : 'bg-emerald-500'}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}
