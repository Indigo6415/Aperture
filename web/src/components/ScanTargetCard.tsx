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

// STREET_THRESHOLD is how many checks a target can have before its squares
// give way to streets. Up to this many, every check is its own square; past
// it, checks are grouped by the category they belong to (see StreetList),
// which keeps a card short even when a wide scan registers hundreds of checks.
export const STREET_THRESHOLD = 36

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

// ScanTargetCard is one target's live view: its domain, running tallies, and
// a visual of every check it has registered -- squares up to STREET_THRESHOLD,
// streets past it. The same content appears in both views; `layout` only
// changes how it's arranged: 'grid' stacks it into a card, 'list' lays it out
// as one wide row. Clicking it opens the target's full results below
// (handled by BatchResultsPanel).
export function ScanTargetCard({
  target,
  summary,
  progress,
  selected,
  onSelect,
  layout = 'grid',
}: {
  target: string
  summary: BatchResultSummary
  progress?: ScanProgress
  selected: boolean
  onSelect: () => void
  layout?: 'grid' | 'list'
}) {
  const checks = progress?.checks ?? []
  const total = checks.length
  const done = checks.filter((c) => c.state === 'done').length
  const running = Boolean(summary.running)
  const pct = total > 0 ? Math.round((done / total) * 100) : null

  // While running, the ticker shows what the scan says it's doing right now;
  // once a check finishes it shows that check's name, so the line keeps
  // moving even through a phase that hasn't changed.
  const ticker = running ? progress?.phase ?? (progress?.lastDone ? `Last: ${progress.lastDone}` : undefined) : undefined

  // info is the text side: identical in both layouts, only its width differs.
  const info = (
    <div className={`flex min-w-0 flex-col gap-1.5 ${layout === 'list' ? 'w-64 shrink-0' : 'flex-1'}`}>
      <div className="flex min-w-0 items-center gap-2">
        {running && <LiveDot />}
        <span className="min-w-0 truncate font-mono text-sm text-neutral-100" title={target}>
          {target}
        </span>
      </div>
      <span className={`w-fit rounded border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide ${TONE_STYLES[summary.tone]}`}>
        {summary.label}
      </span>
      {total > 0 && (
        <p className="text-xs text-neutral-400">
          <span className="font-mono text-neutral-200">{done}</span> / {total} checks completed
        </p>
      )}
      {total > 0 && progress && progress.findings > 0 && (
        <p className="text-xs text-neutral-400">
          <span className="font-mono text-neutral-200">{progress.findings}</span> finding{progress.findings === 1 ? '' : 's'}
        </p>
      )}
      {ticker && (
        // key on the text so each new line fades in rather than snapping.
        <p key={ticker} className="check-ticker truncate text-[11px] text-neutral-500">
          {ticker}
        </p>
      )}
    </div>
  )

  // visual is the check side: squares for a small scan, streets for a large
  // one. A card's grid layout puts streets full-width underneath its text, since
  // their bars need the room; squares sit beside the text as before.
  const streets = total > STREET_THRESHOLD
  const visual =
    total > 0 ? (
      streets ? (
        <StreetList checks={checks} />
      ) : (
        <CheckMatrix checks={checks} />
      )
    ) : null

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
      className={`cursor-pointer rounded-lg border bg-neutral-900 p-3 transition-colors hover:border-neutral-600 focus:outline-none focus-visible:border-sky-500 ${
        selected ? 'border-sky-500 ring-1 ring-sky-500/40' : running ? 'border-amber-800' : TONE_BORDERS[summary.tone]
      } ${layout === 'list' ? 'flex items-center gap-4' : 'flex flex-col gap-3'}`}
    >
      {layout === 'list' ? (
        <>
          {info}
          <div className="flex min-w-0 flex-1 flex-col gap-2">
            {visual}
            {pct !== null && <ProgressBar pct={pct} running={running} />}
          </div>
        </>
      ) : (
        <>
          <div className={`flex min-w-0 gap-3 ${streets ? 'flex-col' : ''}`}>
            {info}
            {visual && !streets && <div className="shrink-0">{visual}</div>}
          </div>
          {visual && streets && visual}
          {pct !== null && <ProgressBar pct={pct} running={running} />}
        </>
      )}
    </div>
  )
}

// CheckMatrix lays out one square per check in a near-square grid -- columns
// are ceil(sqrt(n)), so 9 checks is 3x3 and 36 is 6 wide. Each square's key
// includes its state, so a change of state remounts it and replays its
// animation (a pop when it finishes, a pulse while it runs).
export function CheckMatrix({ checks }: { checks: ScanCheck[] }) {
  const cols = Math.max(1, Math.ceil(Math.sqrt(checks.length)))
  return (
    <div className="grid content-start gap-[3px]" style={{ gridTemplateColumns: `repeat(${cols}, 0.625rem)` }}>
      {checks.map((c) => (
        <span
          key={`${c.id}:${c.state}`}
          title={squareTitle(c)}
          className={`h-2.5 w-2.5 rounded-[2px] ${SQUARE_STATE[c.state]} ${c.error ? 'ring-2 ring-red-500' : ''}`}
        />
      ))}
    </div>
  )
}

// StreetList is the grouped view for a scan with more checks than fit as
// squares: one row per street (group of checks from the same category), each
// a bar filled by how many of its checks have finished, with an amber segment
// for the ones currently in flight. The row's count and hover text give the
// exact figures, so nothing is lost by not drawing every check.
export function StreetList({ checks }: { checks: ScanCheck[] }) {
  const streets = groupStreets(checks)
  return (
    <div className="flex flex-col gap-1.5">
      {streets.map((st) => {
        const total = st.checks.length
        const done = st.checks.filter((c) => c.state === 'done').length
        const running = st.checks.filter((c) => c.state === 'running').length
        const donePct = (done / total) * 100
        const runPct = (running / total) * 100
        const findings = st.checks.reduce((n, c) => n + c.findings, 0)
        return (
          <div key={st.name} className="flex min-w-0 items-center gap-2" title={`${st.name} — ${done} of ${total} finished${findings ? `, ${findings} finding${findings === 1 ? '' : 's'}` : ''}`}>
            <span className="w-40 shrink-0 truncate text-[11px] text-neutral-400">{st.name}</span>
            <div className="relative h-2.5 min-w-0 flex-1 overflow-hidden rounded-[2px] bg-neutral-800 ring-1 ring-inset ring-neutral-700">
              <div className="absolute inset-y-0 left-0 bg-emerald-500 transition-[width] duration-500 ease-out" style={{ width: `${donePct}%` }} />
              {running > 0 && (
                <div
                  className="check-running absolute inset-y-0 bg-amber-400 transition-[left,width] duration-500 ease-out"
                  style={{ left: `${donePct}%`, width: `${runPct}%` }}
                />
              )}
            </div>
            <span className="w-14 shrink-0 text-right font-mono text-[11px] text-neutral-500">
              {done}/{total}
            </span>
          </div>
        )
      })}
    </div>
  )
}

// groupStreets buckets checks by their group, in the order each group first
// appears. A check with no group falls into a catch-all street named "Checks".
function groupStreets(checks: ScanCheck[]): { name: string; checks: ScanCheck[] }[] {
  const byName = new Map<string, ScanCheck[]>()
  for (const c of checks) {
    const name = c.group || 'Checks'
    const bucket = byName.get(name)
    if (bucket) bucket.push(c)
    else byName.set(name, [c])
  }
  return [...byName.entries()].map(([name, list]) => ({ name, checks: list }))
}

// squareTitle is a square's hover text: its group and label, where it is in
// the run, and what it turned up (or the error it hit).
function squareTitle(c: ScanCheck): string {
  const head = c.group ? `${c.group} · ${c.label}` : c.label
  const parts = [`${head} — ${STATE_LABEL[c.state]}`]
  if (c.state === 'done' && c.findings > 0) parts.push(`${c.findings} finding${c.findings === 1 ? '' : 's'}`)
  if (c.error) parts.push(`error: ${c.error}`)
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
