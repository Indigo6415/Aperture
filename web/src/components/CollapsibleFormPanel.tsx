import type { ReactNode } from 'react'

// CollapsibleFormPanel is the shared shape JwtScan and Probe both use for
// their input form: a full form while there's nothing to look at yet, that
// collapses down to a one-line summary bar (plus a re-run button) once a
// result exists, so the results below get the width instead of a
// permanently fixed-width form column eating it forever. Reuses the app's
// existing "▸ / ▾ Label" disclosure convention (see JwtScan's "Advanced
// tuning ▸" toggle) rather than an icon font.
export function CollapsibleFormPanel({
  title,
  open,
  onToggle,
  summary,
  onRun,
  canRun,
  loading,
  runLabel = 'Run',
  children,
}: {
  title: string
  open: boolean
  onToggle: () => void
  summary: ReactNode
  onRun: () => void
  canRun: boolean
  loading: boolean
  runLabel?: string
  children: ReactNode
}) {
  if (!open) {
    return (
      <div className="flex shrink-0 items-center gap-3 rounded-lg border border-neutral-800 bg-neutral-900/60 px-3 py-2">
        <button onClick={onToggle} className="shrink-0 text-xs text-sky-400 hover:text-sky-300">
          ▸ {title}
        </button>
        <div className="min-w-0 flex-1 truncate text-xs text-neutral-500">{summary}</div>
        <button
          onClick={onRun}
          disabled={!canRun}
          className="shrink-0 rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? 'Running…' : runLabel}
        </button>
      </div>
    )
  }

  return (
    <div className="shrink-0 rounded-lg border border-neutral-800 bg-neutral-900/40 p-4">
      {/* Kept top-left, same spot as the collapsed "▸ Title" toggle, so the
          button never jumps sides between the two states and stays where
          the user's eye (and mouse) already is to close it back up. */}
      <button onClick={onToggle} className="mb-3 block text-xs text-neutral-500 hover:text-neutral-300">
        ▾ Collapse
      </button>
      {/* Capped so text inputs don't stretch edge-to-edge once the panel
          spans the full results width instead of a fixed 26rem column. */}
      <div className="max-w-2xl space-y-4">{children}</div>
    </div>
  )
}
