import type { NodeStatus } from '../types'
import { STATUS_META } from '../statusMeta'
import { formatEta } from '../eta'

export interface TargetProgress {
  key: string
  target: string
  status: NodeStatus
  done: number
  total: number
  etaSeconds: number | null
}

// TargetProgressPanel is the Content Discovery tab's per-target breakdown:
// one compact chip per host being bruteforced (ffuf + feroxbuster
// combined), so a scan covering several subdomains shows each one's own
// progress instead of a single aggregate bar -- which used to hide which
// hosts were still queued behind maxConcurrentSourceNodes, and went
// permanently indeterminate the moment any one of them included a
// feroxbuster node. Wraps within its own height instead of scrolling --
// with a handful of targets that's one short row, not a boxed-in list.
export function TargetProgressPanel({ targets }: { targets: TargetProgress[] }) {
  if (targets.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1.5 border-b border-neutral-800 px-3 py-1.5">
      {targets.map((t) => (
        <TargetChip key={t.key} t={t} />
      ))}
    </div>
  )
}

function TargetChip({ t }: { t: TargetProgress }) {
  const pct = t.total > 0 ? Math.min(100, Math.round((t.done / t.total) * 100)) : null
  return (
    <div
      className="flex items-center gap-1.5 rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-xs"
      title={`${t.target} — ${STATUS_META[t.status].label}`}
    >
      <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_META[t.status].dot }} />
      <span className="max-w-[140px] truncate font-mono text-neutral-300">{t.target}</span>
      {/* Only 'running' has anything live to show a bar/ETA for -- every
          other state (queued, pending, or a finished run's node this tab
          never got a live status/progress tick for, e.g. right after a
          page reload) would otherwise render a stale or fabricated 0%
          bar, which is exactly the "resets to 0" confusion this avoids. */}
      {t.status === 'running' ? (
        <>
          <div className="h-1 w-12 shrink-0 overflow-hidden rounded-full bg-neutral-800">
            <div
              className={`h-full rounded-full bg-sky-500 ${pct === null ? 'w-1/3 animate-pulse' : ''}`}
              style={pct !== null ? { width: `${pct}%` } : undefined}
            />
          </div>
          <span className="whitespace-nowrap text-neutral-500">{pct !== null ? `${pct}%` : t.done.toLocaleString()}</span>
          {t.etaSeconds !== null && <span className="whitespace-nowrap text-neutral-600">{formatEta(t.etaSeconds)}</span>}
        </>
      ) : (
        <span className="whitespace-nowrap text-neutral-600">{STATUS_META[t.status].label.toLowerCase()}</span>
      )}
    </div>
  )
}
