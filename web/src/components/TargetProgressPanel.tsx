import type { NodeStatus } from '../types'
import { STATUS_META } from '../statusMeta'
import { formatEta } from '../eta'
import { api } from '../api'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { showToast } from '../toast'

export interface TargetProgress {
  key: string
  target: string
  status: NodeStatus
  done: number
  total: number
  etaSeconds: number | null
}

// TargetProgressPanel is the Content Discovery tab's per-target breakdown: a
// labeled row per host being bruteforced (ffuf + feroxbuster combined), so a
// scan covering several subdomains shows each one's own progress instead of
// a single aggregate bar -- which used to hide which hosts were still queued
// behind maxConcurrentSourceNodes, and went permanently indeterminate the
// moment any one of them included a feroxbuster node. Rendered as a sidebar
// (stacked rows) between the scanner tab list and the results table, rather
// than a wrapping row of chips, so right-clicking a specific target's row is
// unambiguous.
export function TargetProgressPanel({ targets, scanId }: { targets: TargetProgress[]; scanId: string }) {
  if (targets.length === 0) return null
  return (
    <aside className="flex w-64 shrink-0 flex-col overflow-y-auto border-r border-neutral-800 bg-neutral-950">
      <h2 className="border-b border-neutral-800 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">
        Targets ({targets.length})
      </h2>
      <div className="flex flex-col divide-y divide-neutral-900">
        {targets.map((t) => (
          <TargetRow key={t.key} t={t} scanId={scanId} />
        ))}
      </div>
    </aside>
  )
}

function TargetRow({ t, scanId }: { t: TargetProgress; scanId: string }) {
  const { openMenu } = useContextMenu()
  const pct = t.total > 0 ? Math.min(100, Math.round((t.done / t.total) * 100)) : null

  const restart = async () => {
    try {
      const res = await api.restartScanRun(scanId, 'content-discovery', [t.target])
      showToast(res.skipped ? (res.message ?? 'Nothing new to scan') : `Restarted scan for ${t.target}`, res.skipped ? 'info' : 'success')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  return (
    <div
      onContextMenu={(e) => {
        e.stopPropagation()
        openMenu(e, [
          { label: `Restart scan for ${t.target}`, onSelect: restart },
          'separator',
          { label: 'Copy hostname', onSelect: () => copyToClipboard(t.target, 'Copied hostname') },
        ])
      }}
      title={`${t.target} — ${STATUS_META[t.status].label}`}
      className="flex flex-col gap-1 px-3 py-2 text-xs hover:bg-neutral-900/60"
    >
      <div className="flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_META[t.status].dot }} />
        <span className="min-w-0 flex-1 truncate font-mono text-neutral-200">{t.target}</span>
      </div>
      {/* Only 'running' has anything live to show a bar/ETA for -- every
          other state (queued, pending, or a finished run's node this tab
          never got a live status/progress tick for, e.g. right after a
          page reload) would otherwise render a stale or fabricated 0%
          bar, which is exactly the "resets to 0" confusion this avoids. */}
      {t.status === 'running' ? (
        <div className="flex items-center gap-1.5">
          <div className="h-1 flex-1 overflow-hidden rounded-full bg-neutral-800">
            <div
              className={`h-full rounded-full bg-sky-500 ${pct === null ? 'w-1/3 animate-pulse' : ''}`}
              style={pct !== null ? { width: `${pct}%` } : undefined}
            />
          </div>
          <span className="shrink-0 whitespace-nowrap text-neutral-500">{pct !== null ? `${pct}%` : t.done.toLocaleString()}</span>
          {t.etaSeconds !== null && <span className="shrink-0 whitespace-nowrap text-neutral-600">{formatEta(t.etaSeconds)}</span>}
        </div>
      ) : (
        <span className="whitespace-nowrap text-neutral-600">{STATUS_META[t.status].label.toLowerCase()}</span>
      )}
    </div>
  )
}
