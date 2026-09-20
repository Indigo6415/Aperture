import type { NodeStatus } from '../types'
import { STATUS_META } from '../statusMeta'
import { formatEta } from '../eta'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToJwtScanner } from '../jwtHandoff'
import { sendToProbe } from '../probeHandoff'
import { sendToSecretScan } from '../secretScanHandoff'
import { sendToRepeater } from '../repeaterHandoff'
import { useAutoExpandOnce, useCollapsible } from '../collapsible'

export interface TargetProgress {
  key: string
  target: string
  status: NodeStatus
  done: number
  total: number
  etaSeconds: number | null
  // Scan config for this target's node, when known (see
  // internal/api.JobNodeDetail) -- undefined for a node the job response
  // didn't carry details for (e.g. identify jobs have no flow at all).
  wordlist?: string
  extensions?: string[]
  candidates?: number
  threads?: number
  timeoutSeconds?: number
  rateLimit?: number
}

// TargetProgressPanel is a job's per-target breakdown: a labeled row per
// target being scanned, so a job covering several targets shows each one's
// own progress instead of a single aggregate bar -- which would hide which
// targets were still queued behind maxConcurrentSourceNodes, and go
// permanently indeterminate the moment any one of them included a
// feroxbuster node. Rendered as a sidebar (stacked rows) between the tool
// tab's launcher and its results table.
//
// Collapses to a slim icon rail (just the status dots, no labels) so an
// idle or finished job's breakdown doesn't permanently take a quarter of
// the results table's width -- expands on click, and auto-expands itself
// once the first time any target starts running (so a user who left it
// collapsed doesn't miss that a job just started). Persisted per-tab via
// useCollapsible so a user's preference sticks.
export function TargetProgressPanel({ targets, tabKey }: { targets: TargetProgress[]; tabKey: string }) {
  const [open, setOpen] = useCollapsible(`targetProgress.${tabKey}`, true)
  useAutoExpandOnce(targets.some((t) => t.status === 'running'), setOpen)

  if (targets.length === 0) return null

  if (!open) {
    return (
      <aside className="flex w-8 shrink-0 flex-col items-center gap-1.5 overflow-y-auto border-r border-neutral-800 bg-neutral-950 py-2">
        <button onClick={() => setOpen(true)} title={`Show ${targets.length} target${targets.length === 1 ? '' : 's'}`} className="text-neutral-600 hover:text-neutral-300">
          ▸
        </button>
        {targets.map((t) => (
          <span key={t.key} title={tooltipFor(t)} className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_META[t.status].dot }} />
        ))}
      </aside>
    )
  }

  return (
    <aside className="flex w-64 shrink-0 flex-col overflow-y-auto border-r border-neutral-800 bg-neutral-950">
      <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
        <h2 className="flex-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Targets ({targets.length})</h2>
        <button onClick={() => setOpen(false)} title="Collapse" className="shrink-0 text-neutral-600 hover:text-neutral-300">
          ▾
        </button>
      </div>
      <div className="flex flex-col divide-y divide-neutral-900">
        {targets.map((t) => (
          <TargetRow key={t.key} t={t} />
        ))}
      </div>
    </aside>
  )
}

// tooltipFor builds the row's hover title -- the target/status plus every
// scan-config detail known for it, so the full picture is available without
// needing space in the row itself.
function tooltipFor(t: TargetProgress): string {
  const lines = [`${t.target} — ${STATUS_META[t.status].label}`]
  if (t.wordlist) lines.push(`Wordlist: ${t.wordlist}`)
  const candidates = t.candidates ?? (t.total > 0 ? t.total : null)
  if (candidates !== null) lines.push(`Candidates: ${candidates.toLocaleString()}`)
  if (t.status === 'running') lines.push(`Progress: ${t.done.toLocaleString()} / ${t.total > 0 ? t.total.toLocaleString() : '?'}`)
  if (t.extensions?.length) lines.push(`Extensions: ${t.extensions.join(', ')}`)
  if (t.threads) lines.push(`Threads: ${t.threads}`)
  if (t.rateLimit) lines.push(`Rate limit: ${t.rateLimit}/s`)
  if (t.timeoutSeconds) lines.push(`Timeout: ${t.timeoutSeconds}s`)
  return lines.join('\n')
}

function TargetRow({ t }: { t: TargetProgress }) {
  const { openMenu } = useContextMenu()
  const pct = t.total > 0 ? Math.min(100, Math.round((t.done / t.total) * 100)) : null
  // The live total (from ffuf/feroxbuster's own progress ticks) is more
  // accurate once it arrives, so it takes priority over the wordlist-derived
  // estimate carried on the job -- but the estimate is what's shown before
  // the first tick lands (e.g. a still-queued or just-started node).
  const candidates = t.total > 0 ? t.total : t.candidates

  return (
    <div
      onContextMenu={(e) => {
        e.stopPropagation()
        openMenu(e, [
          { label: 'Copy target', onSelect: () => copyToClipboard(t.target, 'Copied target') },
          { label: 'Send to JWT Scanner', onSelect: () => sendToJwtScanner(t.target) },
          { label: 'Send to Probe', onSelect: () => sendToProbe(t.target) },
          { label: 'Send to Secret Scanner', onSelect: () => sendToSecretScan(t.target) },
          { label: 'Send to Repeater', onSelect: () => sendToRepeater(t.target) },
        ])
      }}
      title={tooltipFor(t)}
      className="flex flex-col gap-1 px-3 py-2 text-xs hover:bg-neutral-900/60"
    >
      <div className="flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_META[t.status].dot }} />
        <span className="min-w-0 flex-1 truncate font-mono text-neutral-200">{t.target}</span>
      </div>
      {(t.wordlist || candidates !== undefined) && (
        <div className="flex items-center gap-1 truncate text-neutral-500">
          {t.wordlist && <span className="truncate font-mono">{t.wordlist}</span>}
          {candidates !== undefined && (
            <span className="shrink-0 whitespace-nowrap">
              {t.wordlist && '· '}
              {candidates.toLocaleString()} candidates
            </span>
          )}
        </div>
      )}
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
          <span className="shrink-0 whitespace-nowrap text-neutral-500">
            {pct !== null ? `${pct}% (${t.done.toLocaleString()}/${t.total.toLocaleString()})` : t.done.toLocaleString()}
          </span>
          {t.etaSeconds !== null && <span className="shrink-0 whitespace-nowrap text-neutral-600">{formatEta(t.etaSeconds)}</span>}
        </div>
      ) : (
        <span className="whitespace-nowrap text-neutral-600">{STATUS_META[t.status].label.toLowerCase()}</span>
      )}
    </div>
  )
}
