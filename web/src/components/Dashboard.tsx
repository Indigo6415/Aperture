import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { ScanOptionsPreset, ScanSummary } from '../types'
import { statusHexColor } from '../statusColor'
import { SummaryCard } from './SummaryCard'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { showToast } from '../toast'

// PRESETS backs the "aggressive"/"stealth" shorthand for per-scan tuning --
// mirrors internal/engine.presetDefaults so the description shown here
// stays honest about what picking a preset actually does. "custom" leaves
// every field to the advanced inputs below instead of a preset default.
const PRESETS: { id: ScanOptionsPreset; label: string; description: string }[] = [
  { id: 'custom', label: 'Default', description: 'Engine defaults (balanced speed).' },
  { id: 'aggressive', label: 'Aggressive', description: 'Many threads, short timeout, no rate limit — fastest, loudest.' },
  { id: 'stealth', label: 'Stealth', description: 'Few threads, longer timeout, rate-limited — slower, quieter.' },
]

// How often the scan list is repolled while at least one scan is running,
// so the overview cards/progress and the "Scanning…" pills stay live
// without a bespoke multi-scan WebSocket just for the dashboard.
const POLL_MS = 3000

type StatusFilter = 'all' | 'running' | 'done'

// Dashboard is the app's home view: a single domain input that kicks off a
// scan immediately, plus a list of recent scans to jump back into. This is
// the "you only have to enter a domain" entry point the rest of the app's
// tools (scanner tabs, wordlists) support rather than gate.
export function Dashboard({ onOpen }: { onOpen: (scanId: string) => void }) {
  const { openMenu } = useContextMenu()
  const [domain, setDomain] = useState('')
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [filterText, setFilterText] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [preset, setPreset] = useState<ScanOptionsPreset>('custom')
  const [showTuning, setShowTuning] = useState(false)
  const [threads, setThreads] = useState('')
  const [timeoutSeconds, setTimeoutSeconds] = useState('')
  const [rateLimit, setRateLimit] = useState('')
  const [wordlist, setWordlist] = useState('')

  // Polls instead of holding one WebSocket open per scan -- the dashboard
  // just needs "is anything still running" to stay fresh, not per-finding
  // granularity (ScanView already covers that once a scan is opened).
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>

    const tick = () => {
      api.listScans().then((next) => {
        if (cancelled) return
        setScans(next)
        timer = setTimeout(tick, next.some((s) => s.running) ? POLL_MS : POLL_MS * 4)
      })
    }
    tick()

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [])

  const summary = useMemo(
    () => ({
      scans: scans.length,
      subdomains: scans.reduce((n, s) => n + s.subdomainCount, 0),
      findings: scans.reduce((n, s) => n + s.findingCount, 0),
      running: scans.filter((s) => s.running).length,
    }),
    [scans],
  )

  const filteredScans = useMemo(() => {
    const needle = filterText.trim().toLowerCase()
    return scans.filter((s) => {
      if (needle && !s.domain.toLowerCase().includes(needle)) return false
      if (statusFilter === 'running' && !s.running) return false
      if (statusFilter === 'done' && s.running) return false
      return true
    })
  }, [scans, filterText, statusFilter])

  const restartScan = async (s: ScanSummary) => {
    try {
      await api.restartScan(s.id)
      showToast(`Restarting scan for ${s.domain}`, 'success')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  const cancelScan = async (s: ScanSummary) => {
    try {
      await api.cancelScan(s.id)
      showToast(`Cancelled scan for ${s.domain}`, 'success')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const target = domain.trim()
    if (!target) return
    setStarting(true)
    setError('')
    try {
      const { scanId } = await api.startScan(target, {
        preset: preset === 'custom' ? undefined : preset,
        threads: threads ? Number(threads) : undefined,
        timeoutSeconds: timeoutSeconds ? Number(timeoutSeconds) : undefined,
        rateLimit: rateLimit ? Number(rateLimit) : undefined,
        wordlist: wordlist.trim() || undefined,
      })
      onOpen(scanId)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  return (
    // overflow-y-auto lives on this full-width outer div rather than the
    // max-w-2xl inner one, so the scrollbar it produces sits at the
    // viewport's right edge instead of at the edge of the centered content
    // column.
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex max-w-2xl flex-col items-center justify-center gap-10 px-6 py-10">
        <div className="w-full text-center">
        <h1 className="mb-2 text-3xl font-semibold text-neutral-100">Aperture</h1>
        <p className="mb-4 text-sm text-neutral-500">
          Enter a domain — DNS, TLS, subdomain + virtual-host bruteforce, and content discovery start immediately.
        </p>
        <form onSubmit={submit} className="flex gap-2">
          <input
            autoFocus
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="flex-1 rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-3 text-lg text-neutral-100 outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={starting || !domain.trim()}
            className="rounded-lg bg-sky-600 px-6 py-3 text-lg font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {starting ? 'Starting…' : 'Scan'}
          </button>
        </form>

        <div className="mt-4 flex flex-col items-center gap-2">
          <div className="flex gap-1.5">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                title={p.description}
                onClick={() => setPreset(p.id)}
                className={`rounded border px-2.5 py-1 text-xs transition-colors ${
                  preset === p.id ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
                }`}
              >
                {p.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setShowTuning((v) => !v)}
              className="rounded border border-neutral-800 px-2.5 py-1 text-xs text-neutral-500 hover:text-neutral-300"
            >
              {showTuning ? 'Hide tuning ▾' : 'Advanced tuning ▸'}
            </button>
          </div>
          {showTuning && (
            <div className="grid w-full grid-cols-2 gap-2 sm:grid-cols-4">
              <label className="flex flex-col gap-0.5 text-left">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Threads</span>
                <input
                  value={threads}
                  onChange={(e) => setThreads(e.target.value)}
                  placeholder={preset === 'stealth' ? '3' : preset === 'aggressive' ? '80' : 'default'}
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
                />
              </label>
              <label className="flex flex-col gap-0.5 text-left">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Timeout (s)</span>
                <input
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(e.target.value)}
                  placeholder={preset === 'stealth' ? '15' : preset === 'aggressive' ? '5' : 'default'}
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
                />
              </label>
              <label className="flex flex-col gap-0.5 text-left">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Rate limit (req/s)</span>
                <input
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                  placeholder={preset === 'stealth' ? '5' : 'unlimited'}
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
                />
              </label>
              <label className="flex flex-col gap-0.5 text-left">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Wordlist file</span>
                <input
                  value={wordlist}
                  onChange={(e) => setWordlist(e.target.value)}
                  placeholder="category default"
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
                />
              </label>
            </div>
          )}
        </div>

        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      </div>

      {scans.length > 0 && (
        <div className="grid w-full grid-cols-2 gap-3 sm:grid-cols-4">
          <SummaryCard label="Scans" value={summary.scans} />
          <SummaryCard label="Subdomains found" value={summary.subdomains} />
          <SummaryCard label="Findings" value={summary.findings} />
          <SummaryCard label="Scanning now" value={summary.running} accent={summary.running > 0} />
        </div>
      )}

      {scans.length > 0 && (
        <div className="w-full">
          <div className="mb-2 flex items-center gap-2 px-1">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">Recent scans</h2>
            <span className="text-xs text-neutral-600">
              ({filteredScans.length} of {scans.length})
            </span>
            <input
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder="Filter by domain…"
              className="ml-auto w-48 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
            />
            <div className="flex overflow-hidden rounded border border-neutral-700 text-xs">
              {(['all', 'running', 'done'] as StatusFilter[]).map((f) => (
                <button
                  key={f}
                  onClick={() => setStatusFilter(f)}
                  className={`px-2 py-1 capitalize ${statusFilter === f ? 'bg-neutral-700 text-neutral-100' : 'text-neutral-500 hover:text-neutral-300'}`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
            {filteredScans.length === 0 && <p className="px-4 py-8 text-center text-sm text-neutral-600">No scans match this filter.</p>}
            {filteredScans.map((s) => (
              <div
                key={s.id}
                onClick={() => onOpen(s.id)}
                onContextMenu={(e) => {
                  e.stopPropagation()
                  openMenu(e, [
                    { label: 'Open scan', onSelect: () => onOpen(s.id) },
                    { label: s.running ? 'Cancel scan' : 'Restart scan', onSelect: () => (s.running ? cancelScan(s) : restartScan(s)), danger: s.running },
                    'separator',
                    { label: 'Copy domain', onSelect: () => copyToClipboard(s.domain, 'Copied domain') },
                  ])
                }}
                className="flex cursor-pointer items-center justify-between gap-4 px-4 py-3 hover:bg-neutral-900"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium text-neutral-100">{s.domain}</p>
                    {s.httpStatus !== undefined && (
                      <span className="font-mono text-xs" style={{ color: statusHexColor(s.httpStatus) }}>
                        {s.httpStatus}
                      </span>
                    )}
                    {s.httpTitle && <span className="truncate text-xs text-neutral-500">{s.httpTitle}</span>}
                    {s.cloudflare && (
                      <span
                        title="Fronted by Cloudflare (detected via response headers)"
                        className="shrink-0 rounded border border-orange-800 bg-orange-950/40 px-1 text-xs text-orange-400"
                      >
                        ☁ CF
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-neutral-500">
                    {s.subdomainCount} subdomain{s.subdomainCount === 1 ? '' : 's'} · {s.findingCount} finding{s.findingCount === 1 ? '' : 's'}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <span className={`rounded-full px-2 py-0.5 text-xs ${s.running ? 'bg-amber-900/40 text-amber-400' : 'bg-emerald-900/40 text-emerald-400'}`}>
                    {s.running ? 'Scanning…' : 'Done'}
                  </span>
                  <p className="text-xs text-neutral-500">{new Date(s.createdAt).toLocaleString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      </div>
    </div>
  )
}
