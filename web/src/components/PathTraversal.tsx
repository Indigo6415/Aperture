import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CallbackSelection, Credential, PathTraversalResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { CallbackPicker } from './CallbackPicker'
import { BatchResultsPanel, stoppedSummary, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { emptyProgress, runTrackedScan, type TrackedScan, runBatch, stopTrackedScan, useScanBatch, stopAllScans } from '../scanProgress'
import { indicatorOfScans, useReportScanIndicator } from '../scanIndicator'
import { SeverityTiles, ModuleResultsList, totalFindingsOf, hasSevereFindings } from './ScanModuleResults'
import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'
import { ParamMiningToggle } from './ParamMiningToggle'

type TargetScanState = TrackedScan<PathTraversalResponse>

// PathTraversal is Aperture's path traversal scanner (see internal/pathtraversal).
// It crawls a site same-origin from a seed page and collects every place the
// client can supply a file or path -- query parameters, form fields, path
// segments, a request body, path-like headers, and cookies -- then tries
// traversal payloads at each one (plain, Windows, encoded, absolute, PHP
// wrapper, nginx alias). A finding is reported only when a known file's
// contents appear in the response. Runs against every seed page selected or
// typed, same batch pattern as SstiScan.
export function PathTraversal({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [extraParams, setExtraParams] = useState('')
  const [method, setMethod] = useState<'GET' | 'POST'>('GET')
  const [body, setBody] = useState('')
  const [contentType, setContentType] = useState('')
  const [cookie, setCookie] = useState('')
  const [recursionDepth, setRecursionDepth] = useState(1)
  const [maxPages, setMaxPages] = useState(25)
  const [callback, setCallback] = useState<CallbackSelection | null>(null)

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('pathtraversal.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<PathTraversalResponse>(caseId, 'pathtraversal').then((list) => {
      if (cancelled) return
      const restored = latestByTarget(list)
      if (restored.length === 0) return
      setScans((prev) => {
        const next = { ...prev }
        for (const r of restored) if (!next[r.scan.target]) next[r.scan.target] = { status: 'done', result: r.data, scanId: r.scan.id }
        return next
      })
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])
  const params = useMemo(() => extraParams.split(',').map((s) => s.trim()).filter(Boolean), [extraParams])
  const [mineParams, setMineParams] = useState(false)

  const running = Object.values(scans).some((s) => s.status === 'running')
  // Publishes this tab's scan state to the case nav's border.
  useReportScanIndicator('pathtraversal', indicatorOfScans(scans, (s) => s.result?.modules ?? []))
  // stopScan stops one target's running scan. Its card settles itself once the
  // server's terminal event arrives.
  const stopScan = (t: string) => stopTrackedScan(scans[t])
  const speed = useScanSpeed()
  const canRun = runTargets.length > 0 && !running && speed.rps !== null

  const runScan = () => {
    if (!canRun) return
    const list = runTargets
    setScans(Object.fromEntries(list.map((t) => [t, { status: 'running' as const, progress: emptyProgress() }])))
    // One signal covers the whole batch, so Stop all reaches targets not yet started.
    const signal = batch.begin()
    runBatch(list, (t) => runOneScan(t, signal))
  }

  // retryScan restarts one failed target's scan in place: its card goes back to
  // running and the scan runs again, while the other targets keep going.
  const retryScan = (targetValue: string) => {
    setScans((prev) => ({ ...prev, [targetValue]: { status: 'running' as const, progress: emptyProgress() } }))
    void runOneScan(targetValue, batch.current())
  }

  // runOneScan streams this target's run into its card, and lands the full
  // result once it finishes. The cookie box becomes a Cookie header; the server
  // merges it with any credential headers.
  const runOneScan = (targetValue: string, signal?: AbortSignal) =>
    runTrackedScan<PathTraversalResponse>(
      () => api.pathTraversalScan({
        requestsPerSecond: speed.rps ?? undefined,
        url: toAbsoluteUrl(targetValue),
        method: body.trim() ? method : undefined,
        body: body.trim() ? body : undefined,
        contentType: body.trim() && contentType.trim() ? contentType.trim() : undefined,
        params: params.length ? params : undefined,

        mineParams: mineParams || undefined,
        headers: cookie.trim() ? { Cookie: cookie.trim() } : undefined,
        recursionDepth,
        maxPages,
        credentialId,
        caseId,
        callback: callback ?? undefined,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
      signal,
    )

  // stopAll ends the whole batch: targets not yet started are skipped, and
  // every running target is cancelled.
  const stopAll = () => {
    batch.stop()
    setScans((prev) => stopAllScans(prev))
  }

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Path Traversal"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Path Traversal</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Finds every place the client can name a file or path -- query parameters, form fields, path segments, a request
            body (JSON strings or form fields), path-like headers (X-Original-URL, X-File-Name, ...), and cookies -- and tries
            traversal payloads at each: plain ../ and Windows sequences, percent/double/overlong-UTF-8 and filter-evading
            encodings, absolute paths and file:// URLs, PHP's php://filter base64 wrapper, and the nginx alias
            off-by-slash. A finding is reported only when a known file's contents (for example /etc/passwd or win.ini)
            show up in the response and a control request for a nonexistent file does not. Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Seed pages in this case</span>
          <div className="mt-1">
            <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          </div>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Additional seed pages</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            One-off URLs not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="https://target.htb/download?file=report.pdf"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Extra parameter names</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Comma-separated -- tested directly on the seed URL's query string, in addition to the common file/path names and
            everything the crawl discovers.
          </span>
          <input
            value={extraParams}
            onChange={(e) => setExtraParams(e.target.value)}
            placeholder="document, view"
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <ParamMiningToggle checked={mineParams} onChange={setMineParams} />

        <div className="space-y-2">
          <span className="text-xs font-medium text-neutral-300">Request body (optional)</span>
          <span className="block text-[11px] text-neutral-600">
            When set, every JSON string or form field in it is tested as a path input, and the seed is sent with the method
            below. Leave empty to test the URL, forms, headers, and cookies only.
          </span>
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex items-center gap-1 text-xs text-neutral-400">
              Method
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value as 'GET' | 'POST')}
                className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
              </select>
            </label>
            <label className="flex flex-1 items-center gap-1 text-xs text-neutral-400">
              Content-Type
              <input
                value={contentType}
                onChange={(e) => setContentType(e.target.value)}
                placeholder="auto (JSON or form-encoded)"
                className={`min-w-0 flex-1 ${inputBase}`}
              />
            </label>
          </div>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={'{"name": "report.pdf"}   or   name=report.pdf&lang=en'}
            rows={3}
            className={`${inputBase} font-mono`}
          />
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Cookie header (optional)</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Sent with every request, so the scan runs as a logged-in session. Each cookie is tested as a path input too.
          </span>
          <input
            value={cookie}
            onChange={(e) => setCookie(e.target.value)}
            placeholder="session=abc123; theme=dark"
            className={`mt-1 ${inputBase} font-mono`}
          />
        </label>

        <div className="flex flex-wrap items-end gap-3">
          <label className="flex items-center gap-1 text-xs text-neutral-400">
            Crawl depth
            <input
              type="number"
              min={0}
              max={5}
              value={recursionDepth}
              onChange={(e) => setRecursionDepth(Math.max(0, Number(e.target.value) || 0))}
              className="w-16 rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
            />
          </label>
          <label className="flex items-center gap-1 text-xs text-neutral-400">
            Max pages
            <input
              type="number"
              min={1}
              max={50}
              value={maxPages}
              onChange={(e) => setMaxPages(Math.max(1, Number(e.target.value) || 1))}
              className="w-16 rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
            />
          </label>
        </div>

        {speed.control}

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <div>
          <span className="text-xs font-medium text-neutral-300">Out-of-band callback</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Off by default: this module mints its own throwaway token per point and discards it after. Pick a shared
            server instead to watch every hit live in the Collaborator tab, tagged with which point caused it.
          </span>
          <div className="mt-1">
            <CallbackPicker value={callback} onChange={setCallback} />
          </div>
        </div>

        <button
          onClick={runScan}
          disabled={!canRun}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {running ? 'Running…' : runLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'history' ? (
          <ScanHistoryPanel
            caseId={caseId}
            tool="pathtraversal"
            toState={(data: PathTraversalResponse) => ({ status: 'done' as const, result: data })}
            getSummary={pathTraversalSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        ) : (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more seed pages, then run.
              </div>
            )}
            {hasScans && (
              <BatchResultsPanel entries={Object.entries(scans)} getSummary={pathTraversalSummary} getProgress={(scan) => scan.progress} onRetry={retryScan} onStop={stopScan} onStopAll={stopAll} renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function pathTraversalSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
  const modules = scan.result?.modules ?? []
  const total = totalFindingsOf(modules)
  if (total === 0) return { label: 'Clean', tone: 'clean' }
  return { label: `${total} read${total === 1 ? '' : 's'}`, tone: hasSevereFindings(modules) ? 'danger' : 'warn' }
}

const SCAN_STATUS_STYLES: Record<TargetScanState['status'], { label: string; cls: string }> = {
  running: { label: 'Running…', cls: 'border-amber-700 bg-amber-950/40 text-amber-300' },
  done: { label: 'Done', cls: 'border-emerald-700 bg-emerald-950/40 text-emerald-300' },
  error: { label: 'Failed', cls: 'border-red-700 bg-red-950/40 text-red-300' },
  cancelled: { label: 'Stopped', cls: 'border-neutral-700 bg-neutral-900 text-neutral-400' },
}

function ScanStatusBadge({ status }: { status: TargetScanState['status'] }) {
  const meta = SCAN_STATUS_STYLES[status]
  return <span className={`rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${meta.cls}`}>{meta.label}</span>
}

function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const result = scan.result

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="break-all font-mono text-sm text-neutral-200">{target}</span>
        <ScanStatusBadge status={scan.status} />
      </div>

      {scan.status === 'error' && <ScanErrorNotice message={scan.error} />}

      {scan.status === 'done' && result && (
        <>
          <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
            <div className="flex flex-wrap gap-x-6 gap-y-1">
              <span>
                Baseline → <span className="font-mono text-neutral-200">{result.baseline.statusCode}</span>
              </span>
              <span>
                Pages crawled → <span className="font-mono text-neutral-300">{result.pagesScanned.length}</span>
              </span>
              <span>
                Injection points tested → <span className="font-mono text-neutral-300">{result.pointsTested}</span>
              </span>
            </div>
          </div>
          <SeverityTiles modules={result.modules} />
          <ModuleResultsList modules={result.modules} />
        </>
      )}
    </div>
  )
}
