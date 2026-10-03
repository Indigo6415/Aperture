import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CallbackSelection, Credential, SstiScanResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { CallbackPicker } from './CallbackPicker'
import { BatchResultsPanel, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { emptyProgress, runTrackedScan, type TrackedScan } from '../scanProgress'
import { SeverityTiles, ModuleResultsList, totalFindingsOf, hasSevereFindings } from './ScanModuleResults'

import { ScanErrorNotice } from './ScanErrorNotice'

type TargetScanState = TrackedScan<SstiScanResponse>

// SstiScan is Aperture's Server-Side Template Injection scanner (see
// internal/sstiscan): crawls a site same-origin from a seed page and
// automatically builds its own candidate list of "every input box and every
// place user input may be displayed/used" -- every query parameter already
// in play, every <form> field (submitted via that form's own GET/POST), and
// a fixed set of commonly-logged/echoed request headers (User-Agent,
// Referer, X-Forwarded-For, ...) -- then fires engine-tagged arithmetic
// payloads, a syntax-breaking polyglot, and (with a callback configured)
// well-documented engine-specific RCE payloads against every one of them.
// Runs against every seed page the user selects or types at once, same
// batch pattern as Csrf/OpenRedirect.
export function SstiScan({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [extraParams, setExtraParams] = useState('')
  const [recursionDepth, setRecursionDepth] = useState(1)
  const [maxPages, setMaxPages] = useState(25)
  const [callback, setCallback] = useState<CallbackSelection | null>(null)

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('sstiscan.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<SstiScanResponse>(caseId, 'sstiscan').then((list) => {
      if (cancelled) return
      const restored = latestByTarget(list)
      if (restored.length === 0) return
      setScans((prev) => {
        const next = { ...prev }
        for (const r of restored) if (!next[r.scan.target]) next[r.scan.target] = { status: 'done', result: r.data }
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

  const running = Object.values(scans).some((s) => s.status === 'running')
  const canRun = runTargets.length > 0 && !running

  const runScan = () => {
    if (!canRun) return
    const list = runTargets
    setScans(Object.fromEntries(list.map((t) => [t, { status: 'running' as const, progress: emptyProgress() }])))
    for (const t of list) runOneScan(t)
  }

  // runOneScan streams this target's run into its card, and lands the full
  // result once it finishes.
  const runOneScan = (targetValue: string) =>
    runTrackedScan<SstiScanResponse>(
      () => api.sstiScan({
        url: toAbsoluteUrl(targetValue),
        params: params.length ? params : undefined,
        recursionDepth,
        maxPages,
        credentialId,
        caseId,
        callback: callback ?? undefined,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
    )

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="SSTI Scanner"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">SSTI Scanner</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Crawls a site same-origin from a seed page and automatically tests every input box and every place user input
            may be displayed/used -- every query parameter, every form field (submitted via that form's own GET/POST), and
            a fixed set of commonly-logged request headers -- with engine-tagged arithmetic payloads (Jinja2, Twig,
            FreeMarker, Velocity, Smarty, ERB, Thymeleaf, Pug, ...), a syntax-breaking polyglot checked against each
            engine's own error signature, and -- with an out-of-band callback picked below -- well-documented
            engine-specific RCE payloads to confirm a fully blind SSTI. Authorized testing only.
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
            placeholder="https://target.htb/search?q=test"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Extra parameter names</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Comma-separated -- fuzzed directly onto the seed URL's query string, in addition to every point the crawl
            itself discovers.
          </span>
          <input
            value={extraParams}
            onChange={(e) => setExtraParams(e.target.value)}
            placeholder="name, comment, template"
            className={`mt-1 ${inputBase}`}
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

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <div>
          <span className="text-xs font-medium text-neutral-300">Out-of-band callback (RCE confirmation)</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Off by default: the math-eval and error-signature modules already run without it. Pick a shared server to
            additionally fire well-documented, engine-specific SSTI-to-RCE payloads and get a finding only once the
            target's own infrastructure actually calls back -- confirms a fully blind SSTI that achieves code execution.
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
            tool="sstiscan"
            toState={(data: SstiScanResponse) => ({ status: 'done' as const, result: data })}
            getSummary={sstiScanSummary}
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
              <BatchResultsPanel entries={Object.entries(scans)} getSummary={sstiScanSummary} getProgress={(scan) => scan.progress} renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function sstiScanSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger' }
  const modules = scan.result?.modules ?? []
  const total = totalFindingsOf(modules)
  if (total === 0) return { label: 'Clean', tone: 'clean' }
  return { label: `${total} issue${total === 1 ? '' : 's'}`, tone: hasSevereFindings(modules) ? 'danger' : 'warn' }
}

const SCAN_STATUS_STYLES: Record<TargetScanState['status'], { label: string; cls: string }> = {
  running: { label: 'Running…', cls: 'border-amber-700 bg-amber-950/40 text-amber-300' },
  done: { label: 'Done', cls: 'border-emerald-700 bg-emerald-950/40 text-emerald-300' },
  error: { label: 'Failed', cls: 'border-red-700 bg-red-950/40 text-red-300' },
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
