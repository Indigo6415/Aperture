import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CsrfScanResponse, Credential, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
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

type TargetScanState = TrackedScan<CsrfScanResponse>

// Csrf is Aperture's site-wide CSRF sweep (see internal/csrf):
// internal/pwreset already checks one specific form (the password-reset
// request); this crawls a site the same same-origin way internal/breach
// does, finds every state-changing (POST/PUT/DELETE/PATCH) form, and checks
// each for a CSRF-token-looking field, plus checks every cookie the site
// sets anywhere for the SameSite attribute. Read-only: it crawls with GET
// requests and never submits a discovered form, since actually submitting an
// arbitrary crawled form could trigger a real side effect the operator
// doesn't want performed against the target. Runs against every seed page
// the user selects or types at once, same batch pattern as PwReset/Cors.
export function Csrf({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [recursionDepth, setRecursionDepth] = useState(1)
  const [maxPages, setMaxPages] = useState(25)
  const [apiUrl, setApiUrl] = useState('')
  const [apiMethod, setApiMethod] = useState('POST')
  const [apiBody, setApiBody] = useState('')

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('csrf.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<CsrfScanResponse>(caseId, 'csrf').then((list) => {
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
    runTrackedScan<CsrfScanResponse>(
      () => api.csrfScan({
        url: toAbsoluteUrl(targetValue),
        recursionDepth,
        maxPages,
        credentialId,
        caseId,
        apiUrl: apiUrl.trim() || undefined,
        apiMethod: apiUrl.trim() ? apiMethod : undefined,
        apiBody: apiUrl.trim() ? apiBody : undefined,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
    )

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="CSRF Sweep"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">CSRF Sweep</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Crawls a site same-origin from a seed page, finds every state-changing (POST/PUT/DELETE/PATCH) form, and checks
            each for a CSRF-token-looking field -- plus checks every cookie the site sets anywhere for SameSite. Read-only:
            crawls with GET and never submits a discovered form. Use a credential with a real session for a meaningful crawl
            -- an unauthenticated one typically only reaches a login form. Authorized testing only.
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
            placeholder="https://target.htb/dashboard"
            rows={2}
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

        <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
          <div>
            <span className="text-xs font-medium text-neutral-300">Content-Type CSRF bypass (optional, active)</span>
            <p className="mt-0.5 text-[11px] text-neutral-600">
              Replays a specific JSON API request a second time under Content-Type: text/plain -- a CORS-safelisted header a
              cross-origin page can already set with no preflight (the still-exploitable descendant of Chrome's long-fixed
              sendBeacon bug, crbug.com/490015). If both requests are accepted the same way, this endpoint's JSON-only
              Content-Type isn't providing real CSRF protection. Fires two real requests against this endpoint -- leave the URL
              blank to skip. If multiple seed pages are queued above, it fires once per seed page, so queue just one target
              while using this.
            </p>
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex-1 basis-56">
              <span className="text-[11px] text-neutral-500">Endpoint URL</span>
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                placeholder="https://target.htb/api/account/update"
                className={`mt-0.5 ${inputBase}`}
              />
            </label>
            <label>
              <span className="text-[11px] text-neutral-500">Method</span>
              <select
                value={apiMethod}
                onChange={(e) => setApiMethod(e.target.value)}
                className="mt-0.5 block w-24 rounded border border-neutral-700 bg-neutral-900 px-1.5 py-1.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
              >
                <option>POST</option>
                <option>PUT</option>
                <option>PATCH</option>
                <option>DELETE</option>
              </select>
            </label>
          </div>
          <label className="block">
            <span className="text-[11px] text-neutral-500">JSON body to replay</span>
            <textarea
              value={apiBody}
              onChange={(e) => setApiBody(e.target.value)}
              placeholder={'{"email":"new@example.com"}'}
              rows={2}
              className={`mt-0.5 ${inputBase} font-mono`}
            />
          </label>
        </div>

        <button
          onClick={runScan}
          disabled={!canRun}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {running ? 'Crawling…' : runLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'history' ? (
          <ScanHistoryPanel
            caseId={caseId}
            tool="csrf"
            toState={(data: CsrfScanResponse) => ({ status: 'done' as const, result: data })}
            getSummary={csrfSummary}
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
              <BatchResultsPanel entries={Object.entries(scans)} getSummary={csrfSummary} getProgress={(scan) => scan.progress} renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function csrfSummary(scan: TargetScanState): BatchResultSummary {
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
                Pages crawled → <span className="font-mono text-neutral-200">{result.pagesScanned.length}</span>
              </span>
              <span>
                State-changing forms found → <span className="font-mono text-neutral-300">{result.formsFound}</span>
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
