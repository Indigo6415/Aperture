import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CallbackSelection, Credential, OpenRedirectResponse, Target } from '../types'
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

type TargetScanState = TrackedScan<OpenRedirectResponse>

// OpenRedirect is Aperture's unvalidated-redirect scanner (see
// internal/openredirect). It covers four places an app takes a destination:
// query parameters (absolute, protocol-relative, encoding and parser-
// disagreement bypasses), path segments ("/go/<destination>"), the Referer
// header, and host headers the app builds URLs from (Host, X-Forwarded-Host
// and friends). Every hit is confirmed by a live callback, so a finding means
// the redirect was really followed to the listener. Runs against every
// endpoint the user selects or types at once, same batch pattern as PwReset/Cors.
export function OpenRedirect({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [extraParams, setExtraParams] = useState('')
  const [callback, setCallback] = useState<CallbackSelection | null>(null)
  // On by default: a redirect chain that goes through an intermediate page
  // (login, normalization, "return to") only confirms when it's walked.
  const [followRedirects, setFollowRedirects] = useState(true)

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('openredirect.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<OpenRedirectResponse>(caseId, 'openredirect').then((list) => {
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
    runTrackedScan<OpenRedirectResponse>(
      () => api.openRedirect({
        url: toAbsoluteUrl(targetValue),
        params: params.length ? params : undefined,
        credentialId,
        caseId,
        callback: callback ?? undefined,
        followRedirects,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
    )

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Open Redirect Scanner"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Open Redirect Scanner</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Tries every common redirect parameter name (plus anything already in the URL's own query string) with about a
            dozen parser-disagreement payloads (absolute, protocol-relative, backslash, tab and whitespace, missing slashes,
            userinfo "@", allowlist substring), plus path segments like "/go/&lt;dest&gt;", the Referer header, and the Host,
            X-Forwarded-Host, and Forwarded headers. Each hit is only reported once a callback server records the redirect
            being followed. Point this at a page that's expected to redirect somewhere (a login flow, an SSO callback, a
            "continue" link) for the most meaningful results. Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Endpoints in this case</span>
          <div className="mt-1">
            <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          </div>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Additional endpoints</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            One-off URLs not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="https://target.htb/login?returnTo=/dashboard"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Extra parameter names</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Comma-separated, in addition to the common redirect-parameter list (redirect, url, next, return, continue, ...).
          </span>
          <input
            value={extraParams}
            onChange={(e) => setExtraParams(e.target.value)}
            placeholder="returnTo, successUrl"
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={followRedirects}
            onChange={(e) => setFollowRedirects(e.target.checked)}
            className="mt-0.5 accent-sky-500"
          />
          <span>
            <span className="block text-xs font-medium text-neutral-300">Follow redirects</span>
            <span className="block text-[11px] text-neutral-600">
              On by default. Walks each redirect chain (up to five hops) looking for the callback, so a redirect that reaches it
              through an intermediate page (a login, a normalization, a "return to") still counts. Off checks only the first hop.
            </span>
          </span>
        </label>

        <div>
          <span className="text-xs font-medium text-neutral-300">Out-of-band callback</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Every run confirms its hits against a callback server. Without one picked, the scanner mints a throwaway listener
            for the run. Pick a shared server to watch the same hits live in the Collaborator tab.
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
            tool="openredirect"
            toState={(data: OpenRedirectResponse) => ({ status: 'done' as const, result: data })}
            getSummary={openRedirectSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        ) : (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more endpoints, then run.
              </div>
            )}
            {hasScans && (
              <BatchResultsPanel entries={Object.entries(scans)} getSummary={openRedirectSummary} getProgress={(scan) => scan.progress} renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function openRedirectSummary(scan: TargetScanState): BatchResultSummary {
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
                Parameters tested → <span className="font-mono text-neutral-300">{result.paramsTested.length}</span>
              </span>
              {result.probesSent !== undefined && (
                <span>
                  Probes sent → <span className="font-mono text-neutral-300">{result.probesSent}</span>
                </span>
              )}
              {result.followRedirects !== undefined && (
                <span>
                  Follow redirects → <span className="font-mono text-neutral-300">{result.followRedirects ? 'on' : 'off'}</span>
                </span>
              )}
            </div>
          </div>
          <SeverityTiles modules={result.modules} />
          <ModuleResultsList modules={result.modules} />
        </>
      )}
    </div>
  )
}
