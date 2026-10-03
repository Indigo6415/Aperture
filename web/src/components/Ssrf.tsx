import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CallbackSelection, Credential, SsrfResponse, Target } from '../types'
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
import { SeverityTiles, ModuleResultsList, totalFindingsOf, hasSevereFindings } from './ScanModuleResults'
import { emptyProgress, runTrackedScan, type TrackedScan } from '../scanProgress'

import { ScanErrorNotice } from './ScanErrorNotice'

type TargetScanState = TrackedScan<SsrfResponse>

// Ssrf is Aperture's server-side-request-forgery scanner (see internal/ssrf):
// targets URL-accepting parameters (a webhook, an "import/fetch from URL"
// field, an avatar-from-URL field, ...) with cloud metadata addresses
// (AWS/GCP/Azure/DigitalOcean/Alibaba) and localhost/internal-network
// addresses (including several filter-bypass encodings), and -- the only
// way to confirm a fully blind SSRF -- points a payload at Aperture's own
// out-of-band collaborator listener and checks whether the target's
// infrastructure actually called back. Deliberately narrower than Probe's
// own path-traversal/SSTI checks: only parameters that are actually
// URL-shaped, with payloads that only matter when the server fetches them
// itself. Runs against every endpoint the user selects or types at once,
// same batch pattern as PwReset/Cors/OpenRedirect.
export function Ssrf({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [extraParams, setExtraParams] = useState('')
  const [autoDiscover, setAutoDiscover] = useState(false)
  const [callback, setCallback] = useState<CallbackSelection | null>(null)

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('ssrf.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<SsrfResponse>(caseId, 'ssrf').then((list) => {
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

  // runOneScan streams this target's run -- one live check per (module,
  // parameter) -- into its card, and lands the full result once it's done.
  const runOneScan = (targetValue: string) =>
    runTrackedScan<SsrfResponse>(
      () =>
        api.ssrfScan({
          url: toAbsoluteUrl(targetValue),
          params: params.length ? params : undefined,
          credentialId,
          caseId,
          autoDiscover: autoDiscover || undefined,
          callback: callback ?? undefined,
        }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
    )

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="SSRF Scanner"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">SSRF Scanner</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Targets URL-accepting parameters (a webhook, an "import/fetch from URL" field, an avatar-from-URL field, ...) with
            cloud metadata and internal-network addresses, plus a blind-SSRF confirmation via Aperture's own out-of-band
            collaborator listener (see the Collaborator tab/Settings to configure its domain for DNS-based confirmation --
            the HTTP side works with no setup, as long as the target can reach this Aperture instance). Never submits a
            destructive payload -- every request is a GET. Authorized testing only.
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
            placeholder="https://target.htb/api/webhooks?url=https://example.com"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Extra parameter names</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Comma-separated, in addition to the common URL-fetching-parameter list (url, webhook, avatar_url, import_url, ...).
          </span>
          <input
            value={extraParams}
            onChange={(e) => setExtraParams(e.target.value)}
            placeholder="sourceUrl, previewUrl"
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label
          className="flex items-center gap-1.5 text-xs text-neutral-400"
          title="Crawls same-origin pages from the target first (links' query params, form field names, form action query params) and adds whatever parameter names it finds to the candidate set. Off by default -- leaves today's behavior unchanged."
        >
          <input type="checkbox" checked={autoDiscover} onChange={(e) => setAutoDiscover(e.target.checked)} className="accent-sky-500" />
          Auto-discover parameters (crawl same-origin pages/forms)
        </label>

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <div>
          <span className="text-xs font-medium text-neutral-300">Out-of-band callback</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Off by default: this module mints its own throwaway token per parameter and discards it after. Pick a shared
            server instead to watch every hit live in the Collaborator tab, tagged with which parameter caused it.
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
          {running ? 'Running… (the OOB module waits a few seconds for callbacks)' : runLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'history' ? (
          <ScanHistoryPanel
            caseId={caseId}
            tool="ssrf"
            toState={(data: SsrfResponse) => ({ status: 'done' as const, result: data })}
            getSummary={ssrfSummary}
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
              <BatchResultsPanel
                entries={Object.entries(scans)}
                getSummary={ssrfSummary}
                getProgress={(scan) => scan.progress}
                renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function ssrfSummary(scan: TargetScanState): BatchResultSummary {
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
            </div>
          </div>
          <SeverityTiles modules={result.modules} />
          <ModuleResultsList modules={result.modules} />
        </>
      )}
    </div>
  )
}
