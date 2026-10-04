import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CallbackSelection, Credential, Target, XxeResponse } from '../types'
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
import { SeverityTiles, ModuleResultsList, totalFindingsOf, hasSevereFindings } from './ScanModuleResults'
import { emptyProgress, runTrackedScan, type TrackedScan, runBatch, stopTrackedScan, useScanBatch, stopAllScans } from '../scanProgress'

import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'

type TargetScanState = TrackedScan<XxeResponse>

// placeholderXml is shown in the XML box when it's empty. It is a sample of the
// kind of document an XML endpoint takes, so the operator can see the shape the
// scanner will mutate.
const placeholderXml = `<?xml version="1.0" encoding="UTF-8"?>
<login>
  <username>alice</username>
  <password>hunter2</password>
</login>`

// Xxe is Aperture's XML External Entity scanner (see internal/xxe). It sends
// XML to each endpoint with an external entity added and each text value
// swapped for an entity reference. The checks run from the safest proof to the
// strongest: an internal-entity canary, file reads, a missing-path error leak,
// XInclude, a metadata fetch, and finally a blind callback to Aperture's own
// collaborator listener. Auto-discover finds other same-origin endpoints that
// take XML and tests each one. Every payload is read-only, and nothing here
// uses an entity-expansion denial of service.
export function Xxe({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [method, setMethod] = useState<'POST' | 'PUT'>('POST')
  const [xmlBody, setXmlBody] = useState('')
  const [autoDiscover, setAutoDiscover] = useState(false)
  const [callback, setCallback] = useState<CallbackSelection | null>(null)

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('xxe.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<XxeResponse>(caseId, 'xxe').then((list) => {
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

  const running = Object.values(scans).some((s) => s.status === 'running')
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

  // runOneScan streams this target's run -- one live check per (endpoint,
  // module, injection point) -- into its card, and lands the full result once
  // it's done.
  const runOneScan = (targetValue: string, signal?: AbortSignal) =>
    runTrackedScan<XxeResponse>(
      () =>
        api.xxeScan({
          requestsPerSecond: speed.rps ?? undefined,
          url: toAbsoluteUrl(targetValue),
          method,
          // An empty box sends no body, so the server uses its own probe document.
          body: xmlBody.trim() ? xmlBody : undefined,
          credentialId,
          caseId,
          autoDiscover: autoDiscover || undefined,
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
        title="XXE"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">XXE</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Tests endpoints that accept XML for XML External Entity injection. Every text value in the XML below becomes an
            injection point. Checks run from the safest proof to the strongest: an internal entity that proves the parser
            expands entities, a local file read, a parser error that names a missing path, XInclude, a cloud-metadata fetch,
            and a blind callback to Aperture's collaborator listener (works with no setup when the target can reach this
            Aperture instance). No denial-of-service payloads. Authorized testing only.
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
            placeholder="https://target.htb/api/import"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">Method</span>
            <select value={method} onChange={(e) => setMethod(e.target.value as 'POST' | 'PUT')} className={`mt-1 ${inputBase}`}>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">XML part (optional)</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              A sample of the XML the endpoint takes. Each text value is tested, and any DOCTYPE in it is replaced. Leave empty
              to send a built-in probe document.
            </span>
            <textarea
              value={xmlBody}
              onChange={(e) => setXmlBody(e.target.value)}
              placeholder={placeholderXml}
              rows={6}
              spellCheck={false}
              className={`mt-1 font-mono text-xs ${inputBase}`}
            />
          </label>
        </div>

        <label
          className="flex items-center gap-1.5 text-xs text-neutral-400"
          title="Crawls same-origin pages (links, form actions, paths named in scripts) and probes the common XML paths with a well-formed and a malformed XML document. Each endpoint that answers XML, or rejects malformed XML with a parser error, is tested. Off by default."
        >
          <input type="checkbox" checked={autoDiscover} onChange={(e) => setAutoDiscover(e.target.checked)} className="accent-sky-500" />
          Auto-discover XML endpoints on the same origin
        </label>

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
          {running ? 'Running… (the blind module waits a few seconds for callbacks)' : runLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'history' ? (
          <ScanHistoryPanel
            caseId={caseId}
            tool="xxe"
            toState={(data: XxeResponse) => ({ status: 'done' as const, result: data })}
            getSummary={xxeSummary}
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
                getSummary={xxeSummary}
                getProgress={(scan) => scan.progress}
                onRetry={retryScan} onStop={stopScan} onStopAll={stopAll}
                renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

function xxeSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
  const result = scan.result
  // An auto-discover run that found no XML endpoint has nothing to report, so
  // it is not a clean pass.
  if (result && result.endpoints.length === 0) return { label: 'No XML endpoints', tone: 'neutral' }
  const modules = result?.modules ?? []
  const total = totalFindingsOf(modules)
  if (total === 0) return { label: 'Clean', tone: 'clean' }
  return { label: `${total} issue${total === 1 ? '' : 's'}`, tone: hasSevereFindings(modules) ? 'danger' : 'warn' }
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
  // Confirmed and likely counts are shown separately, since a parser error
  // that names a path proves less than a file read or a callback.
  const findings = result?.modules.flatMap((m) => m.findings) ?? []
  const confirmed = findings.filter((f) => f.confidence === 'confirmed').length
  const likely = findings.filter((f) => f.confidence === 'likely').length

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
                Endpoints tested → <span className="font-mono text-neutral-300">{result.endpoints.length}</span>
              </span>
              <span>
                Injection points → <span className="font-mono text-neutral-300">{result.pointsTested}</span>
              </span>
              <span>
                Confirmed → <span className="font-mono text-neutral-300">{confirmed}</span>
              </span>
              <span>
                Likely → <span className="font-mono text-neutral-300">{likely}</span>
              </span>
            </div>
          </div>

          {result.endpoints.length === 0 && (
            <div className="rounded-lg border border-dashed border-neutral-800 p-3 text-xs text-neutral-500">
              No same-origin endpoint answered XML, so nothing was tested. This is not a clean result.
            </div>
          )}

          {result.endpoints.length > 0 && (
            <ul className="space-y-1 rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs">
              {result.endpoints.map((e) => (
                <li key={`${e.method} ${e.url}`} className="flex flex-wrap items-baseline gap-x-2">
                  <span className="font-mono text-neutral-300">
                    {e.method} {e.url}
                  </span>
                  <span className="text-neutral-500">{e.source}</span>
                  {e.evidence && <span className="text-neutral-600">— {e.evidence}</span>}
                </li>
              ))}
            </ul>
          )}

          {!result.oobEnabled && (
            <div className="rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-xs text-amber-300">
              The blind (out-of-band) module did not run: no callback listener is configured. Set a collaborator domain or
              callback address in Settings to test blind XXE.
            </div>
          )}

          <SeverityTiles modules={result.modules} />
          <ModuleResultsList modules={result.modules} />
        </>
      )}
    </div>
  )
}
