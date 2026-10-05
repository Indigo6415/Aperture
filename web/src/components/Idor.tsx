import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CookieVaultEntry, Credential, IdorResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { CookieVaultPicker } from './CookieVaultPicker'
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

type TargetScanState = TrackedScan<IdorResponse>

// Idor is Aperture's IDOR / broken-object-level-authorization scanner (see
// internal/idor). It finds every place a request carries an object reference
// (query parameters, path segments, JSON/form body fields, cookies, identity
// headers) whose value or name looks like an id, then mutates each one --
// adjacent ids, boundary values, parameter pollution, array/NoSQL wrapping,
// suffix and encoding tricks -- reporting a lead when a distinct, real object
// comes back. When a second credential is supplied, it also replays each
// request under that identity (and under no auth) and confirms broken access
// control outright when the other identity reads the owner's object. Runs
// against every seed selected or typed, same batch pattern as PathTraversal.
export function Idor({ caseId, targets, credentials, cookieVault }: { caseId: string; targets: Target[]; credentials: Credential[]; cookieVault: CookieVaultEntry[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [attackerCredentialId, setAttackerCredentialId] = useState<string | undefined>()
  const [extraParams, setExtraParams] = useState('')
  const [method, setMethod] = useState<'GET' | 'POST'>('GET')
  const [body, setBody] = useState('')
  const [contentType, setContentType] = useState('')
  const [cookie, setCookie] = useState('')
  const [attackerCookie, setAttackerCookie] = useState('')
  const [mineParams, setMineParams] = useState(false)

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('idor.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  useEffect(() => {
    let cancelled = false
    loadCaseScans<IdorResponse>(caseId, 'idor').then((list) => {
      if (cancelled) return
      const restored = latestByTarget(list)
      if (restored.length === 0) return
      setScans((prev) => {
        const next = { ...prev }
        // Only restore a target that has no live card already.
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

  const running = Object.values(scans).some((s) => s.status === 'running')
  // Publishes this tab's scan state to the case nav's border.
  useReportScanIndicator('idor', indicatorOfScans(scans, (s) => s.result?.modules ?? []))
  // stopScan stops one target's running scan; its card settles on the server's terminal event.
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

  // retryScan restarts one failed target's scan in place while the others keep going.
  const retryScan = (targetValue: string) => {
    setScans((prev) => ({ ...prev, [targetValue]: { status: 'running' as const, progress: emptyProgress() } }))
    void runOneScan(targetValue, batch.current())
  }

  // runOneScan streams this target's run into its card. The owner cookie and
  // the attacker cookie each become a Cookie header on their own identity; the
  // server merges them with the chosen credentials.
  const runOneScan = (targetValue: string, signal?: AbortSignal) =>
    runTrackedScan<IdorResponse>(
      () => api.idorScan({
        requestsPerSecond: speed.rps ?? undefined,
        url: toAbsoluteUrl(targetValue),
        method: body.trim() ? method : undefined,
        body: body.trim() ? body : undefined,
        contentType: body.trim() && contentType.trim() ? contentType.trim() : undefined,
        params: params.length ? params : undefined,
        mineParams: mineParams || undefined,
        headers: cookie.trim() ? { Cookie: cookie.trim() } : undefined,
        attackerHeaders: attackerCookie.trim() ? { Cookie: attackerCookie.trim() } : undefined,
        credentialId,
        attackerCredentialId,
        caseId,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
      signal,
    )

  // stopAll ends the whole batch: targets not yet started are skipped, running ones cancelled.
  const stopAll = () => {
    batch.stop()
    setScans((prev) => stopAllScans(prev))
  }

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="IDOR"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">IDOR / Broken Access</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Finds every object reference the request carries -- ids in the query, path, JSON or form body, cookies, and
            identity headers (X-User-Id, ...) -- and mutates each: adjacent ids, boundary and first-record values, parameter
            pollution, array and NoSQL-operator wrapping, suffix and wildcard tricks, and encoding bypasses. A single-identity
            lead is reported when a distinct, real object comes back for a changed reference (a negative control rules out
            catch-all endpoints). Supply a <span className="text-neutral-300">second credential</span> to confirm outright:
            each request is replayed under that identity, and under no auth, and a finding is confirmed when the other
            identity reads the owner's object. Authorized testing only -- verify ownership before reporting a lead.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Seed requests in this case</span>
          <div className="mt-1">
            <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          </div>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Additional seed requests</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            One-off URLs not saved to the case -- comma- or newline-separated for a batch. Include the id in the URL.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="https://target.htb/api/orders/1024"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Extra id-parameter names</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Comma-separated -- added to the seed query (seeded with "1") alongside the built-in common id names and anything
            mining finds, to surface hidden id parameters the UI never sends.
          </span>
          <input
            value={extraParams}
            onChange={(e) => setExtraParams(e.target.value)}
            placeholder="owner_id, tenant"
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <ParamMiningToggle checked={mineParams} onChange={setMineParams} />

        <div className="space-y-2">
          <span className="text-xs font-medium text-neutral-300">Request body (optional)</span>
          <span className="block text-[11px] text-neutral-600">
            When set, every JSON string/number or form field in it that looks like a reference is mutated, and the seed is sent
            with the method below. Leave empty to test the URL, cookies, and headers only.
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
            placeholder={'{"orderId": "1024"}   or   order_id=1024&page=1'}
            rows={3}
            className={`${inputBase} font-mono`}
          />
        </div>

        {speed.control}

        <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
          <div>
            <span className="text-xs font-medium text-neutral-300">Owner identity</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              The user who legitimately owns the objects under test. Its response is the baseline every mutation is compared to.
            </span>
            <div className="mt-1 space-y-2">
              <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />
              <CookieVaultPicker entries={cookieVault} value={cookie} onPick={setCookie} />
              <input
                value={cookie}
                onChange={(e) => setCookie(e.target.value)}
                placeholder="owner Cookie header, e.g. session=abc123"
                className={`${inputBase} font-mono`}
              />
            </div>
          </div>

          <div>
            <span className="text-xs font-medium text-neutral-300">Attacker identity (optional, for confirmation)</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              A second, lower-privileged user. When set, each request is replayed under this identity; a finding is confirmed
              when it reads the owner's object. Leave empty to run single-identity leads plus an unauthenticated replay.
            </span>
            <div className="mt-1 space-y-2">
              <CredentialPicker credentials={credentials} selected={attackerCredentialId} onSelect={setAttackerCredentialId} />
              <CookieVaultPicker entries={cookieVault} value={attackerCookie} onPick={setAttackerCookie} />
              <input
                value={attackerCookie}
                onChange={(e) => setAttackerCookie(e.target.value)}
                placeholder="attacker Cookie header, e.g. session=def456"
                className={`${inputBase} font-mono`}
              />
            </div>
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
            tool="idor"
            toState={(data: IdorResponse) => ({ status: 'done' as const, result: data })}
            getSummary={idorSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        ) : (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more seed requests, then run.
              </div>
            )}
            {hasScans && (
              <BatchResultsPanel entries={Object.entries(scans)} getSummary={idorSummary} getProgress={(scan) => scan.progress} onRetry={retryScan} onStop={stopScan} onStopAll={stopAll} renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />} />
            )}
          </>
        )}
      </div>
    </div>
  )
}

// idorSummary is the one-line batch badge for a target's card.
function idorSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
  const modules = scan.result?.modules ?? []
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
                Reference points → <span className="font-mono text-neutral-300">{result.pointsTested}</span>
              </span>
              <span>
                Tests run → <span className="font-mono text-neutral-300">{result.testsRun}</span>
              </span>
              <span>
                Identities → <span className="font-mono text-neutral-300">{result.identities.length > 0 ? result.identities.join(', ') : 'owner only'}</span>
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
