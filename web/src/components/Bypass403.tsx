import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { Bypass403HandoffRequest as HandoffRequest } from '../bypass403Handoff'
import type { Bypass403Attempt, Bypass403Response, Credential, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { BatchResultsPanel, stoppedSummary, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { CopyButton } from './CopyButton'
import { SendToTesterButton } from './SendToTesterButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { emptyProgress, runTrackedScan, type TrackedScan, runBatch, stopTrackedScan, useScanBatch, stopAllScans } from '../scanProgress'
import { indicatorOfScans, useReportScanIndicator } from '../scanIndicator'
import { statusHexColor } from '../statusColor'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToTester } from '../testerHandoff'

// TargetScanState is one target's place in a (possibly multi-target) run --
// same shape/reasoning as SecretScan.tsx's TargetScanState.
import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'

type TargetScanState = TrackedScan<Bypass403Response>

const CATEGORY_LABELS: Record<Bypass403Attempt['category'], string> = {
  path: 'Path manipulation',
  header: 'Header spoofing',
  method: 'Method tricks',
  protocol: 'Protocol tricks',
  archive: 'Wayback Machine',
}

// Bypass403 is Aperture's Go/tsx port of a "403 bypass" scanner (see
// internal/bypass403): take a baseline request against a target, and if -- and
// only if -- that baseline actually looks denied (a hard 401/403, or an
// HTTP success whose body still reads like a denial page), replay it through
// a battery of path/header/method/protocol variations and report which ones
// stopped looking denied. Runs against every target the user selects or
// types at once, same batch pattern as Probe/SecretScan.
export function Bypass403({
  caseId,
  targets,
  credentials,
  prefill,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  prefill?: HandoffRequest
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [allowWrites, setAllowWrites] = useState(false)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('bypass403.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

  // Restores this case's most recent 403-bypass run per target on
  // mount/reload -- see saveCaseScan in internal/api/handlers_bypass403.go.
  // Every past run is also browsable via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<Bypass403Response>(caseId, 'bypass403').then((list) => {
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

  // Applies a "Send to 403 Bypass" handoff -- see bypass403Handoff.ts.
  useEffect(() => {
    if (prefill) setManualTarget(prefill.url)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.seq])

  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])

  const running = Object.values(scans).some((s) => s.status === 'running')
  // Publishes this tab's scan state to the case nav's border.
  useReportScanIndicator('bypass403', indicatorOfScans(scans, () => []))
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
  // result once it finishes.
  const runOneScan = (targetValue: string, signal?: AbortSignal) =>
    runTrackedScan<Bypass403Response>(
      () => api.bypass403({ requestsPerSecond: speed.rps ?? undefined, url: toAbsoluteUrl(targetValue), credentialId, allowWriteMethods: allowWrites || undefined, caseId }),
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
        title="403 Bypass"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">403 Bypass</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Takes a baseline request against a URL that returns 401/403 (or an HTTP success whose body still reads like a
            denial page), then replays it through path-manipulation, header-spoofing, method, and protocol variations,
            flagging any that stop looking denied. Runs against as many targets at once as you select. A target that
            doesn't actually look blocked is reported as such with no further requests sent. Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Targets in this case</span>
          <div className="mt-1">
            <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          </div>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Additional targets</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            One-off URLs not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="https://target.htb/admin"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>


        {speed.control}


        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <label className="flex items-start gap-2 text-[11px] text-amber-300/90">
          <input type="checkbox" checked={allowWrites} onChange={(e) => setAllowWrites(e.target.checked)} className="mt-0.5" />
          <span>Also try PUT, PATCH and DELETE against the path. These can change or delete data on the target.</span>
        </label>

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
            tool="bypass403"
            toState={(data: Bypass403Response) => ({ status: 'done' as const, result: data })}
            getSummary={bypassSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        ) : (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more targets, then run.
              </div>
            )}

            {hasScans && (
              <BatchResultsPanel
                entries={Object.entries(scans)}
                getSummary={bypassSummary}
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

// bypassSummary is one target's one-line compact-view badge once a batch
// covers more than BatchResultsPanel's threshold -- mirrors
// SecretScan.tsx's secretScanSummary.
function bypassSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
  const result = scan.result
  if (!result?.baseline.blocked) return { label: 'Not blocked', tone: 'clean' }
  const n = result.bypassCount
  return n === 0 ? { label: 'No bypass', tone: 'clean' } : { label: `${n} bypass${n === 1 ? '' : 'es'}`, tone: 'danger' }
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

// TargetScanCard is one target's whole run lifecycle in a batch -- same role
// as SecretScan.tsx's TargetScanCard.
function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const grouped = useMemo(() => {
    const byCategory = new Map<Bypass403Attempt['category'], Bypass403Attempt[]>()
    for (const a of scan.result?.attempts ?? []) {
      const list = byCategory.get(a.category) ?? []
      list.push(a)
      byCategory.set(a.category, list)
    }
    // Sorted so a category with a bypass in it floats to the top -- the
    // whole point of this view is "which technique worked", not an
    // alphabetical tour of every category that didn't.
    return [...byCategory.entries()].sort((a, b) => {
      const aBypassed = a[1].some((x) => x.bypassed) ? 1 : 0
      const bBypassed = b[1].some((x) => x.bypassed) ? 1 : 0
      return bBypassed - aBypassed
    })
  }, [scan.result])

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
                Baseline →{' '}
                <span className="font-mono" style={{ color: statusHexColor(result.baseline.statusCode) }}>
                  {result.baseline.statusCode}
                </span>{' '}
                · {result.baseline.contentLength}b
              </span>
              <span>
                Looks blocked →{' '}
                <span className={result.baseline.blocked ? 'text-amber-400' : 'text-emerald-400'}>
                  {result.baseline.blocked ? result.baseline.reason || 'yes' : 'no'}
                </span>
              </span>
              {result.baseline.blocked && (
                <span>
                  Bypasses → <span className={result.bypassCount ? 'font-semibold text-red-400' : 'text-neutral-200'}>{result.bypassCount}</span>
                </span>
              )}
            </div>
          </div>

          {!result.baseline.blocked ? (
            <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
              This target doesn't look blocked -- nothing to bypass, so no further requests were sent.
            </div>
          ) : (
            <div className="space-y-3">
              {grouped.map(([category, attempts]) => (
                <AttemptGroup key={category} category={category} attempts={attempts} baselineUrl={result.baseline.url} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function AttemptGroup({ category, attempts, baselineUrl }: { category: Bypass403Attempt['category']; attempts: Bypass403Attempt[]; baselineUrl: string }) {
  const bypassed = attempts.filter((a) => a.bypassed).length
  const [expanded, setExpanded] = useState(bypassed > 0)
  return (
    <div className={`rounded-lg border border-neutral-800 bg-neutral-900 ${bypassed > 0 ? 'border-l-4 border-l-red-500' : ''}`}>
      <button onClick={() => setExpanded((v) => !v)} className="flex w-full items-center gap-3 p-4 text-left">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-neutral-100">{CATEGORY_LABELS[category]}</p>
        </div>
        <span className={`shrink-0 text-xs ${bypassed > 0 ? 'font-semibold text-red-400' : 'text-neutral-500'}`}>
          {bypassed > 0 ? (category === 'archive' ? 'snapshot found / ' : `${bypassed} bypass${bypassed === 1 ? '' : 'es'} / `) : ''}
          {attempts.length} tried
        </span>
        <span className="shrink-0 text-xs text-neutral-600">{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded && (
        <div className="border-t border-neutral-800 px-4 py-2">
          <ul className="divide-y divide-neutral-900">
            {attempts.map((a) => (
              <AttemptRow key={a.id} attempt={a} baselineUrl={baselineUrl} />
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// attemptFullUrl resolves an attempt's literal request-target (path+query
// only -- see Bypass403Attempt.target's own doc comment) against the
// baseline's scheme+host, so the Tester gets an absolute URL to send. The
// archive category's target is already an absolute Wayback Machine URL.
function attemptFullUrl(attempt: Bypass403Attempt, baselineUrl: string): string {
  if (attempt.category === 'archive') return attempt.target
  try {
    return new URL(attempt.target, baselineUrl).href
  } catch {
    return attempt.target
  }
}

function AttemptRow({ attempt, baselineUrl }: { attempt: Bypass403Attempt; baselineUrl: string }) {
  const { openMenu } = useContextMenu()
  return (
    <li
      onContextMenu={(e) => {
        e.stopPropagation()
        openMenu(e, [
          { label: 'Copy request target', onSelect: () => copyToClipboard(attempt.target, 'Copied') },
          { label: 'Send to Tester', onSelect: () => sendToTester(attemptFullUrl(attempt, baselineUrl), attempt.method || 'GET', attempt.headers) },
        ])
      }}
      className="flex items-start gap-2 py-2 text-xs"
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          {attempt.bypassed && (
            <span className="rounded border border-red-700 bg-red-950/40 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-300">
              {attempt.category === 'archive' ? 'Snapshot found' : 'Bypassed'}
            </span>
          )}
          {attempt.category !== 'archive' && (
            <>
              <span className="font-mono text-neutral-300">{attempt.method}</span>
              <span className="break-all font-mono text-neutral-200">{attempt.target}</span>
            </>
          )}
          {attempt.category === 'archive' && attempt.bypassed && (
            <a href={attempt.target} target="_blank" rel="noreferrer" className="break-all font-mono text-sky-400 hover:text-sky-300">
              {attempt.target}
            </a>
          )}
        </div>
        <p className="mt-0.5 text-neutral-500">{attempt.description}</p>
        {attempt.headers && (
          <p className="mt-0.5 font-mono text-neutral-600">
            {Object.entries(attempt.headers)
              .map(([k, v]) => `${k}: ${v}`)
              .join('; ')}
          </p>
        )}
        {attempt.error && <p className="mt-0.5 text-red-400">{attempt.error}</p>}
        {attempt.category !== 'archive' && !attempt.error && (
          <p className="mt-0.5">
            <span className="font-mono" style={{ color: statusHexColor(attempt.statusCode) }}>
              {attempt.statusCode}
            </span>{' '}
            <span className="text-neutral-600">· {attempt.contentLength}b</span>
          </p>
        )}
      </div>
      {attempt.category !== 'archive' && <CopyButton text={attempt.target} />}
      <SendToTesterButton url={attemptFullUrl(attempt, baselineUrl)} method={attempt.method} headers={attempt.headers} />
    </li>
  )
}
