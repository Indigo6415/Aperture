import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { Credential, GitDumpResponse, GitDumpTarget, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { BatchResultsPanel, stoppedSummary, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { emptyProgress, runTrackedScan, type TrackedScan, runBatch, stopTrackedScan, useScanBatch, stopAllScans } from '../scanProgress'
import { indicatorOfScans, useReportScanIndicator } from '../scanIndicator'
import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'

type TargetScanState = TrackedScan<GitDumpResponse>

// GitDump is Aperture's front end for the git exposure dumper (see
// internal/gitdump). Each target is checked for a publicly served .git
// directory. If one is found, its objects are downloaded, the HEAD working
// tree is restored, and the result is zipped for download. Each target runs as its
// own card, same batch pattern as 403 Bypass, so a single target can be
// stopped or retried without touching the rest.
export function GitDump({ caseId, targets, credentials }: { caseId: string; targets: Target[]; credentials: Credential[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [view, setView] = useState<'scan' | 'history'>('scan')

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('gitdump.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

  // Restores this case's most recent git dump per target on mount/reload. See
  // saveCaseScan for the tool "gitdump" in internal/api/handlers_scans.go.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<GitDumpResponse>(caseId, 'gitdump').then((list) => {
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

  // Targets are split on commas and newlines so a batch can be pasted in as a list.
  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])

  const running = Object.values(scans).some((s) => s.status === 'running')
  // Publishes this tab's scan state to the case nav's border.
  useReportScanIndicator('gitdump', indicatorOfScans(scans, () => []))
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

  // retryScan restarts one failed target in place; the other targets keep their results.
  const retryScan = (targetValue: string) => {
    setScans((prev) => ({ ...prev, [targetValue]: { status: 'running' as const, progress: emptyProgress() } }))
    void runOneScan(targetValue, batch.current())
  }

  const runOneScan = (targetValue: string, signal?: AbortSignal) =>
    runTrackedScan<GitDumpResponse>(
      () => api.gitDump({ requestsPerSecond: speed.rps ?? undefined, targets: [targetValue], credentialId, caseId }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
      signal,
    )

  const stopAll = () => {
    batch.stop()
    setScans((prev) => stopAllScans(prev))
  }

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Git Dump"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Git Dump</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Checks each target for a publicly served <span className="font-mono">.git</span> directory. When one is
            exposed, its commit history and objects are downloaded and the HEAD working tree is restored, so the source
            can be browsed or downloaded as a zip. Bare hosts are tried over https, then http. Authorized testing only.
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
            One-off URLs or hosts not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder={'https://target.htb/app\nexample.com'}
            rows={3}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        {speed.control}

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

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
            tool="gitdump"
            toState={(data: GitDumpResponse) => ({ status: 'done' as const, result: data })}
            getSummary={gitDumpSummary}
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
                getSummary={gitDumpSummary}
                getProgress={(scan) => scan.progress}
                onRetry={retryScan}
                onStop={stopScan}
                onStopAll={stopAll}
                renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

// gitDumpSummary is one target's one-line badge in the compact batch view. A
// target counts as exposed when any of its result rows is.
function gitDumpSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
  const rows = scan.result?.targets ?? []
  const exposed = rows.filter((r) => r.exposed)
  if (exposed.length === 0) return { label: 'Not exposed', tone: 'clean' }
  const files = exposed.reduce((n, r) => n + r.files, 0)
  return { label: `Exposed · ${files} file${files === 1 ? '' : 's'}`, tone: 'danger' }
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

// TargetScanCard shows one target's run. A run normally holds a single result
// row, but a restored history entry can hold one row per target in its batch,
// so every row is rendered.
function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const rows = scan.result?.targets ?? []
  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="break-all font-mono text-sm text-neutral-200">{target}</span>
        <ScanStatusBadge status={scan.status} />
      </div>

      {scan.status === 'error' && <ScanErrorNotice message={scan.error} />}

      {scan.status === 'done' && rows.map((row, i) => <GitDumpRow key={`${row.input}-${i}`} row={row} />)}
    </div>
  )
}

// formatSize renders a byte count the way a file browser would.
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// GitDumpRow is one target's result: whether .git was exposed and, if so, what
// was recovered and where the zip of it can be downloaded.
function GitDumpRow({ row }: { row: GitDumpTarget }) {
  if (!row.exposed) {
    return (
      <div className="space-y-2">
        {row.error && <ScanErrorNotice message={row.error} />}
        <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
          No exposed <span className="font-mono">.git</span> found at <span className="break-all font-mono">{row.baseUrl}</span>. Nothing was dumped.
        </div>
      </div>
    )
  }

  const stats: [string, string | number][] = [
    ['Files restored', row.files],
    ['Objects', row.objects],
    ['Packs', row.packs],
    ['Refs', row.refs],
    ['Missing objects', row.missingObjects],
  ]

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 border-l-4 border-l-red-500 bg-neutral-900 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded border border-red-700 bg-red-950/40 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-300">
          .git exposed
        </span>
        <span className="break-all font-mono text-xs text-neutral-300">{row.baseUrl}{row.gitPath ?? '.git/'}</span>
        {row.gitPath && row.gitPath !== '.git/' && (
          <span className="rounded border border-amber-700 bg-amber-950/40 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300">
            Outlier path
          </span>
        )}
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
        {stats.map(([label, value]) => (
          <div key={label}>
            <dt className="text-neutral-500">{label}</dt>
            <dd className={`font-mono ${label === 'Missing objects' && Number(value) > 0 ? 'text-amber-300' : 'text-neutral-200'}`}>{value}</dd>
          </div>
        ))}
        {row.headRef && (
          <div>
            <dt className="text-neutral-500">HEAD</dt>
            <dd className="break-all font-mono text-neutral-200">{row.headRef}</dd>
          </div>
        )}
        {row.restoredFrom && (
          <div>
            <dt className="text-neutral-500">Working tree from</dt>
            <dd className="font-mono text-neutral-200">{row.restoredFrom === 'index' ? 'index (no HEAD commit)' : row.restoredFrom}</dd>
          </div>
        )}
      </dl>

      <div className="flex flex-wrap items-center gap-3">
        {row.bucketId && (
          <a
            href={`/api/gitdump/buckets/${row.bucketId}/download`}
            className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500"
          >
            Download {row.host}.zip{row.zipBytes ? ` (${formatSize(row.zipBytes)})` : ''}
          </a>
        )}
        {row.error && <span className="text-xs text-amber-300">{row.error}</span>}
      </div>

      {row.warnings && row.warnings.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer text-neutral-500">
            {row.warnings.length} warning{row.warnings.length === 1 ? '' : 's'}
          </summary>
          <ul className="mt-2 list-inside list-disc space-y-0.5 font-mono text-neutral-500">
            {row.warnings.map((w, i) => (
              <li key={i} className="break-all">
                {w}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
