import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, watchDomainScan } from '../api'
import type {
  Credential,
  DomainScanFinding,
  DomainScanModuleResult,
  DomainScanResponse,
  Target,
} from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { BatchResultsPanel, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { CopyButton } from './CopyButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { SEVERITY_META, SEVERITY_ORDER } from '../severityColor'
import { sendToTester } from '../testerHandoff'
import { applyScanEvent, emptyProgress, finishProgress, type ScanProgress } from '../scanProgress'

// TestState/TargetScanState mirror Probe.tsx's own -- one registered
// module's place in a running scan, and one target's place in a (possibly
// multi-target) batch. See Probe.tsx for the full reasoning; kept
// identical here so the two tools feel like the same family of tool.

import { ScanErrorNotice } from './ScanErrorNotice'

interface TargetScanState {
  status: 'running' | 'done' | 'error'
  // progress is the run's live per-module state (see scanProgress.ts), shown
  // as a grid of squares on the target's card.
  progress?: ScanProgress
  result?: DomainScanResponse
  error?: string
}

// DomainScan is Aperture's "master" vulnerability/misconfiguration scanner
// (see internal/domainscan): unlike Probe, which checks individual paths on
// one already-known route, every module here is a whole external tool --
// retire.js first -- pointed at an entire domain. Each module crawls the
// site itself (there's no shared per-path client the way Probe's modules
// share one) before handing whatever it found to its tool, so a scan here
// can take noticeably longer than a Probe run against the same target.
export function DomainScan({
  caseId,
  targets,
  credentials,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [crawlDepth, setCrawlDepth] = useState(2)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('domainscan.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

  // Restores this case's most recent domain scan per target on mount/reload
  // -- see saveCaseScan in internal/api/handlers_domainscan.go. Every past
  // run is also browsable via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<DomainScanResponse>(caseId, 'domainscan').then((list) => {
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

  // runOneScan streams this target's domain scan into its card: each module's
  // start and finish arrive as progress events, and the full result is built
  // from the module events once the terminal "done" lands. Same pattern as
  // Probe.tsx's runOneScan.
  const runOneScan = async (targetValue: string) => {
    // Modules finish in whatever order their own crawl+tool run happens to
    // complete, streamed one at a time over this target's domain scan
    // WebSocket -- collected here and only turned into a result once the
    // terminal "done" event says every module has reported in.
    const collected: DomainScanModuleResult[] = []
    const patch = (fn: (cur: TargetScanState) => TargetScanState) =>
      setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: fn(prev[targetValue]) } : prev))
    let stopWatch: () => void = () => {}
    try {
      const { scanId } = await api.domainScan({
        target: toAbsoluteUrl(targetValue),
        credentialId,
        crawlDepth,
        caseId,
      })
      await new Promise<void>((resolve, reject) => {
        stopWatch = watchDomainScan(scanId, (ev) => {
          if (ev.type === 'domainModule' && ev.domainModule) {
            collected.push(ev.domainModule)
          } else if (ev.type === 'done') {
            if (ev.status === 'failed') {
              reject(new Error(ev.message || 'Domain scan failed'))
            } else if (ev.domainTarget) {
              const result: DomainScanResponse = { target: ev.domainTarget, modules: collected }
              patch((cur) => ({ ...cur, status: 'done', result, progress: finishProgress(cur.progress ?? emptyProgress()) }))
              resolve()
            } else {
              reject(new Error('Domain scan ended without a result'))
            }
            return
          }
          patch((cur) => ({ ...cur, progress: applyScanEvent(cur.progress ?? emptyProgress(), ev) }))
        })
      })
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
      patch((cur) => ({ ...cur, status: 'error', error: message }))
    } finally {
      stopWatch()
    }
  }

  const runLabel = runTargets.length > 1 ? `Run Domain Scan (${runTargets.length})` : 'Run Domain Scan'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Domain Scan"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Domain Scan</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Aperture's master vulnerability scanner: instead of checking one known path at a time (that's Probe), every
            module here crawls the whole domain itself and hands what it finds off to a real external scanner. First
            module: Retire.js, which flags known-vulnerable/outdated JavaScript libraries -- this crawls the site,
            downloads every script it references (same-origin or third-party CDN), and runs retire.js against the lot,
            since retire.js itself only knows how to scan a local folder, not a live site. Authorized testing only.
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
            One-off domains/URLs not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="target.htb, https://target.htb"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Crawl depth</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            How many hops of same-origin links each module's own crawl follows while discovering what to feed its tool.
          </span>
          <select value={crawlDepth} onChange={(e) => setCrawlDepth(Number(e.target.value))} className={`mt-1 ${inputBase}`}>
            <option value={0}>Just the homepage (+ its scripts)</option>
            <option value={1}>1 hop of same-origin links</option>
            <option value={2}>2 hops</option>
            <option value={3}>3 hops</option>
            <option value={4}>4 hops</option>
          </select>
        </label>

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <button
          onClick={runScan}
          disabled={!canRun}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {running ? 'Scanning…' : runLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'scan' ? (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more domains, then run.
              </div>
            )}

            {hasScans && (
              <BatchResultsPanel
                entries={Object.entries(scans)}
                getSummary={domainScanSummary}
                getProgress={(scan) => scan.progress}
                renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
              />
            )}
          </>
        ) : (
          <ScanHistoryPanel
            caseId={caseId}
            tool="domainscan"
            toState={(data: DomainScanResponse) => ({ status: 'done' as const, result: data })}
            getSummary={domainScanSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        )}
      </div>
    </div>
  )
}

// domainScanSummary is one target's one-line compact-view badge once a
// batch covers more than BatchResultsPanel's threshold -- same reasoning as
// Probe.tsx's probeScanSummary.
function domainScanSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger' }
  const modules = scan.result?.modules ?? []
  const total = modules.reduce((n, m) => n + m.findings.length, 0)
  if (total === 0) return { label: 'Clean', tone: 'clean' }
  const hasSevere = modules.some((m) => m.severity === 'critical' || m.severity === 'high')
  return { label: `${total} finding${total === 1 ? '' : 's'}`, tone: hasSevere ? 'danger' : 'warn' }
}

function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const totalFindings = (scan.result?.modules ?? []).reduce((n, m) => n + m.findings.length, 0)

  const sortedModules = useMemo(() => {
    const mods = scan.result?.modules ?? []
    return [...mods].sort((a, b) => a.name.localeCompare(b.name))
  }, [scan.result])

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="break-all font-mono text-sm text-neutral-200">{target}</span>
        <ScanStatusBadge status={scan.status} />
      </div>

      {scan.status === 'error' && <ScanErrorNotice message={scan.error} />}


      {scan.status === 'done' && scan.result && (
        <>
          <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
            <div className="flex flex-wrap gap-x-6 gap-y-1">
              <span>
                URL → <span className="font-mono text-neutral-200">{scan.result.target.url}</span>
              </span>
              <span>
                Hostname → <span className="text-neutral-200">{scan.result.target.hostname}</span>
              </span>
            </div>
          </div>

          {totalFindings === 0 ? (
            <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
              No vulnerabilities found across {scan.result.modules.length} module{scan.result.modules.length === 1 ? '' : 's'}.
            </div>
          ) : (
            <div className="space-y-3">
              {sortedModules.map((m) => (
                <ModuleCard key={m.id} module={m} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
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


function ModuleCard({ module }: { module: DomainScanModuleResult }) {
  const meta = SEVERITY_META[module.severity]
  const [expanded, setExpanded] = useState(module.findings.length > 0 || Boolean(module.error))

  // Findings are sorted worst-first -- unlike Probe's modules (one fixed
  // severity per module), a single module here (retire.js) can flag
  // everything from "low" to "critical" in the same run.
  const sortedFindings = useMemo(() => {
    const rank: Record<string, number> = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i]))
    return [...module.findings].sort((a, b) => (rank[a.severity] ?? 99) - (rank[b.severity] ?? 99))
  }, [module.findings])

  return (
    <div className={`rounded-lg border border-neutral-800 border-l-4 bg-neutral-900 ${meta.border}`}>
      <button onClick={() => setExpanded((v) => !v)} className="flex w-full items-center gap-3 p-4 text-left">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-neutral-100">{module.name}</p>
        </div>
        {module.findings.length > 0 && (
          <span className={`shrink-0 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${meta.badge}`}>{meta.label}</span>
        )}
        <span className="shrink-0 text-xs text-neutral-500">
          {module.error ? 'error' : `${module.findings.length} finding${module.findings.length === 1 ? '' : 's'}`}
        </span>
        <span className="shrink-0 text-xs text-neutral-600">{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded && (
        <div className="border-t border-neutral-800 px-4 py-2">
          {module.error ? (
            <p className="py-2 text-xs text-red-400">{module.error}</p>
          ) : module.findings.length === 0 ? (
            <p className="py-2 text-xs text-neutral-600">Checked, nothing found.</p>
          ) : (
            <ul className="divide-y divide-neutral-900">
              {sortedFindings.map((f, i) => (
                <FindingRow key={i} finding={f} />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

function FindingRow({ finding }: { finding: DomainScanFinding }) {
  const [expanded, setExpanded] = useState(false)
  const hasExpandable = Boolean(finding.evidence || finding.url)
  const meta = SEVERITY_META[finding.severity]

  return (
    <li className="py-2 text-xs">
      <div
        onClick={() => hasExpandable && setExpanded((v) => !v)}
        className={`flex items-start gap-2 ${hasExpandable ? 'cursor-pointer' : ''}`}
      >
        {hasExpandable && <span className="mt-0.5 shrink-0 text-neutral-600">{expanded ? '▾' : '▸'}</span>}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${meta.badge}`}>
              {meta.label}
            </span>
            <p className="break-all text-neutral-300">{finding.label}</p>
          </div>
          {finding.detail && <p className="mt-0.5 text-neutral-600">{finding.detail}</p>}
        </div>
        {finding.url && (
          <span onClick={(e) => e.stopPropagation()}>
            <CopyButton text={finding.url} />
          </span>
        )}
      </div>

      {expanded && (
        <div className="ml-4 mt-1.5 space-y-1.5 rounded border border-neutral-800 bg-neutral-950 p-2">
          {finding.evidence && (
            <div className="flex items-start gap-2">
              <span className="mt-0.5 shrink-0 text-[10px] uppercase tracking-wide text-neutral-600">Component</span>
              <code className="min-w-0 flex-1 break-all text-[11px] text-amber-300">{finding.evidence}</code>
            </div>
          )}
          {finding.url && (
            <p className="break-all text-[11px] text-neutral-500">
              <span className="text-neutral-600">Source — </span>
              <a href={finding.url} target="_blank" rel="noreferrer" className="text-sky-400 hover:text-sky-300">
                {finding.url}
              </a>
            </p>
          )}
          {finding.url && (
            <button
              onClick={() => sendToTester(finding.url!)}
              className="rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
            >
              Send to Tester
            </button>
          )}
        </div>
      )}
    </li>
  )
}
