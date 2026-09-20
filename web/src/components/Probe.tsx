import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, watchProbeScan } from '../api'
import type { ProbeRequest } from '../probeHandoff'
import type { Credential, JobOptionsPreset, ProbeFinding, ProbeModuleInfo, ProbeModuleResult, ProbeScanResponse, ProbeSeverity, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { SEVERITY_META, SEVERITY_ORDER } from '../severityColor'
import { JOB_PRESETS } from '../presets'
import { CopyButton } from './CopyButton'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToRepeater } from '../repeaterHandoff'

// TestState is one check module's place in a running scan -- grey (not
// running yet), orange (in flight), or green (finished) -- see ProbeTestList
// below.
type TestState = 'idle' | 'running' | 'done'

// TargetScanState is one target's place in a (possibly multi-target) probe
// run: its own test-progress map and, once finished, its own result --
// independent of every other target running alongside it.
interface TargetScanState {
  status: 'running' | 'done' | 'error'
  testStatus: Record<string, TestState>
  result?: ProbeScanResponse
  error?: string
}

export function Probe({
  caseId,
  targets,
  credentials,
  prefill,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  prefill?: ProbeRequest
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [modules, setModules] = useState<ProbeModuleInfo[]>([])
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [preset, setPreset] = useState<JobOptionsPreset>('custom')
  const [credentialId, setCredentialId] = useState<string | undefined>()

  const hasScans = Object.keys(scans).length > 0
  // Same collapse-on-first-result pattern as JwtScan.tsx -- see
  // collapsible.ts and CollapsibleFormPanel.tsx.
  const [formOpen, setFormOpen] = useCollapsible('probe.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

  // Applies a "Send to Probe" handoff (see probeHandoff.ts) even though this
  // component stays mounted the whole time the case is open -- keyed on
  // prefill.seq so sending the same target twice in a row still re-applies
  // it instead of being a no-op dependency change.
  useEffect(() => {
    if (prefill) setManualTarget(prefill.target)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.seq])

  // The module list is static (every registered check, unaffected by the
  // target) so it's fetched once and used to render every test grey before
  // a scan ever starts.
  useEffect(() => {
    api.listProbeModules().then(setModules).catch(() => {})
  }, [])

  // manualTargets splits the free-text field on commas/newlines, matching
  // the Targets tab's "paste a list" convention -- lets a batch be typed or
  // pasted in one go instead of one target at a time.
  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])

  const running = Object.values(scans).some((s) => s.status === 'running')
  const canRun = runTargets.length > 0 && !running

  // runScan kicks off one independent scan per target in runTargets --
  // each streams its own progress and finishes on its own schedule, so a
  // slow target doesn't hold up the others' results from appearing.
  const runScan = () => {
    if (!canRun) return
    const list = runTargets
    const initialTestStatus = Object.fromEntries(modules.map((m) => [m.id, 'running' as TestState]))
    setScans(Object.fromEntries(list.map((t) => [t, { status: 'running' as const, testStatus: { ...initialTestStatus } }])))
    for (const t of list) runOneScan(t)
  }

  const runOneScan = async (targetValue: string) => {
    // Modules finish in whatever order their HTTP checks happen to
    // complete, streamed one at a time over this target's probe scan
    // WebSocket (see runProbeScan in internal/api) -- collected here and
    // only turned into a result once the terminal "done" event says every
    // module has reported in.
    const collected: ProbeModuleResult[] = []
    let stopWatch: () => void = () => {}
    try {
      const { scanId } = await api.probeScan({
        target: targetValue,
        preset: preset === 'custom' ? undefined : preset,
        credentialId,
        caseId,
      })
      await new Promise<void>((resolve, reject) => {
        stopWatch = watchProbeScan(scanId, (ev) => {
          if (ev.type === 'module' && ev.module) {
            const mod = ev.module
            collected.push(mod)
            setScans((prev) => {
              const cur = prev[targetValue]
              if (!cur) return prev
              return { ...prev, [targetValue]: { ...cur, testStatus: { ...cur.testStatus, [mod.id]: 'done' } } }
            })
          } else if (ev.type === 'done') {
            if (ev.status === 'failed') {
              reject(new Error(ev.message || 'Probe scan failed'))
            } else if (ev.probeTarget && ev.probeHealth) {
              const result: ProbeScanResponse = { target: ev.probeTarget, health: ev.probeHealth, modules: collected }
              setScans((prev) => ({ ...prev, [targetValue]: { ...prev[targetValue], status: 'done', result } }))
              resolve()
            } else {
              reject(new Error('Probe scan ended without a result'))
            }
          }
        })
      })
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
      setScans((prev) => ({ ...prev, [targetValue]: { ...prev[targetValue], status: 'error', error: message } }))
    } finally {
      stopWatch()
    }
  }

  const runLabel = runTargets.length > 1 ? `Run Probe (${runTargets.length})` : 'Run Probe'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Probe"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Probe</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Scans a URL, hostname, or IP for common web server misconfigurations -- exposed .git/.svn, sensitive files, open admin
            panels, dev artifacts, API endpoints, WordPress/Flask/Django issues, TLS problems, and injection points (SQLi, path
            traversal, SSTI). Runs against as many targets at once as you select. Authorized testing only.
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
            One-off URLs/hosts not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="target.htb, 10.10.10.10, https://target.htb:8443"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-neutral-300">Intensity</span>
          {JOB_PRESETS.map((p) => (
            <button
              key={p.id}
              type="button"
              title={p.description}
              onClick={() => setPreset(p.id)}
              className={`rounded border px-2 py-0.5 text-xs ${
                preset === p.id ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>
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
        {!hasScans && (
          <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
            Select or type one or more targets, then run.
          </div>
        )}

        {Object.entries(scans).map(([t, scan]) => (
          <TargetScanCard key={t} target={t} scan={scan} modules={modules} />
        ))}
      </div>
    </div>
  )
}

// TargetScanCard is one target's whole scan lifecycle in a batch run: its
// header (target + status badge), the live test list while running, and
// its own findings once done -- everything Probe used to render globally
// for the single current target, now scoped per target.
function TargetScanCard({ target, scan, modules }: { target: string; scan: TargetScanState; modules: ProbeModuleInfo[] }) {
  const severityCounts = useMemo(() => {
    const c: Record<ProbeSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const m of scan.result?.modules ?? []) c[m.severity] += m.findings.length
    return c
  }, [scan.result])

  const sortedModules = useMemo(() => {
    const mods = scan.result?.modules ?? []
    const rank: Record<ProbeSeverity, number> = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i])) as Record<ProbeSeverity, number>
    return [...mods].sort((a, b) => rank[a.severity] - rank[b.severity] || a.name.localeCompare(b.name))
  }, [scan.result])

  const totalFindings = (scan.result?.modules ?? []).reduce((n, m) => n + m.findings.length, 0)

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="font-mono text-sm text-neutral-200">{target}</span>
        <ScanStatusBadge status={scan.status} />
      </div>

      {scan.status === 'error' && (
        <div className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-xs text-red-300">{scan.error}</div>
      )}

      {scan.status === 'running' && <ProbeTestList modules={modules} status={scan.testStatus} loading />}

      {scan.status === 'done' && scan.result && (
        <>
          <TargetSummaryCard result={scan.result} />

          <div className="grid grid-cols-5 gap-2">
            {SEVERITY_ORDER.map((sev) => (
              <SeverityTile key={sev} severity={sev} value={severityCounts[sev]} />
            ))}
          </div>

          {totalFindings === 0 ? (
            <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
              No misconfigurations found across {scan.result.modules.length} module{scan.result.modules.length === 1 ? '' : 's'}.
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

// ProbeTestList shows every registered check module as a small pill --
// grey while idle, orange while the scan has it in flight, green once it's
// reported back. Once a scan finishes, the caller stops rendering this in
// favor of the findings themselves.
function ProbeTestList({ modules, status, loading }: { modules: ProbeModuleInfo[]; status: Record<string, TestState>; loading: boolean }) {
  if (modules.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
        Results will appear here once you run a scan.
      </div>
    )
  }
  const doneCount = modules.filter((m) => status[m.id] === 'done').length
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Tests</h2>
        {loading ? (
          <span className="text-xs text-neutral-500">
            {doneCount} / {modules.length} finished
          </span>
        ) : (
          <span className="text-xs text-neutral-600">Run a scan to see progress</span>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {modules.map((m) => (
          <TestPill key={m.id} name={m.name} state={status[m.id] ?? 'idle'} />
        ))}
      </div>
    </div>
  )
}

const TEST_STATE_STYLES: Record<TestState, { pill: string; dot: string }> = {
  idle: { pill: 'border-neutral-700 bg-neutral-950 text-neutral-500', dot: 'bg-neutral-600' },
  running: { pill: 'border-amber-700 bg-amber-950/40 text-amber-300', dot: 'bg-amber-400 animate-pulse' },
  done: { pill: 'border-emerald-700 bg-emerald-950/40 text-emerald-300', dot: 'bg-emerald-400' },
}

function TestPill({ name, state }: { name: string; state: TestState }) {
  const styles = TEST_STATE_STYLES[state]
  return (
    <span className={`flex items-center gap-1.5 rounded border px-2 py-1 text-xs ${styles.pill}`}>
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${styles.dot}`} />
      {name}
    </span>
  )
}

function TargetSummaryCard({ result }: { result: ProbeScanResponse }) {
  const { target, health } = result
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
      <div className="flex flex-wrap gap-x-6 gap-y-1">
        <span>
          URL → <span className="font-mono text-neutral-200">{target.url}</span>
        </span>
        <span>
          Hostname → <span className="text-neutral-200">{target.hostname}</span>
        </span>
        <span>
          IP → <span className="text-neutral-200">{target.ip || 'unresolved'}</span>
        </span>
        <span>
          Port → <span className="text-neutral-200">{target.port}</span>
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        <HealthDot label="TCP" up={health.tcp} />
        <HealthDot label="HTTP" up={health.http} />
        <HealthDot label="HTTPS" up={health.https} />
      </div>
    </div>
  )
}

function HealthDot({ label, up }: { label: string; up: boolean }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: up ? '#34d399' : '#f87171' }} />
      <span className={up ? 'text-neutral-300' : 'text-neutral-600'}>{label}</span>
    </span>
  )
}

function SeverityTile({ severity, value }: { severity: ProbeSeverity; value: number }) {
  const meta = SEVERITY_META[severity]
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-center">
      <p className={`text-2xl font-semibold ${meta.text}`}>{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-neutral-500">{meta.label}</p>
    </div>
  )
}

function ModuleCard({ module }: { module: ProbeModuleResult }) {
  const meta = SEVERITY_META[module.severity]
  const [expanded, setExpanded] = useState(module.findings.length > 0)

  return (
    <div className={`rounded-lg border border-neutral-800 border-l-4 bg-neutral-900 ${meta.border}`}>
      <button onClick={() => setExpanded((v) => !v)} className="flex w-full items-center gap-3 p-4 text-left">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-neutral-100">{module.name}</p>
        </div>
        <span className={`shrink-0 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${meta.badge}`}>{meta.label}</span>
        <span className="shrink-0 text-xs text-neutral-500">
          {module.findings.length} finding{module.findings.length === 1 ? '' : 's'}
        </span>
        <span className="shrink-0 text-xs text-neutral-600">{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded && (
        <div className="border-t border-neutral-800 px-4 py-2">
          {module.findings.length === 0 ? (
            <p className="py-2 text-xs text-neutral-600">Checked, nothing found.</p>
          ) : (
            <ul className="divide-y divide-neutral-900">
              {module.findings.map((f, i) => (
                <FindingRow key={i} finding={f} />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

// FindingRow shows a finding's one-line summary (and its short, always-on
// Detail line, same as before) plus -- when the backend sent any -- a
// toggleable "how it was found" panel: the exact request (Method +
// StatusCode) and the exact matched content (Evidence, e.g. a leaked key's
// actual value or a SQL error string), not just which check fired.
function FindingRow({ finding }: { finding: ProbeFinding }) {
  const { openMenu } = useContextMenu()
  const [expanded, setExpanded] = useState(false)
  const hasExpandable = Boolean(finding.evidence || finding.method || finding.statusCode !== undefined || finding.url)

  return (
    <li
      onContextMenu={(e) => {
        if (!finding.url) return
        e.stopPropagation()
        openMenu(e, [
          { label: 'Copy URL', onSelect: () => copyToClipboard(finding.url!, 'Copied URL') },
          { label: 'Send to Repeater', onSelect: () => sendToRepeater(finding.url!, finding.method || 'GET') },
        ])
      }}
      className="py-2 text-xs"
    >
      <div
        onClick={() => hasExpandable && setExpanded((v) => !v)}
        className={`flex items-start gap-2 ${hasExpandable ? 'cursor-pointer' : ''}`}
      >
        {hasExpandable && <span className="mt-0.5 shrink-0 text-neutral-600">{expanded ? '▾' : '▸'}</span>}
        <div className="min-w-0 flex-1">
          <p className="break-all text-neutral-300">{finding.label}</p>
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
              <span className="mt-0.5 shrink-0 text-[10px] uppercase tracking-wide text-neutral-600">Found</span>
              <code className="min-w-0 flex-1 break-all text-[11px] text-amber-300">{finding.evidence}</code>
              <span onClick={(e) => e.stopPropagation()}>
                <CopyButton text={finding.evidence} />
              </span>
            </div>
          )}
          {(finding.method || finding.statusCode !== undefined) && (
            <p className="text-[11px] text-neutral-500">
              <span className="text-neutral-600">Request — </span>
              {finding.method}
              {finding.method && finding.statusCode !== undefined ? ' → HTTP ' : finding.statusCode !== undefined ? 'HTTP ' : ''}
              {finding.statusCode}
            </p>
          )}
          {finding.url && (
            <p className="break-all text-[11px] text-neutral-500">
              <span className="text-neutral-600">URL — </span>
              {finding.url}
            </p>
          )}
        </div>
      )}
    </li>
  )
}
