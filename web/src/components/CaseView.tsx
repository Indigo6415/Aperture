import { useEffect, useRef, useState } from 'react'
import { api, watchJob } from '../api'
import type { Case, Check, CheckKind, Finding, Job, JobOptions, JobOptionsPreset, NodeStatus, RunStatus, Target, Tool } from '../types'
import { statusHexColor } from '../statusColor'
import { estimateEtaSeconds } from '../eta'
import { ResultsTable } from './ResultsTable'
import { TargetProgressPanel, type TargetProgress } from './TargetProgressPanel'
import { GraphView } from './GraphView'
import { TechTable } from './TechTable'
import { JwtScan } from './JwtScan'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { showToast } from '../toast'
import { sendToJwtScanner, onJwtScannerRequest, type JwtScannerRequest } from '../jwtHandoff'

const CHECK_LABELS: Record<CheckKind, string> = {
  dns: 'DNS',
  tls: 'TLS',
  http: 'HTTP',
  subdomains: 'Subdomains',
  'subdomains-verified': 'Verified subdomains',
  whois: 'WHOIS',
  takeover: 'Takeover',
  dnsdumpster: 'DNSDumpster',
  technologies: 'Technologies',
}

const STATUS_DOT: Record<Check['status'] | 'pending', string> = {
  pending: '#6b7280',
  running: '#facc15',
  done: '#34d399',
  error: '#f87171',
}

function keyFor(target: string, kind: CheckKind): string {
  return `${target}::${kind}`
}

type Tab = 'targets' | 'identify' | 'feroxbuster' | 'ffuf-subdomain' | 'ffuf-vhost' | 'graph' | 'jwtscan'

const TABS: { id: Tab; label: string }[] = [
  { id: 'targets', label: 'Targets' },
  { id: 'identify', label: 'Identify' },
  { id: 'feroxbuster', label: 'Feroxbuster' },
  { id: 'ffuf-subdomain', label: 'FFuF Subdomain' },
  { id: 'ffuf-vhost', label: 'FFuF VHost' },
  { id: 'jwtscan', label: 'JWT Scanner' },
  { id: 'graph', label: 'Graph' },
]

// CaseView is one case's workspace: a left navbar switching between Targets,
// Identify, each scanning tool, and the Graph, each rendered as its own tab
// so the user can see how each tool is doing independently. Every tool tab
// only ever runs when the user launches it from that tab's JobLauncher --
// nothing here starts anything on its own.
export function CaseView({ caseId }: { caseId: string }) {
  const [c, setCase] = useState<Case | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [checks, setChecks] = useState<Record<string, Check>>({})
  const [runFindings, setRunFindings] = useState<Record<string, Finding[]>>({}) // keyed by jobId
  const [jobStatus, setJobStatus] = useState<Record<string, RunStatus>>({}) // keyed by jobId, overrides job.status once live events arrive
  // Keyed by `${jobId}:${nodeId}` since one job can have several source
  // nodes (one per target).
  const [jobProgress, setJobProgress] = useState<Record<string, { done: number; total: number }>>({})
  const [nodeStatus, setNodeStatus] = useState<Record<string, NodeStatus>>({})
  const nodeStartedAtRef = useRef<Record<string, number>>({})
  const [tab, setTab] = useState<Tab>('targets')
  const [reportFormat, setReportFormat] = useState<'json' | 'html' | 'pdf'>('html')
  // Set by a "Send to JWT Scanner" context-menu item anywhere in this case
  // (Targets list, tool results, graph/hierarchy nodes -- see
  // jwtHandoff.ts); JwtScan applies it even though it stays mounted the
  // whole time this case is open.
  const [jwtPrefill, setJwtPrefill] = useState<JwtScannerRequest | undefined>()

  // Only one case is ever open at a time, so this subscription always
  // targets whichever case is currently visible -- no need to key it by
  // caseId or re-subscribe when the user switches cases.
  useEffect(() => {
    return onJwtScannerRequest((req) => {
      setJwtPrefill(req)
      setTab('jwtscan')
    })
  }, [])

  const stopJobWatches = useRef<Record<string, () => void>>({})

  const watchTheJob = (job: Job) => {
    if (stopJobWatches.current[job.id]) return // already watching
    if (job.runId) {
      api.listFindings(job.runId).then((all) => setRunFindings((prev) => ({ ...prev, [job.id]: all })))
    }
    stopJobWatches.current[job.id] = watchJob(job.id, (ev) => {
      if (ev.type === 'finding' && ev.finding) {
        const finding = ev.finding
        setRunFindings((prev) => ({ ...prev, [job.id]: [...(prev[job.id] ?? []), finding] }))
      } else if (ev.type === 'progress' && ev.nodeId) {
        const key = `${job.id}:${ev.nodeId}`
        if (!nodeStartedAtRef.current[key]) nodeStartedAtRef.current[key] = Date.now()
        setJobProgress((prev) => ({ ...prev, [key]: { done: ev.done ?? 0, total: ev.total ?? 0 } }))
      } else if (ev.type === 'status' && ev.nodeId && ev.status) {
        const key = `${job.id}:${ev.nodeId}`
        if (ev.status === 'running' && !nodeStartedAtRef.current[key]) nodeStartedAtRef.current[key] = Date.now()
        setNodeStatus((prev) => ({ ...prev, [key]: ev.status! }))
      } else if (ev.type === 'check' && ev.check) {
        const check = ev.check
        setChecks((prev) => ({ ...prev, [keyFor(check.domain, check.kind)]: check }))
      } else if (ev.type === 'done') {
        setJobStatus((prev) => ({
          ...prev,
          [job.id]: ev.status === 'failed' ? 'failed' : ev.status === 'cancelled' ? 'cancelled' : 'succeeded',
        }))
      }
    })
  }

  useEffect(() => {
    let cancelled = false
    setCase(null)
    setTargets([])
    setJobs([])
    setChecks({})
    setRunFindings({})
    setJobStatus({})
    setJobProgress({})
    setNodeStatus({})
    nodeStartedAtRef.current = {}
    setTab('targets')
    Object.values(stopJobWatches.current).forEach((stop) => stop())
    stopJobWatches.current = {}

    api.getCase(caseId).then((full) => {
      if (!cancelled) setCase(full)
    })
    api.listTargets(caseId).then((t) => {
      if (!cancelled) setTargets(t)
    })
    api.listCaseChecks(caseId).then((list) => {
      if (cancelled) return
      const byKey: Record<string, Check> = {}
      for (const chk of list) byKey[keyFor(chk.domain, chk.kind)] = chk
      setChecks(byKey)
    })
    api.listJobs(caseId).then((js) => {
      if (cancelled) return
      setJobs(js)
      for (const j of js) watchTheJob(j)
    })

    return () => {
      cancelled = true
      Object.values(stopJobWatches.current).forEach((stop) => stop())
      stopJobWatches.current = {}
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId])

  const refreshTargets = () => {
    api.listTargets(caseId).then(setTargets)
  }

  const addJob = (job: Job) => {
    setJobs((prev) => [...prev, job])
    watchTheJob(job)
  }

  const statusOf = (job: Job): RunStatus => jobStatus[job.id] ?? job.status
  const jobsOfTool = (tool: Tool) => jobs.filter((j) => j.tool === tool)

  const findingsOfTool = (tool: Tool): Finding[] => {
    const byKey = new Map<string, Finding>()
    for (const job of jobsOfTool(tool)) {
      for (const f of runFindings[job.id] ?? []) byKey.set(`${f.url}|${f.statusCode}`, f)
    }
    return [...byKey.values()]
  }

  const cancelJob = async (job: Job) => {
    try {
      await api.cancelJob(job.id)
      showToast('Cancelling…', 'info')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  const promoteFromTool = async (tool: Tool, values: string[]) => {
    const latest = [...jobsOfTool(tool)].pop()
    if (!latest) return
    try {
      await api.promoteTargets(caseId, latest.id, values)
      showToast(`Saved ${values.length} target${values.length === 1 ? '' : 's'} to the case`, 'success')
      refreshTargets()
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  if (!c) {
    return <div className="p-8 text-neutral-500">Loading…</div>
  }

  const runningJobs = jobs.filter((j) => statusOf(j) === 'running')
  const dots: Record<Tab, string> = {
    targets: STATUS_DOT.done,
    identify: jobsOfTool('identify').length === 0 ? STATUS_DOT.pending : jobsOfTool('identify').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    feroxbuster: jobsOfTool('feroxbuster').length === 0 ? STATUS_DOT.pending : jobsOfTool('feroxbuster').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    'ffuf-subdomain':
      jobsOfTool('ffuf-subdomain').length === 0 ? STATUS_DOT.pending : jobsOfTool('ffuf-subdomain').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    'ffuf-vhost': jobsOfTool('ffuf-vhost').length === 0 ? STATUS_DOT.pending : jobsOfTool('ffuf-vhost').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    graph: STATUS_DOT.done,
    jwtscan: STATUS_DOT.done,
  }
  const counts: Record<Tab, number | null> = {
    targets: targets.length,
    identify: null,
    feroxbuster: findingsOfTool('feroxbuster').length,
    'ffuf-subdomain': findingsOfTool('ffuf-subdomain').length,
    'ffuf-vhost': findingsOfTool('ffuf-vhost').length,
    graph: null,
    jwtscan: null,
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-3 border-b border-neutral-800 bg-neutral-950 px-4 py-2">
        <h1 className="text-sm font-medium text-neutral-100">{c.name}</h1>
        {c.description && <span className="truncate text-xs text-neutral-500">{c.description}</span>}
        <span className="text-xs text-neutral-500">{new Date(c.createdAt).toLocaleString()}</span>
        {runningJobs.length > 0 && (
          <span className="rounded-full bg-amber-900/40 px-2 py-0.5 text-xs text-amber-400">
            {runningJobs.length} job{runningJobs.length === 1 ? '' : 's'} running
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <select
            value={reportFormat}
            onChange={(e) => setReportFormat(e.target.value as 'json' | 'html' | 'pdf')}
            className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-1 text-xs text-neutral-300 outline-none focus:border-sky-500"
          >
            <option value="html">HTML</option>
            <option value="pdf">PDF</option>
            <option value="json">JSON</option>
          </select>
          <a
            href={api.reportUrl(caseId, reportFormat)}
            className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:border-sky-500 hover:text-sky-400"
          >
            Download report
          </a>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className="w-48 shrink-0 space-y-0.5 overflow-y-auto border-r border-neutral-800 bg-neutral-950 p-2">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm ${
                tab === t.id ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200'
              }`}
            >
              <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: dots[t.id] }} />
              <span className="flex-1">{t.label}</span>
              {counts[t.id] !== null && <span className="text-xs text-neutral-500">{counts[t.id]}</span>}
            </button>
          ))}
        </aside>

        {/* Every tab stays mounted (toggled via `hidden`, not conditional
            rendering) so switching tabs to peek at another tool doesn't
            reset a results table's row selection right before you meant to
            click "Save selected to case". */}
        <div className="flex-1 overflow-hidden">
          <div className={`h-full ${tab === 'targets' ? '' : 'hidden'}`}>
            <TargetsTab caseId={caseId} targets={targets} onChange={refreshTargets} />
          </div>

          <div className={`h-full ${tab === 'identify' ? '' : 'hidden'}`}>
            <IdentifyTab
              caseId={caseId}
              targets={targets}
              jobs={jobsOfTool('identify')}
              statusOf={statusOf}
              checks={checks}
              onStart={addJob}
              onCancel={cancelJob}
              onTargetsChanged={refreshTargets}
            />
          </div>

          <div className={`h-full ${tab === 'feroxbuster' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="feroxbuster"
              targets={targets}
              jobs={jobsOfTool('feroxbuster')}
              findings={findingsOfTool('feroxbuster')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('feroxbuster', values)}
              deriveTargetValue={(f) => f.url}
              schemeField
              recursiveField
            />
          </div>

          <div className={`h-full ${tab === 'ffuf-subdomain' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="ffuf-subdomain"
              targets={targets}
              jobs={jobsOfTool('ffuf-subdomain')}
              findings={findingsOfTool('ffuf-subdomain')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('ffuf-subdomain', values)}
              schemeField
            />
          </div>

          <div className={`h-full ${tab === 'ffuf-vhost' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="ffuf-vhost"
              targets={targets}
              jobs={jobsOfTool('ffuf-vhost')}
              findings={findingsOfTool('ffuf-vhost')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('ffuf-vhost', values)}
              schemeField
              hostSuffixField
            />
          </div>

          <div className={`h-full ${tab === 'graph' ? '' : 'hidden'}`}>
            <GraphView caseId={caseId} />
          </div>

          <div className={`h-full overflow-y-auto ${tab === 'jwtscan' ? '' : 'hidden'}`}>
            <JwtScan prefill={jwtPrefill} />
          </div>
        </div>
      </div>
    </div>
  )
}

// --- Targets tab ---

function TargetsTab({ caseId, targets, onChange }: { caseId: string; targets: Target[]; onChange: () => void }) {
  const { openMenu } = useContextMenu()
  const [value, setValue] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')

  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = value.trim()
    if (!trimmed) return
    setAdding(true)
    setError('')
    try {
      await api.addTarget(caseId, trimmed)
      setValue('')
      onChange()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setAdding(false)
    }
  }

  const remove = async (t: Target) => {
    try {
      await api.deleteTarget(t.id)
      onChange()
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-4 px-4 py-6">
      <form onSubmit={add} className="flex gap-2">
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="example.com, sub.example.com, 10.0.0.1, https://example.com/api …"
          className="flex-1 rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 outline-none focus:border-sky-500"
        />
        <button
          type="submit"
          disabled={adding || !value.trim()}
          className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          {adding ? 'Adding…' : 'Add target'}
        </button>
      </form>
      {error && <p className="text-sm text-red-400">{error}</p>}

      <div className="rounded-lg border border-neutral-800">
        <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Targets</h2>
          <span className="text-xs text-neutral-600">{targets.length}</span>
        </div>
        {targets.length === 0 ? (
          <p className="px-3 py-8 text-center text-xs text-neutral-600">
            No targets yet — add one above, or run a tool and save some of its results.
          </p>
        ) : (
          <div className="divide-y divide-neutral-900">
            {targets.map((t) => (
              <div
                key={t.id}
                onContextMenu={(e) => {
                  e.stopPropagation()
                  openMenu(e, [
                    { label: 'Copy value', onSelect: () => copyToClipboard(t.value, 'Copied target') },
                    { label: 'Send to JWT Scanner', onSelect: () => sendToJwtScanner(t.value) },
                    'separator',
                    { label: 'Remove target', onSelect: () => remove(t), danger: true },
                  ])
                }}
                className="flex items-center gap-3 px-3 py-2 text-sm hover:bg-neutral-900/60"
              >
                <span className="min-w-0 flex-1 truncate font-mono text-neutral-200">{t.value}</span>
                {t.sourceTool && (
                  <span className="shrink-0 rounded border border-neutral-700 px-1.5 py-0.5 text-xs text-neutral-400">from {t.sourceTool}</span>
                )}
                <span className="shrink-0 text-xs text-neutral-600">{new Date(t.createdAt).toLocaleDateString()}</span>
                <button onClick={() => remove(t)} className="shrink-0 text-xs text-neutral-600 hover:text-red-400">
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// --- Shared target picker used by every job launcher ---

function TargetPicker({ targets, selected, onChange }: { targets: Target[]; selected: Set<string>; onChange: (next: Set<string>) => void }) {
  const toggle = (value: string) => {
    const next = new Set(selected)
    if (next.has(value)) next.delete(value)
    else next.add(value)
    onChange(next)
  }
  if (targets.length === 0) {
    return <p className="text-xs text-neutral-600">No targets in this case yet — add one on the Targets tab first.</p>
  }
  const allSelected = targets.every((t) => selected.has(t.value))
  const toggleAll = () => onChange(allSelected ? new Set() : new Set(targets.map((t) => t.value)))
  return (
    <div className="space-y-1.5">
      <button
        type="button"
        onClick={toggleAll}
        className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-400 hover:border-sky-600 hover:text-sky-400"
      >
        {allSelected ? 'Deselect all' : `Select all (${targets.length})`}
      </button>
      <div className="flex max-h-32 flex-wrap gap-1.5 overflow-y-auto">
        {targets.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => toggle(t.value)}
            className={`rounded border px-2 py-1 font-mono text-xs ${
              selected.has(t.value) ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-neutral-500'
            }`}
          >
            {t.value}
          </button>
        ))}
      </div>
    </div>
  )
}

const PRESETS: { id: JobOptionsPreset; label: string; description: string }[] = [
  { id: 'custom', label: 'Default', description: 'Engine defaults (balanced speed).' },
  { id: 'aggressive', label: 'Aggressive', description: 'Many threads, short timeout, no rate limit — fastest, loudest.' },
  { id: 'stealth', label: 'Stealth', description: 'Few threads, longer timeout, rate-limited — slower, quieter.' },
]

// --- Identify tab ---

function IdentifyTab({
  caseId,
  targets,
  jobs,
  statusOf,
  checks,
  onStart,
  onCancel,
  onTargetsChanged,
}: {
  caseId: string
  targets: Target[]
  jobs: Job[]
  statusOf: (job: Job) => RunStatus
  checks: Record<string, Check>
  onStart: (job: Job) => void
  onCancel: (job: Job) => void
  onTargetsChanged: () => void
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [starting, setStarting] = useState(false)
  const [message, setMessage] = useState('')
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')

  const start = async () => {
    if (selected.size === 0) return
    setStarting(true)
    setMessage('')
    try {
      const res = await api.startJob(caseId, 'identify', [...selected])
      if (res.jobId) {
        const job = await api.getJob(res.jobId)
        onStart(job)
        setMessage('Started — see the check cards below')
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  // Every target this case knows about that has at least one check
  // recorded, in target list order -- so a target picked for a past
  // identify job keeps its card even after being deselected.
  const targetsWithChecks = targets.filter((t) => Object.keys(checks).some((k) => k.startsWith(`${t.value}::`)))

  const allSubdomains = new Map<string, string>() // value -> discovering target
  for (const key in checks) {
    const c = checks[key]
    if (c.kind !== 'subdomains-verified' || c.status !== 'done') continue
    const found = (c.data?.subdomains as string[] | undefined) ?? []
    for (const h of found) if (!allSubdomains.has(h)) allSubdomains.set(h, c.domain)
  }
  const knownValues = new Set(targets.map((t) => t.value))
  const undiscoveredSubdomains = [...allSubdomains.keys()].filter((h) => !knownValues.has(h))

  const technologyChecks = Object.values(checks).filter((c) => c.kind === 'technologies')

  const saveSubdomains = async (values: string[]) => {
    try {
      await Promise.all(values.map((v) => api.addTarget(caseId, v, 'subdomain')))
      showToast(`Saved ${values.length} target${values.length === 1 ? '' : 's'} to the case`, 'success')
      onTargetsChanged()
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  return (
    <div className="h-full mx-auto max-w-5xl space-y-6 overflow-y-auto px-4 py-6">
      <div className="rounded-lg border border-neutral-800 p-3">
        <p className="mb-2 text-xs text-neutral-500">
          Runs passive/read-only recon (DNS, TLS, HTTP, WHOIS, certificate-transparency subdomain discovery) against the selected targets. Nothing
          active — no bruteforcing.
        </p>
        <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
        <div className="mt-2 flex items-center gap-3">
          <button
            onClick={start}
            disabled={starting || selected.size === 0}
            className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {starting ? 'Starting…' : `Identify (${selected.size})`}
          </button>
          {message && <span className="text-xs text-neutral-500">{message}</span>}
        </div>
      </div>

      {jobs.length > 0 && (
        <JobHistory jobs={jobs} statusOf={statusOf} onCancel={onCancel} />
      )}

      {targetsWithChecks.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Checks</h2>
            <span className="text-xs text-neutral-600">{targetsWithChecks.length}</span>
            <div className="ml-auto flex items-center gap-1">
              <button
                type="button"
                onClick={() => setViewMode('grid')}
                className={`rounded border px-2 py-0.5 text-xs ${
                  viewMode === 'grid' ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-neutral-500'
                }`}
              >
                Grid
              </button>
              <button
                type="button"
                onClick={() => setViewMode('list')}
                className={`rounded border px-2 py-0.5 text-xs ${
                  viewMode === 'list' ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-neutral-500'
                }`}
              >
                List
              </button>
            </div>
          </div>

          {viewMode === 'grid' ? (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {targetsWithChecks.map((t) => (
                <div key={t.id} className="rounded-lg border border-neutral-800 p-3">
                  <h3 className="mb-2 font-mono text-xs text-neutral-300">{t.value}</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {(['dns', 'tls', 'http', 'whois'] as CheckKind[]).map((kind) => (
                      <CheckCard key={kind} kind={kind} check={checks[keyFor(t.value, kind)]} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="overflow-auto rounded-lg border border-neutral-800">
              <table className="w-full text-left text-sm">
                <thead className="sticky top-0 bg-neutral-950">
                  <tr>
                    <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Target</th>
                    {(['dns', 'tls', 'http', 'whois'] as CheckKind[]).map((kind) => (
                      <th key={kind} className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">
                        {CHECK_LABELS[kind]}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {targetsWithChecks.map((t) => (
                    <tr key={t.id} className="border-b border-neutral-900 hover:bg-neutral-900/60">
                      <td className="px-3 py-1.5 font-mono text-xs text-neutral-200">{t.value}</td>
                      {(['dns', 'tls', 'http', 'whois'] as CheckKind[]).map((kind) => (
                        <CheckCell key={kind} kind={kind} check={checks[keyFor(t.value, kind)]} />
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {undiscoveredSubdomains.length > 0 && (
        <div className="rounded-lg border border-neutral-800">
          <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Discovered subdomains</h2>
            <span className="text-xs text-neutral-600">{undiscoveredSubdomains.length}</span>
            <button
              onClick={() => saveSubdomains(undiscoveredSubdomains)}
              className="ml-auto rounded bg-sky-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-sky-500"
            >
              Save all to case
            </button>
          </div>
          <div className="max-h-56 divide-y divide-neutral-900 overflow-y-auto">
            {undiscoveredSubdomains.map((h) => (
              <div key={h} className="flex items-center gap-2 px-3 py-1.5 text-xs">
                <span className="font-mono text-neutral-200">{h}</span>
                <span className="text-neutral-600">via {allSubdomains.get(h)}</span>
                <button onClick={() => saveSubdomains([h])} className="ml-auto text-sky-400 hover:text-sky-300">
                  Save
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {technologyChecks.length > 0 && <TechTable checks={checks} />}
    </div>
  )
}

function CheckCard({ kind, check }: { kind: CheckKind; check?: Check }) {
  const status = check?.status ?? 'pending'
  return (
    <div className="rounded border border-neutral-800 bg-neutral-900 p-2">
      <div className="mb-1 flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: STATUS_DOT[status] }} />
        <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-400">{CHECK_LABELS[kind]}</span>
      </div>
      {status === 'pending' && <p className="text-xs text-neutral-600">Not run</p>}
      {status === 'running' && <p className="text-xs text-neutral-500">Checking…</p>}
      {status === 'error' && <p className="text-xs text-red-400">{check?.error || 'failed'}</p>}
      {status === 'done' && check?.data && <CheckSummary kind={kind} data={check.data} />}
    </div>
  )
}

function CheckCell({ kind, check }: { kind: CheckKind; check?: Check }) {
  const status = check?.status ?? 'pending'
  return (
    <td className="px-3 py-1.5 text-xs">
      <div className="flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_DOT[status] }} />
        <span className="truncate text-neutral-300">{checkCellText(kind, check)}</span>
      </div>
    </td>
  )
}

// checkCellText condenses the same data CheckSummary renders as a small
// card into one line, for the Identify tab's list view.
function checkCellText(kind: CheckKind, check?: Check): string {
  if (!check) return 'Not run'
  if (check.status === 'running') return 'Checking…'
  if (check.status === 'error') return check.error || 'failed'
  const data = check.data ?? {}
  switch (kind) {
    case 'dns': {
      const a = (data.a as string[]) ?? []
      return a.length ? a.join(', ') : 'no A records'
    }
    case 'tls': {
      const issuer = (data.issuer as string) || 'unknown issuer'
      const days = data.daysRemaining as number | undefined
      return days !== undefined ? `${issuer} (${days}d)` : issuer
    }
    case 'http': {
      const code = data.statusCode as number | undefined
      const title = (data.title as string) || (data.server as string) || ''
      return [code ?? '—', title].filter(Boolean).join(' ')
    }
    case 'whois':
      return (data.registrar as string) || 'unknown registrar'
    default:
      return ''
  }
}

function CheckSummary({ kind, data }: { kind: CheckKind; data: Record<string, unknown> }) {
  switch (kind) {
    case 'dns': {
      const a = (data.a as string[]) ?? []
      const ns = (data.ns as string[]) ?? []
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate font-mono">{a.length ? a.join(', ') : 'no A records'}</p>
          <p className="text-neutral-500">
            {ns.length} nameserver{ns.length === 1 ? '' : 's'}
          </p>
        </div>
      )
    }
    case 'tls': {
      const days = data.daysRemaining as number | undefined
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate">{(data.issuer as string) || 'unknown issuer'}</p>
          <p className={days !== undefined && days < 14 ? 'text-amber-400' : 'text-neutral-500'}>{days !== undefined ? `${days} days remaining` : ''}</p>
        </div>
      )
    }
    case 'http': {
      const code = data.statusCode as number | undefined
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p>
            <span className="font-mono" style={{ color: code ? statusHexColor(code) : undefined }}>
              {code}
            </span>{' '}
            · {(data.scheme as string)?.toUpperCase()}
          </p>
          <p className="truncate text-neutral-500">{(data.title as string) || (data.server as string) || ''}</p>
        </div>
      )
    }
    case 'whois': {
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate">{(data.registrar as string) || 'unknown registrar'}</p>
          <p className="text-neutral-500">{(data.expiresAt as string)?.slice(0, 10) || ''}</p>
        </div>
      )
    }
    default:
      return null
  }
}

// --- Tool tabs (feroxbuster / ffuf-subdomain / ffuf-vhost) ---

function JobHistory({ jobs, statusOf, onCancel }: { jobs: Job[]; statusOf: (job: Job) => RunStatus; onCancel: (job: Job) => void }) {
  return (
    <div className="rounded-lg border border-neutral-800">
      <div className="border-b border-neutral-800 px-3 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Jobs</h2>
      </div>
      <div className="divide-y divide-neutral-900">
        {[...jobs].reverse().map((job) => {
          const status = statusOf(job)
          return (
            <div key={job.id} className="flex items-center gap-2 px-3 py-1.5 text-xs">
              <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_DOT[status === 'running' ? 'running' : status === 'failed' ? 'error' : 'done'] }} />
              <span className="truncate font-mono text-neutral-300">{job.targets.join(', ')}</span>
              <span className="shrink-0 text-neutral-600">{status}</span>
              <span className="shrink-0 text-neutral-600">{new Date(job.createdAt).toLocaleTimeString()}</span>
              {status === 'running' && (
                <button onClick={() => onCancel(job)} className="ml-auto shrink-0 rounded border border-red-900 px-2 py-0.5 text-red-400 hover:border-red-500 hover:text-red-300">
                  Stop
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ToolTab({
  caseId,
  tool,
  targets,
  jobs,
  findings,
  statusOf,
  nodeStatus,
  jobProgress,
  nodeStartedAtRef,
  onStart,
  onCancel,
  onPromote,
  deriveTargetValue,
  schemeField,
  hostSuffixField,
  recursiveField,
}: {
  caseId: string
  tool: Tool
  targets: Target[]
  jobs: Job[]
  findings: Finding[]
  statusOf: (job: Job) => RunStatus
  nodeStatus: Record<string, NodeStatus>
  jobProgress: Record<string, { done: number; total: number }>
  nodeStartedAtRef: React.MutableRefObject<Record<string, number>>
  onStart: (job: Job) => void
  onCancel: (job: Job) => void
  onPromote: (values: string[]) => void
  deriveTargetValue?: (f: Finding) => string
  schemeField?: boolean
  hostSuffixField?: boolean
  recursiveField?: boolean
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [starting, setStarting] = useState(false)
  const [message, setMessage] = useState('')
  const [preset, setPreset] = useState<JobOptionsPreset>('custom')
  const [showTuning, setShowTuning] = useState(false)
  const [threads, setThreads] = useState('')
  const [timeoutSeconds, setTimeoutSeconds] = useState('')
  const [rateLimit, setRateLimit] = useState('')
  const [wordlist, setWordlist] = useState('')
  const [scheme, setScheme] = useState('https')
  const [hostSuffix, setHostSuffix] = useState('')
  // Off by default -- see engine.ScanOptions.Recursive: recursion
  // multiplies request volume by however many directories turn up, so it's
  // opt-in rather than a silent default.
  const [recursive, setRecursive] = useState(false)

  const nodePrefix = tool === 'feroxbuster' ? 'feroxbuster' : 'ffuf'

  const start = async () => {
    if (selected.size === 0) return
    setStarting(true)
    setMessage('')
    try {
      const options: JobOptions = {
        preset: preset === 'custom' ? undefined : preset,
        threads: threads ? Number(threads) : undefined,
        timeoutSeconds: timeoutSeconds ? Number(timeoutSeconds) : undefined,
        rateLimit: rateLimit ? Number(rateLimit) : undefined,
        wordlist: wordlist.trim() || undefined,
        scheme: schemeField ? scheme : undefined,
        hostSuffix: hostSuffixField ? hostSuffix.trim() || undefined : undefined,
        recursive: recursiveField ? recursive : undefined,
      }
      const res = await api.startJob(caseId, tool, [...selected], options)
      if (res.jobId) {
        const job = await api.getJob(res.jobId)
        onStart(job)
        setMessage('Started — see results below')
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  const targetProgress = (): TargetProgress[] => {
    const rows: TargetProgress[] = []
    for (const job of jobs) {
      const jStatus = statusOf(job)
      job.targets.forEach((target, i) => {
        const nodeId = `${nodePrefix}-${i}`
        const key = `${job.id}:${nodeId}`
        const status: NodeStatus = nodeStatus[key] ?? (jobProgress[key] ? 'running' : jStatus === 'running' ? 'pending' : jStatus)
        const p = jobProgress[key]
        const done = p?.done ?? 0
        const total = p?.total ?? 0
        const startedAt = nodeStartedAtRef.current[key] ?? null
        const detail = job.nodes?.find((n) => n.nodeId === nodeId)
        rows.push({
          key, target, status, done, total, etaSeconds: estimateEtaSeconds(done, total, startedAt),
          wordlist: detail?.wordlist, extensions: detail?.extensions, candidates: detail?.candidates,
          threads: detail?.threads, timeoutSeconds: detail?.timeoutSeconds, rateLimit: detail?.rateLimit,
        })
      })
    }
    return rows
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="shrink-0 overflow-y-auto border-b border-neutral-800 p-3">
        <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {schemeField && (
            <label className="flex items-center gap-1 text-xs text-neutral-400">
              Scheme
              <select
                value={scheme}
                onChange={(e) => setScheme(e.target.value)}
                className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
              >
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
            </label>
          )}
          {hostSuffixField && (
            <label className="flex items-center gap-1 text-xs text-neutral-400">
              Host header domain
              <input
                value={hostSuffix}
                onChange={(e) => setHostSuffix(e.target.value)}
                placeholder="example.com"
                className="w-40 rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 font-mono text-xs text-neutral-200 outline-none focus:border-sky-500"
              />
            </label>
          )}
          {recursiveField && (
            <label className="flex items-center gap-1.5 text-xs text-neutral-400" title="Fuzz found directories again with the same wordlist. Off by default -- multiplies request volume by however many directories turn up.">
              <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} className="accent-sky-500" />
              Recursive
            </label>
          )}
          {PRESETS.map((p) => (
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
          <button
            type="button"
            onClick={() => setShowTuning((v) => !v)}
            className="rounded border border-neutral-800 px-2 py-0.5 text-xs text-neutral-500 hover:text-neutral-300"
          >
            {showTuning ? 'Hide tuning ▾' : 'Advanced tuning ▸'}
          </button>
          <button
            onClick={start}
            disabled={starting || selected.size === 0 || (hostSuffixField && !hostSuffix.trim())}
            className="ml-auto rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {starting ? 'Starting…' : `Run (${selected.size})`}
          </button>
        </div>
        {showTuning && (
          <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Threads</span>
              <input value={threads} onChange={(e) => setThreads(e.target.value)} placeholder="default" className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500" />
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Timeout (s)</span>
              <input value={timeoutSeconds} onChange={(e) => setTimeoutSeconds(e.target.value)} placeholder="default" className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500" />
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Rate limit (req/s)</span>
              <input value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} placeholder="unlimited" className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500" />
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Wordlist file</span>
              <input value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="category default" className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500" />
            </label>
          </div>
        )}
        {message && <p className="mt-2 text-xs text-neutral-500">{message}</p>}
      </div>

      {jobs.length > 0 && (
        <div className="shrink-0 border-b border-neutral-800">
          <JobHistory jobs={jobs} statusOf={statusOf} onCancel={onCancel} />
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <TargetProgressPanel targets={targetProgress()} />
        <div className="flex-1 overflow-hidden">
          <ResultsTable findings={findings} caseId={caseId} facetPlacement="right" selectable onPromote={onPromote} deriveTargetValue={deriveTargetValue} />
        </div>
      </div>
    </div>
  )
}
