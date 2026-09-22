import { useEffect, useRef, useState, type ReactElement, type SVGProps } from 'react'
import { api, watchJob } from '../api'
import type { Case, CaseScan, Check, CheckKind, Credential, Finding, Job, JobOptions, JobOptionsPreset, NodeStatus, RunStatus, Target, Tool } from '../types'
import { JOB_PRESETS } from '../presets'
import { statusHexColor } from '../statusColor'
import { estimateEtaSeconds } from '../eta'
import { ResultsTable } from './ResultsTable'
import { TargetProgressPanel, type TargetProgress } from './TargetProgressPanel'
import { GraphView } from './GraphView'
import { TechTable } from './TechTable'
import { JwtScan } from './JwtScan'
import { Probe } from './Probe'
import { SecretScan } from './SecretScan'
import { Repeater } from './Repeater'
import { FfufTab } from './Ffuf'
import { JobHistory } from './JobHistory'
import { TargetPicker } from './TargetPicker'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { showToast } from '../toast'
import { sendToJwtScanner, onJwtScannerRequest, type JwtScannerRequest } from '../jwtHandoff'
import { sendToProbe, onProbeRequest, type ProbeRequest } from '../probeHandoff'
import { sendToSecretScan, onSecretScanRequest, type SecretScanRequest } from '../secretScanHandoff'
import { sendToRepeater, onRepeaterRequest, type RepeaterHandoffRequest } from '../repeaterHandoff'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { useAutoCollapseOnce, useAutoExpandOnce, useCollapsible } from '../collapsible'
import { CredentialVault } from './CredentialVault'
import { CredentialPicker } from './CredentialPicker'
import { ActivityTimeline } from './ActivityTimeline'
import { RiskPanel } from './RiskPanel'
import { JobTemplatePicker } from './JobTemplatePicker'
import {
  IconActivity,
  IconChart,
  IconCrosshair,
  IconFolder,
  IconFolderSearch,
  IconGlobe,
  IconKey,
  IconLightning,
  IconLock,
  IconRadar,
  IconRepeat,
  IconScan,
  IconServer,
  IconShieldKey,
  IconSitemap,
  IconTarget,
  IconWarning,
  IconWrench,
} from './icons'

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
  asn: 'Hosting network',
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

type Tab =
  | 'targets'
  | 'credentials'
  | 'identify'
  | 'risk'
  | 'feroxbuster'
  | 'ffuf-subdomain'
  | 'ffuf-vhost'
  | 'ffuf-custom'
  | 'subfinder'
  | 'amass'
  | 'katana'
  | 'httpx'
  | 'whatweb'
  | 'graph'
  | 'jwtscan'
  | 'probe'
  | 'secrets'
  | 'repeater'
  | 'activity'

type IconType = (props: SVGProps<SVGSVGElement>) => ReactElement

const TAB_META: Record<Tab, { label: string; icon: IconType }> = {
  targets: { label: 'Targets', icon: IconTarget },
  credentials: { label: 'Credentials', icon: IconKey },
  identify: { label: 'Identify', icon: IconRadar },
  feroxbuster: { label: 'Directory Scanner', icon: IconFolderSearch },
  'ffuf-subdomain': { label: 'Subdomain Scanner', icon: IconGlobe },
  'ffuf-vhost': { label: 'VHost Scanner', icon: IconServer },
  'ffuf-custom': { label: 'FFuF', icon: IconLightning },
  subfinder: { label: 'Subfinder', icon: IconGlobe },
  amass: { label: 'Amass', icon: IconSitemap },
  katana: { label: 'Katana Crawler', icon: IconFolder },
  httpx: { label: 'Httpx Prober', icon: IconServer },
  whatweb: { label: 'WhatWeb', icon: IconChart },
  jwtscan: { label: 'JWT Scanner', icon: IconShieldKey },
  probe: { label: 'Probe', icon: IconCrosshair },
  secrets: { label: 'Secrets', icon: IconLock },
  repeater: { label: 'Repeater', icon: IconRepeat },
  risk: { label: 'Risk', icon: IconWarning },
  graph: { label: 'Graph', icon: IconSitemap },
  activity: { label: 'Activity', icon: IconActivity },
}

// NAV_GROUPS is the left navbar's shape: case-management tabs pinned above
// the groups, then groups ordered the way a case is actually worked --
// identify the target first, run the automated scanners, reach for a
// standalone tool for something targeted, and finish in the
// intelligence/analysis views that summarize everything above. Each group
// (other than the pinned "Case" one) is independently collapsible -- see
// the `navGroupOpen` state below.
type NavGroup = { id: string; label: string; icon: IconType; tabs: Tab[] }

const PINNED_TABS: Tab[] = ['targets', 'credentials']

const NAV_GROUPS: NavGroup[] = [
  { id: 'identify', label: 'Identify', icon: IconRadar, tabs: ['identify'] },
  {
    id: 'scanners',
    label: 'Scanners',
    icon: IconScan,
    tabs: ['feroxbuster', 'ffuf-subdomain', 'ffuf-vhost', 'subfinder', 'amass', 'katana'],
  },
  { id: 'tools', label: 'Tools', icon: IconWrench, tabs: ['ffuf-custom', 'httpx', 'whatweb', 'jwtscan', 'probe', 'secrets', 'repeater'] },
  { id: 'intelligence', label: 'Intelligence', icon: IconChart, tabs: ['risk', 'graph', 'activity'] },
]

// CaseView is one case's workspace: a left navbar switching between Targets,
// Identify, each scanning tool, and the Graph, each rendered as its own tab
// so the user can see how each tool is doing independently. Every tool tab
// only ever runs when the user launches it from that tab's JobLauncher --
// nothing here starts anything on its own.
export function CaseView({ caseId }: { caseId: string }) {
  const [c, setCase] = useState<Case | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [credentials, setCredentials] = useState<Credential[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [caseScans, setCaseScans] = useState<CaseScan[]>([])
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
  // Collapses the tab nav to a slim dot rail so a case with many tools open
  // gives the active tab's content the width instead of a permanently fixed
  // 12rem sidebar -- persisted like every other collapse toggle in this file.
  const [navOpen, setNavOpen] = useCollapsible('caseNav', true)
  // Set by a "Send to JWT Scanner" context-menu item anywhere in this case
  // (Targets list, tool results, graph/hierarchy nodes -- see
  // jwtHandoff.ts); JwtScan applies it even though it stays mounted the
  // whole time this case is open.
  const [jwtPrefill, setJwtPrefill] = useState<JwtScannerRequest | undefined>()
  // Set by a "Send to Probe" context-menu item, same shape as jwtPrefill
  // above -- see probeHandoff.ts.
  const [probePrefill, setProbePrefill] = useState<ProbeRequest | undefined>()
  // Set by a "Send to Secret Scanner" context-menu item -- see
  // secretScanHandoff.ts.
  const [secretScanPrefill, setSecretScanPrefill] = useState<SecretScanRequest | undefined>()
  // Set by a "Send to Repeater" context-menu item -- see repeaterHandoff.ts.
  const [repeaterPrefill, setRepeaterPrefill] = useState<RepeaterHandoffRequest | undefined>()

  // Only one case is ever open at a time, so this subscription always
  // targets whichever case is currently visible -- no need to key it by
  // caseId or re-subscribe when the user switches cases.
  useEffect(() => {
    return onJwtScannerRequest((req) => {
      setJwtPrefill(req)
      setTab('jwtscan')
    })
  }, [])

  useEffect(() => {
    return onProbeRequest((req) => {
      setProbePrefill(req)
      setTab('probe')
    })
  }, [])

  useEffect(() => {
    return onSecretScanRequest((req) => {
      setSecretScanPrefill(req)
      setTab('secrets')
    })
  }, [])

  useEffect(() => {
    return onRepeaterRequest((req) => {
      setRepeaterPrefill(req)
      setTab('repeater')
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
    setCredentials([])
    setJobs([])
    setCaseScans([])
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
    api.listCredentials(caseId).then((c) => {
      if (!cancelled) setCredentials(c)
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
    api.listCaseScans(caseId).then((list) => {
      if (!cancelled) setCaseScans(list)
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

  const refreshCredentials = () => {
    api.listCredentials(caseId).then(setCredentials)
  }

  // Probe/JWT/Secret Scanner runs are one-shot actions with no live stream
  // (unlike checks/findings above), so the Risk Panel's rollup of them is
  // only ever as fresh as its last fetch -- refetched every time that tab
  // is opened rather than polled continuously.
  useEffect(() => {
    if (tab === 'risk') api.listCaseScans(caseId).then(setCaseScans)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, caseId])

  const addJob = (job: Job) => {
    setJobs((prev) => [...prev, job])
    watchTheJob(job)
  }

  const statusOf = (job: Job): RunStatus => jobStatus[job.id] ?? job.status
  const jobsOfTool = (tool: Tool) => jobs.filter((j) => j.tool === tool)

  const findingsOfTool = (tool: Tool): Finding[] => {
    const byKey = new Map<string, Finding>()
    // Subfinder's second stage (see internal/api.buildSubfinderFlow) re-emits
    // an already-seen host as a fresh Finding once httpx has actually probed
    // it, entirely superseding the bare "found it" placeholder subfinder
    // itself emitted first -- keyed by URL alone here (not URL+status, like
    // every other tool below) so the real probe result replaces the
    // placeholder in the table instead of both showing up as separate rows.
    const keyOf = tool === 'subfinder' ? (f: Finding) => f.url : (f: Finding) => `${f.url}|${f.statusCode}`
    for (const job of jobsOfTool(tool)) {
      for (const f of runFindings[job.id] ?? []) byKey.set(keyOf(f), f)
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
    'ffuf-custom': jobsOfTool('ffuf-custom').length === 0 ? STATUS_DOT.pending : jobsOfTool('ffuf-custom').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    subfinder: jobsOfTool('subfinder').length === 0 ? STATUS_DOT.pending : jobsOfTool('subfinder').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    amass: jobsOfTool('amass').length === 0 ? STATUS_DOT.pending : jobsOfTool('amass').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    katana: jobsOfTool('katana').length === 0 ? STATUS_DOT.pending : jobsOfTool('katana').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    httpx: jobsOfTool('httpx').length === 0 ? STATUS_DOT.pending : jobsOfTool('httpx').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    whatweb: jobsOfTool('whatweb').length === 0 ? STATUS_DOT.pending : jobsOfTool('whatweb').some((j) => statusOf(j) === 'running') ? STATUS_DOT.running : STATUS_DOT.done,
    graph: STATUS_DOT.done,
    jwtscan: STATUS_DOT.done,
    probe: STATUS_DOT.done,
    secrets: STATUS_DOT.done,
    repeater: STATUS_DOT.done,
    credentials: STATUS_DOT.done,
    risk: STATUS_DOT.done,
    activity: STATUS_DOT.done,
  }
  const counts: Record<Tab, number | null> = {
    targets: targets.length,
    identify: null,
    feroxbuster: findingsOfTool('feroxbuster').length,
    'ffuf-subdomain': findingsOfTool('ffuf-subdomain').length,
    'ffuf-vhost': findingsOfTool('ffuf-vhost').length,
    'ffuf-custom': findingsOfTool('ffuf-custom').length,
    subfinder: findingsOfTool('subfinder').length,
    amass: findingsOfTool('amass').length,
    katana: findingsOfTool('katana').length,
    httpx: findingsOfTool('httpx').length,
    whatweb: findingsOfTool('whatweb').length,
    graph: null,
    jwtscan: null,
    probe: null,
    secrets: null,
    repeater: null,
    credentials: credentials.length,
    risk: null,
    activity: null,
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
        {navOpen ? (
          <aside className="flex w-52 shrink-0 flex-col overflow-y-auto border-r border-neutral-800 bg-neutral-950 p-2">
            <button onClick={() => setNavOpen(false)} title="Collapse" className="mb-1 self-end px-1 text-xs text-neutral-600 hover:text-neutral-300">
              ◂
            </button>
            <div className="space-y-0.5">
              {PINNED_TABS.map((id) => (
                <NavTabButton key={id} id={id} active={tab === id} dot={dots[id]} count={counts[id]} onSelect={() => setTab(id)} />
              ))}
            </div>
            <div className="my-2 border-t border-neutral-900" />
            <div className="space-y-1">
              {NAV_GROUPS.map((group) => (
                <NavGroupSection key={group.id} group={group} activeTab={tab} dots={dots} counts={counts} onSelect={setTab} />
              ))}
            </div>
          </aside>
        ) : (
          <aside className="flex w-9 shrink-0 flex-col items-center gap-1 overflow-y-auto border-r border-neutral-800 bg-neutral-950 py-2">
            <button onClick={() => setNavOpen(true)} title="Expand navigation" className="mb-1 text-neutral-600 hover:text-neutral-300">
              ▸
            </button>
            {[...PINNED_TABS, ...NAV_GROUPS.flatMap((g) => g.tabs)].map((id) => {
              const Icon = TAB_META[id].icon
              return (
                <button
                  key={id}
                  onClick={() => setTab(id)}
                  title={`${TAB_META[id].label}${counts[id] !== null ? ` (${counts[id]})` : ''}`}
                  className={`relative flex h-7 w-7 items-center justify-center rounded ${
                    tab === id ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span className="absolute right-0.5 top-0.5 h-1.5 w-1.5 rounded-full" style={{ background: dots[id] }} />
                </button>
              )
            })}
          </aside>
        )}

        {/* Every tab stays mounted (toggled via `hidden`, not conditional
            rendering) so switching tabs to peek at another tool doesn't
            reset a results table's row selection right before you meant to
            click "Save selected to case". */}
        <div className="flex-1 overflow-hidden">
          <div className={`h-full ${tab === 'targets' ? '' : 'hidden'}`}>
            <TargetsTab caseId={caseId} targets={targets} onChange={refreshTargets} />
          </div>

          <div className={`h-full overflow-y-auto ${tab === 'credentials' ? '' : 'hidden'}`}>
            <CredentialVault caseId={caseId} credentials={credentials} onChanged={refreshCredentials} />
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
              credentials={credentials}
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
              credentials={credentials}
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
              credentials={credentials}
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

          <div className={`h-full ${tab === 'subfinder' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="subfinder"
              targets={targets}
              credentials={credentials}
              jobs={jobsOfTool('subfinder')}
              findings={findingsOfTool('subfinder')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('subfinder', values)}
              wordlistField={false}
              credentialField={false}
            />
          </div>

          <div className={`h-full ${tab === 'amass' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="amass"
              targets={targets}
              credentials={credentials}
              jobs={jobsOfTool('amass')}
              findings={findingsOfTool('amass')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('amass', values)}
              wordlistField={false}
              credentialField={false}
              disabledMessage="The amass binary itself just hangs and produces nothing on every run right now, regardless of flags -- disabled for the moment. Will be fixed soon."
            />
          </div>

          <div className={`h-full ${tab === 'katana' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="katana"
              targets={targets}
              credentials={credentials}
              jobs={jobsOfTool('katana')}
              findings={findingsOfTool('katana')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('katana', values)}
              schemeField
              wordlistField={false}
            />
          </div>

          <div className={`h-full ${tab === 'ffuf-custom' ? '' : 'hidden'}`}>
            <FfufTab
              caseId={caseId}
              targets={targets}
              credentials={credentials}
              jobs={jobsOfTool('ffuf-custom')}
              findings={findingsOfTool('ffuf-custom')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('ffuf-custom', values)}
            />
          </div>

          <div className={`h-full ${tab === 'httpx' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="httpx"
              targets={targets}
              credentials={credentials}
              jobs={jobsOfTool('httpx')}
              findings={findingsOfTool('httpx')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('httpx', values)}
              schemeField
              wordlistField={false}
            />
          </div>

          <div className={`h-full ${tab === 'whatweb' ? '' : 'hidden'}`}>
            <ToolTab
              caseId={caseId}
              tool="whatweb"
              targets={targets}
              credentials={credentials}
              jobs={jobsOfTool('whatweb')}
              findings={findingsOfTool('whatweb')}
              statusOf={statusOf}
              nodeStatus={nodeStatus}
              jobProgress={jobProgress}
              nodeStartedAtRef={nodeStartedAtRef}
              onStart={addJob}
              onCancel={cancelJob}
              onPromote={(values) => promoteFromTool('whatweb', values)}
              schemeField
              wordlistField={false}
            />
          </div>

          <div className={`h-full ${tab === 'risk' ? '' : 'hidden'}`}>
            <RiskPanel checks={checks} targets={targets} jobs={jobs} caseScans={caseScans} />
          </div>

          <div className={`h-full ${tab === 'graph' ? '' : 'hidden'}`}>
            <GraphView caseId={caseId} />
          </div>

          <div className={`h-full overflow-hidden ${tab === 'jwtscan' ? '' : 'hidden'}`}>
            <JwtScan caseId={caseId} targets={targets} credentials={credentials} prefill={jwtPrefill} />
          </div>

          <div className={`h-full overflow-y-auto ${tab === 'probe' ? '' : 'hidden'}`}>
            <Probe caseId={caseId} targets={targets} credentials={credentials} prefill={probePrefill} />
          </div>

          <div className={`h-full overflow-y-auto ${tab === 'secrets' ? '' : 'hidden'}`}>
            <SecretScan caseId={caseId} targets={targets} credentials={credentials} prefill={secretScanPrefill} />
          </div>

          <div className={`h-full overflow-hidden ${tab === 'repeater' ? '' : 'hidden'}`}>
            <Repeater caseId={caseId} targets={targets} credentials={credentials} prefill={repeaterPrefill} />
          </div>

          <div className={`h-full ${tab === 'activity' ? '' : 'hidden'}`}>
            <ActivityTimeline caseId={caseId} />
          </div>
        </div>
      </div>
    </div>
  )
}

// --- Nav (left sidebar) ---

// NavTabButton is one row in the expanded nav -- either pinned above the
// groups (Targets/Credentials) or inside a NavGroupSection below.
function NavTabButton({
  id,
  active,
  dot,
  count,
  onSelect,
}: {
  id: Tab
  active: boolean
  dot: string
  count: number | null
  onSelect: () => void
}) {
  const { label, icon: Icon } = TAB_META[id]
  return (
    <button
      onClick={onSelect}
      className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm ${
        active ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200'
      }`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span className="flex-1 truncate">{label}</span>
      <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: dot }} />
      {count !== null && <span className="text-xs text-neutral-500">{count}</span>}
    </button>
  )
}

// NavGroupSection renders one collapsible group (Identify/Scanners/Tools/
// Intelligence). Each group remembers its own open/closed state under its
// own key so collapsing "Tools" doesn't affect "Scanners" -- and it starts
// open, expanding to reveal the active tab if a group is reopened to reveal
// a saved-collapsed tab that later becomes active (e.g. via a "Send to X"
// handoff from elsewhere in the case).
function NavGroupSection({
  group,
  activeTab,
  dots,
  counts,
  onSelect,
}: {
  group: NavGroup
  activeTab: Tab
  dots: Record<Tab, string>
  counts: Record<Tab, number | null>
  onSelect: (tab: Tab) => void
}) {
  const [open, setOpen] = useCollapsible(`caseNav.group.${group.id}`, true)
  const hasActive = group.tabs.includes(activeTab)
  useAutoExpandOnce(hasActive, setOpen)
  const Icon = group.icon
  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-1.5 border-l-2 border-sky-700/70 py-1.5 pl-2 pr-1 text-left text-[11px] font-bold uppercase tracking-wider text-sky-400 hover:border-sky-500 hover:text-sky-300"
      >
        <Icon className="h-3.5 w-3.5 shrink-0 text-sky-500" />
        <span className="flex-1">{group.label}</span>
        <span className="text-sky-700">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="space-y-0.5 border-l-2 border-transparent pt-0.5">
          {group.tabs.map((id) => (
            <NavTabButton key={id} id={id} active={activeTab === id} dot={dots[id]} count={counts[id]} onSelect={() => onSelect(id)} />
          ))}
        </div>
      )}
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
                    { label: 'Send to Probe', onSelect: () => sendToProbe(t.value) },
                    { label: 'Send to Secret Scanner', onSelect: () => sendToSecretScan(t.value) },
                    { label: 'Send to Repeater', onSelect: () => sendToRepeater(t.value) },
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

const PRESETS = JOB_PRESETS

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

      {jobs.length > 0 && <JobHistory jobs={jobs} statusOf={statusOf} onCancel={onCancel} panelKey="identify" />}

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
    case 'asn': {
      const asn = (data.asn as string) || ''
      const org = (data.org as string) || ''
      return [asn, org].filter(Boolean).join(' · ') || 'unresolved'
    }
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
    case 'asn': {
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate font-mono">{(data.asn as string) || 'unresolved'}</p>
          <p className="truncate text-neutral-500">{(data.org as string) || ''}</p>
        </div>
      )
    }
    default:
      return null
  }
}

// --- Tool tabs (feroxbuster / ffuf-subdomain / ffuf-vhost) ---
// JobHistory (a tab's past-job log) is shared with Ffuf.tsx -- see
// ./JobHistory.tsx.

function ToolTab({
  caseId,
  tool,
  targets,
  credentials,
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
  wordlistField = true,
  credentialField = true,
  disabledMessage,
}: {
  caseId: string
  tool: Tool
  targets: Target[]
  credentials: Credential[]
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
  // wordlistField hides the wordlist-file tuning input for tools that
  // don't fuzz off a wordlist at all (subfinder/amass/katana/httpx/
  // whatweb) -- true (shown) for every wordlist-driven tool that predates
  // this flag.
  wordlistField?: boolean
  // credentialField hides the saved-credential picker for tools that never
  // issue an authenticated request to the target at all (subfinder/amass,
  // which only ever query third-party OSINT sources) -- true (shown) for
  // every tool that predates this flag.
  credentialField?: boolean
  // disabledMessage, when set, replaces this tab's launcher with a static
  // notice and blocks starting a new job entirely -- for a tool that's
  // known broken right now rather than one the user just hasn't run yet.
  // Past jobs/results (if any) still render below it as usual.
  disabledMessage?: string
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
  const [credentialId, setCredentialId] = useState<string | undefined>()
  // Off by default -- see engine.ScanOptions.Recursive: recursion
  // multiplies request volume by however many directories turn up, so it's
  // opt-in rather than a silent default.
  const [recursive, setRecursive] = useState(false)

  // Collapses the launcher (target picker, scheme/preset/tuning controls)
  // to a compact bar the first time this tab has a job to show, so the
  // results table gets the width instead of the launcher permanently
  // occupying it -- same pattern as JwtScan/Probe's form column.
  const [launcherOpen, setLauncherOpen] = useCollapsible(`launcher.${tool}`, true)
  useAutoCollapseOnce(jobs.length > 0, setLauncherOpen)

  // Every fanout tool's source node IDs are "<kind>-<index>" (see
  // buildFanoutFlow) where kind is the engine.NodeKind the tool maps to --
  // one-to-one with the tool name itself except the three ffuf-* tools,
  // which all share the single "ffuf" adapter/node kind.
  const nodePrefix = tool === 'feroxbuster' ? 'feroxbuster' : tool.startsWith('ffuf') ? 'ffuf' : tool

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
        credentialId,
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
          key, target, status, done, total, etaSeconds: estimateEtaSeconds(done, total, startedAt), startedAt,
          wordlist: detail?.wordlist, extensions: detail?.extensions, candidates: detail?.candidates,
          threads: detail?.threads, timeoutSeconds: detail?.timeoutSeconds, rateLimit: detail?.rateLimit,
        })
      })

      // Subfinder's second stage: the enumeration nodes above feed a single
      // shared "verify" node (see internal/api.buildSubfinderFlow) that
      // isn't one of job.targets, so it needs its own row here instead of
      // falling out of the forEach above.
      if (tool === 'subfinder') {
        const key = `${job.id}:verify`
        const status: NodeStatus = nodeStatus[key] ?? (jobProgress[key] ? 'running' : jStatus === 'running' ? 'pending' : jStatus)
        const p = jobProgress[key]
        const done = p?.done ?? 0
        const total = p?.total ?? 0
        const startedAt = nodeStartedAtRef.current[key] ?? null
        rows.push({ key, target: 'Verify (httpx)', status, done, total, etaSeconds: estimateEtaSeconds(done, total, startedAt), startedAt })
      }
    }
    return rows
  }

  const canRun = !disabledMessage && !starting && selected.size > 0 && !(hostSuffixField && !hostSuffix.trim())
  const launcherSummary =
    selected.size > 0
      ? `${selected.size} target${selected.size === 1 ? '' : 's'} selected${preset !== 'custom' ? ` · ${preset}` : ''}`
      : 'No targets selected'

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="shrink-0 overflow-y-auto border-b border-neutral-800 p-3">
        {disabledMessage ? (
          <div className="flex items-start gap-2 rounded border border-amber-900/50 bg-amber-950/20 px-3 py-2 text-xs text-amber-200">
            <span className="mt-0.5 shrink-0">⚠</span>
            <span>{disabledMessage}</span>
          </div>
        ) : (
        <CollapsibleFormPanel
          title="Configure"
          open={launcherOpen}
          onToggle={() => setLauncherOpen(!launcherOpen)}
          summary={launcherSummary}
          onRun={start}
          canRun={canRun}
          loading={starting}
          runLabel={`Run (${selected.size})`}
        >
          <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          <div className="flex flex-wrap items-center gap-2">
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
          <JobTemplatePicker
            tool={tool}
            current={{
              preset: preset === 'custom' ? undefined : preset,
              threads: threads ? Number(threads) : undefined,
              timeoutSeconds: timeoutSeconds ? Number(timeoutSeconds) : undefined,
              rateLimit: rateLimit ? Number(rateLimit) : undefined,
              wordlist: wordlist.trim() || undefined,
              scheme: schemeField ? scheme : undefined,
              hostSuffix: hostSuffixField ? hostSuffix.trim() || undefined : undefined,
              recursive: recursiveField ? recursive : undefined,
            }}
            onApply={(options) => {
              setPreset(options.preset ?? 'custom')
              setThreads(options.threads ? String(options.threads) : '')
              setTimeoutSeconds(options.timeoutSeconds ? String(options.timeoutSeconds) : '')
              setRateLimit(options.rateLimit ? String(options.rateLimit) : '')
              setWordlist(options.wordlist ?? '')
              if (schemeField && options.scheme) setScheme(options.scheme)
              if (hostSuffixField) setHostSuffix(options.hostSuffix ?? '')
              if (recursiveField) setRecursive(options.recursive ?? false)
            }}
          />
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
              {wordlistField && (
                <label className="flex flex-col gap-0.5">
                  <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Wordlist file</span>
                  <input value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="category default" className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500" />
                </label>
              )}
              {credentialField && (
                <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} className="col-span-2 sm:col-span-4" />
              )}
            </div>
          )}
          {message && <p className="mt-2 text-xs text-neutral-500">{message}</p>}
        </CollapsibleFormPanel>
        )}
      </div>

      {jobs.length > 0 && <JobHistory jobs={jobs} statusOf={statusOf} onCancel={onCancel} panelKey={tool} />}

      <div className="flex flex-1 overflow-hidden">
        <TargetProgressPanel targets={targetProgress()} tabKey={tool} />
        <div className="flex-1 overflow-hidden">
          <ResultsTable findings={findings} caseId={caseId} facetPlacement="right" selectable onPromote={onPromote} deriveTargetValue={deriveTargetValue} />
        </div>
      </div>
    </div>
  )
}
