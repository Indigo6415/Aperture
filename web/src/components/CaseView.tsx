import { useCallback, useEffect, useRef, useState } from 'react'
import { api, watchJob } from '../api'
import { IDLE_INDICATOR, INDICATOR_COLOR, ScanIndicatorContext, severityOfName, worseSeverity, type IndicatorSeverity, type ScanIndicator, type ScanPhase } from '../scanIndicator'
import type { Case, Check, CheckKind, CookieVaultEntry, Credential, Finding, Job, JobOptions, JobOptionsPreset, NodeStatus, RunStatus, Target, TargetList, TargetListKind, TargetPingResult, Tool } from '../types'
import { JOB_PRESETS } from '../presets'
import { statusHexColor } from '../statusColor'
import { estimateEtaSeconds } from '../eta'
import { ResultsTable } from './ResultsTable'
import { NucleiResults } from './NucleiResults'
import { TargetProgressPanel, type TargetProgress } from './TargetProgressPanel'
import { TechTable } from './TechTable'
import { JwtScan } from './JwtScan'
import { Probe } from './Probe'
import { DomainScan } from './DomainScan'
import { SecretScan } from './SecretScan'
import { BreachCheck } from './BreachCheck'
import { Bypass403 } from './Bypass403'
import { GitDump } from './GitDump'
import { PwReset } from './PwReset'
import { GraphqlEnum } from './GraphqlEnum'
import { ApiEnum } from './ApiEnum'
import { Cors } from './Cors'
import { OpenRedirect } from './OpenRedirect'
import { Ssrf } from './Ssrf'
import { Csrf } from './Csrf'
import { SstiScan } from './SstiScan'
import { PathTraversal } from './PathTraversal'
import { Idor } from './Idor'
import { Xxe } from './Xxe'
import { XssScan } from './XssScan'
import { Tester } from './Tester'
import { Collaborator } from './Collaborator'
import { FfufTab } from './Ffuf'
import { JobHistory } from './JobHistory'
import { TargetPicker } from './TargetPicker'
import { SaveToListModal } from './SaveToListModal'
import { TARGET_LIST_KINDS, TARGET_LIST_KIND_LABELS, TARGET_LIST_KIND_PLACEHOLDERS } from '../targetListKinds'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { showToast } from '../toast'
import { sendToJwtScanner, onJwtScannerRequest, type JwtScannerRequest } from '../jwtHandoff'
import { sendToProbe, onProbeRequest, type ProbeRequest } from '../probeHandoff'
import { sendToSecretScan, onSecretScanRequest, type SecretScanRequest } from '../secretScanHandoff'
import { sendToBypass403, onBypass403Request, type Bypass403HandoffRequest } from '../bypass403Handoff'
import { sendToTester, onTesterRequest, type TesterHandoffRequest } from '../testerHandoff'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { ScopeEditor } from './ScopeEditor'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { CredentialVault } from './CredentialVault'
import { CredentialPicker } from './CredentialPicker'
import { CookieVault } from './CookieVault'
import { JobTemplatePicker } from './JobTemplatePicker'
import { ScannerNav, scanBorderProps } from './ScannerNav'
import { NAV_GROUPS, PINNED_TABS, TAB_META, type Tab } from '../scannerNavData'

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

// JOB_INDICATOR_TABS are the tabs whose scans run as jobs tracked here in
// CaseView (identify and the recon tools), so their nav border is derived
// from those jobs rather than reported by the tab itself.
const JOB_INDICATOR_TABS: Tool[] = ['identify', 'feroxbuster', 'ffuf-subdomain', 'ffuf-vhost', 'ffuf-custom', 'subfinder', 'katana', 'nuclei']

// CaseView is one case's workspace: a left navbar switching between Targets,
// Identify, and each scanning tool, each rendered as its own tab
// so the user can see how each tool is doing independently. Every tool tab
// only ever runs when the user launches it from that tab's JobLauncher --
// nothing here starts anything on its own.
export function CaseView({ caseId }: { caseId: string }) {
  const [c, setCase] = useState<Case | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [targetLists, setTargetLists] = useState<TargetList[]>([])
  // Set whenever a tool result (or a discovered subdomain) is being saved
  // to the case from outside the Targets tab -- opens SaveToListModal to
  // ask which list it should go into. See promoteFromTool/confirmPromote.
  const [pendingPromote, setPendingPromote] = useState<{ values: string[]; save: (listId: string) => Promise<void> } | null>(null)
  const [credentials, setCredentials] = useState<Credential[]>([])
  const [cookieVault, setCookieVault] = useState<CookieVaultEntry[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [checks, setChecks] = useState<Record<string, Check>>({})
  const [runFindings, setRunFindings] = useState<Record<string, Finding[]>>({}) // keyed by jobId
  const [jobStatus, setJobStatus] = useState<Record<string, RunStatus>>({}) // keyed by jobId, overrides job.status once live events arrive
  // Keyed by `${jobId}:${nodeId}` since one job can have several source
  // nodes (one per target).
  const [jobProgress, setJobProgress] = useState<Record<string, { done: number; total: number }>>({})
  const [nodeStatus, setNodeStatus] = useState<Record<string, NodeStatus>>({})
  // When each node first started running, keyed like jobProgress. Kept in state
  // (not a ref) because the render reads it.
  const [nodeStartedAt, setNodeStartedAt] = useState<Record<string, number>>({})
  const [tab, setTab] = useState<Tab>('targets')
  // Each scanner tab's live state for the nav's border, keyed by tab id.
  // Scanner tabs publish theirs through ScanIndicatorContext; the job-driven
  // tabs are derived from jobs below.
  const [indicators, setIndicators] = useState<Record<string, ScanIndicator>>({})
  // Tabs that finished a run while the user was on another tab. Their border
  // breathes until the user opens them.
  const [unseen, setUnseen] = useState<Record<string, true>>({})
  // The phase each tab had the last time the unseen check ran, so it can tell
  // a run that just finished from one that was already done.
  const lastPhase = useRef<Record<string, ScanPhase>>({})
  // Whether the scope editor is open under the case header.
  const [scopeOpen, setScopeOpen] = useState(false)
  const [reportFormat, setReportFormat] = useState<'json' | 'html' | 'pdf'>('html')
  // Collapses the tab nav to a slim dot rail so a case with many tools open
  // gives the active tab's content the width instead of a permanently fixed
  // 12rem sidebar -- persisted like every other collapse toggle in this file.
  const [navOpen, setNavOpen] = useCollapsible('caseNav', true)
  // Set by a "Send to JWT Scanner" context-menu item anywhere in this case
  // (Targets list, tool results -- see
  // jwtHandoff.ts); JwtScan applies it even though it stays mounted the
  // whole time this case is open.
  const [jwtPrefill, setJwtPrefill] = useState<JwtScannerRequest | undefined>()
  // Set by a "Send to Probe" context-menu item, same shape as jwtPrefill
  // above -- see probeHandoff.ts.
  const [probePrefill, setProbePrefill] = useState<ProbeRequest | undefined>()
  // Set by a "Send to Secret Scanner" context-menu item -- see
  // secretScanHandoff.ts.
  const [secretScanPrefill, setSecretScanPrefill] = useState<SecretScanRequest | undefined>()
  // Set by a "Send to 403 Bypass" context-menu item -- see
  // bypass403Handoff.ts.
  const [bypass403Prefill, setBypass403Prefill] = useState<Bypass403HandoffRequest | undefined>()
  // Set by a "Send to Tester" context-menu item anywhere in this case
  // (any scanner's findings, a raw target/URL) -- see testerHandoff.ts.
  const [testerPrefill, setTesterPrefill] = useState<TesterHandoffRequest | undefined>()

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
    return onBypass403Request((req) => {
      setBypass403Prefill(req)
      setTab('bypass403')
    })
  }, [])

  useEffect(() => {
    return onTesterRequest((req) => {
      setTesterPrefill(req)
      setTab('tester')
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
        setNodeStartedAt((prev) => (prev[key] ? prev : { ...prev, [key]: Date.now() }))
        setJobProgress((prev) => ({ ...prev, [key]: { done: ev.done ?? 0, total: ev.total ?? 0 } }))
      } else if (ev.type === 'status' && ev.nodeId && ev.status) {
        const key = `${job.id}:${ev.nodeId}`
        if (ev.status === 'running') setNodeStartedAt((prev) => (prev[key] ? prev : { ...prev, [key]: Date.now() }))
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
    setTargetLists([])
    setCredentials([])
    setCookieVault([])
    setJobs([])
    setChecks({})
    setRunFindings({})
    setJobStatus({})
    setJobProgress({})
    setNodeStatus({})
    setNodeStartedAt({})
    setTab('targets')
    Object.values(stopJobWatches.current).forEach((stop) => stop())
    stopJobWatches.current = {}

    api.getCase(caseId).then((full) => {
      if (!cancelled) setCase(full)
    })
    api.listTargets(caseId).then((t) => {
      if (!cancelled) setTargets(t)
    })
    api.listTargetLists(caseId).then((l) => {
      if (!cancelled) setTargetLists(l)
    })
    api.listCredentials(caseId).then((c) => {
      if (!cancelled) setCredentials(c)
    })
    api.listCookieVault(caseId).then((v) => {
      if (!cancelled) setCookieVault(v)
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
    // A new target can add a domain the cookie vault hasn't seen yet.
    refreshCookieVault()
  }

  const refreshTargetLists = () => {
    api.listTargetLists(caseId).then(setTargetLists)
  }

  const createTargetList = async (name: string, kind: TargetListKind) => {
    const list = await api.createTargetList(caseId, name, kind)
    refreshTargetLists()
    return list
  }

  const refreshCredentials = () => {
    api.listCredentials(caseId).then(setCredentials)
  }

  const refreshCookieVault = () => {
    api.listCookieVault(caseId).then(setCookieVault)
  }

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

  // requestSaveTargets opens the "which list?" prompt for any save flow
  // that isn't already inside a specific list tab (promoting tool results,
  // saving discovered subdomains) -- save is called with the list the user
  // picked (or just created) once they confirm.
  const requestSaveTargets = (values: string[], save: (listId: string) => Promise<void>) => {
    if (values.length === 0) return
    setPendingPromote({ values, save })
  }

  // Left for SaveToListModal to catch and display inline -- no toast here,
  // so a failed save leaves the modal open with the error instead of
  // dismissing it silently.
  const confirmPromote = async (listId: string) => {
    if (!pendingPromote) return
    await pendingPromote.save(listId)
  }

  const promoteFromTool = (tool: Tool, values: string[]) => {
    const latest = [...jobsOfTool(tool)].pop()
    if (!latest) return
    requestSaveTargets(values, async (listId) => {
      await api.promoteTargets(caseId, latest.id, listId, values)
      showToast(`Saved ${values.length} target${values.length === 1 ? '' : 's'} to the case`, 'success')
      refreshTargets()
    })
  }

  // reportIndicator is the reporter every scanner tab gets through
  // ScanIndicatorContext. It is stable, and it skips a report that changes
  // nothing, so a scan's progress events don't re-render the whole case.
  const reportIndicator = useCallback((key: string, indicator: ScanIndicator) => {
    setIndicators((prev) => {
      const before = prev[key]
      if (before && before.phase === indicator.phase && before.severity === indicator.severity) return prev
      return { ...prev, [key]: indicator }
    })
  }, [])

  // The job-driven tabs report from their jobs: running while any job is,
  // otherwise done with the worst severity their findings carry (only nuclei
  // findings carry one).
  useEffect(() => {
    for (const tool of JOB_INDICATOR_TABS) {
      const list = jobsOfTool(tool)
      // Never run: nothing to outline.
      if (list.length === 0) {
        reportIndicator(tool, IDLE_INDICATOR)
        continue
      }
      if (list.some((j) => statusOf(j) === 'running')) {
        reportIndicator(tool, { phase: 'running', severity: null })
        continue
      }
      let severity: IndicatorSeverity | null = null
      for (const f of findingsOfTool(tool)) severity = worseSeverity(severity, severityOfName(f.severity))
      reportIndicator(tool, { phase: 'done', severity })
    }
    // jobsOfTool, statusOf and findingsOfTool are plain render helpers over
    // jobs, jobStatus and runFindings, which are the deps listed here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobs, jobStatus, runFindings, reportIndicator])

  // Works out which tabs finished a run while they were off screen. Those stay
  // unseen (and their border breathes) until the user opens them. A tab that
  // starts running again is no longer unseen, since it is showing live.
  useEffect(() => {
    const finishedElsewhere: string[] = []
    const started: string[] = []
    for (const [key, ind] of Object.entries(indicators)) {
      const was = lastPhase.current[key]
      lastPhase.current[key] = ind.phase
      if (ind.phase === 'running') started.push(key)
      // A run that finished on a tab the user isn't looking at.
      else if (ind.phase === 'done' && was === 'running' && key !== tab) finishedElsewhere.push(key)
    }
    if (started.length === 0 && finishedElsewhere.length === 0) return
    setUnseen((prev) => {
      let changed = false
      const next = { ...prev }
      for (const key of started) {
        if (!next[key]) continue
        delete next[key]
        changed = true
      }
      for (const key of finishedElsewhere) {
        if (next[key]) continue
        next[key] = true
        changed = true
      }
      return changed ? next : prev
    })
  }, [indicators, tab])

  // Opening a tab marks it seen, however the user got there (a click, or a
  // "Send to X" handoff switching tabs for them).
  useEffect(() => {
    setUnseen((prev) => {
      if (!prev[tab]) return prev
      const next = { ...prev }
      delete next[tab]
      return next
    })
  }, [tab])

  if (!c) {
    return <div className="p-8 text-neutral-500">Loading…</div>
  }

  const runningJobs = jobs.filter((j) => statusOf(j) === 'running')
  const counts: Record<Tab, number | null> = {
    targets: targets.length,
    identify: null,
    feroxbuster: findingsOfTool('feroxbuster').length,
    'ffuf-subdomain': findingsOfTool('ffuf-subdomain').length,
    'ffuf-vhost': findingsOfTool('ffuf-vhost').length,
    'ffuf-custom': findingsOfTool('ffuf-custom').length,
    subfinder: findingsOfTool('subfinder').length,
    katana: findingsOfTool('katana').length,
    nuclei: findingsOfTool('nuclei').length,
    jwtscan: null,
    probe: null,
    domainscan: null,
    secrets: null,
    breach: null,
    bypass403: null,
    gitdump: null,
    pwreset: null,
    graphqlenum: null,
    apienum: null,
    corsscan: null,
    openredirect: null,
    ssrf: null,
    csrf: null,
    sstiscan: null,
    pathtraversal: null,
    idor: null,
    xxe: null,
    xss: null,
    tester: null,
    collaborator: null,
    credentials: credentials.length,
    cookieVault: cookieVault.filter((e) => e.cookie).length,
  }

  return (
    <ScanIndicatorContext.Provider value={reportIndicator}>
      <div className="flex h-full flex-col">
        <header className="flex items-center gap-3 border-b border-neutral-800 bg-neutral-950 px-4 py-2">
          <h1 className="text-sm font-medium text-neutral-100">{c.name}</h1>
          <button
            type="button"
            onClick={() => setScopeOpen((v) => !v)}
            className="rounded border border-neutral-700 px-2 py-0.5 text-xs text-neutral-300 hover:bg-neutral-800"
          >
            Scope{scopeOpen ? ' ▴' : ' ▾'}
          </button>
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
        {scopeOpen && <ScopeEditor key={c.id} caseId={c.id} />}

        <div className="flex flex-1 overflow-hidden">
          {navOpen ? (
            <aside className="flex shrink-0 flex-col overflow-y-auto border-r border-neutral-800 bg-neutral-950 p-2">
              <button onClick={() => setNavOpen(false)} title="Collapse" className="mb-1 self-end px-1 text-xs text-neutral-600 hover:text-neutral-300">
                ◂
              </button>
              <ScannerNav activeTab={tab} indicators={indicators} unseen={unseen} counts={counts} onSelect={setTab} />
            </aside>
          ) : (
            <aside className="flex w-9 shrink-0 flex-col items-center gap-1 overflow-y-auto border-r border-neutral-800 bg-neutral-950 py-2">
              <button onClick={() => setNavOpen(true)} title="Expand navigation" className="mb-1 text-neutral-600 hover:text-neutral-300">
                ▸
              </button>
              {[...PINNED_TABS, ...NAV_GROUPS.flatMap((g) => g.tabs)].map((id) => {
                const Icon = TAB_META[id].icon
                // The rail is too small for the tile's text, so it shows the same
                // scan border on the icon button alone.
                const scan = scanBorderProps(indicators[id], !!unseen[id])
                return (
                  <button
                    key={id}
                    onClick={() => setTab(id)}
                    title={`${TAB_META[id].label}${counts[id] !== null ? ` (${counts[id]})` : ''}`}
                    style={scan.style}
                    className={`relative flex h-7 w-7 items-center justify-center rounded border ${scan.className} ${
                      scan.ownBorder ? '' : 'border-transparent'
                    } ${tab === id ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300'}`}
                  >
                    <Icon className="h-4 w-4" />
                    {indicators[id]?.phase === 'done' && (
                      <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full" style={{ background: INDICATOR_COLOR[indicators[id]?.severity ?? 'clean'] }} />
                    )}
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
            <div className={`h-full overflow-y-auto ${tab === 'targets' ? '' : 'hidden'}`}>
              <TargetsTab caseId={caseId} targets={targets} lists={targetLists} onChange={refreshTargets} onListsChanged={refreshTargetLists} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'credentials' ? '' : 'hidden'}`}>
              <CredentialVault caseId={caseId} credentials={credentials} onChanged={refreshCredentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'cookieVault' ? '' : 'hidden'}`}>
              <CookieVault caseId={caseId} entries={cookieVault} onChanged={refreshCookieVault} />
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
                requestSaveTargets={requestSaveTargets}
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
                nodeStartedAt={nodeStartedAt}
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
                nodeStartedAt={nodeStartedAt}
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
                nodeStartedAt={nodeStartedAt}
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
                nodeStartedAt={nodeStartedAt}
                onStart={addJob}
                onCancel={cancelJob}
                onPromote={(values) => promoteFromTool('subfinder', values)}
                wordlistField={false}
                credentialField={false}
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
                nodeStartedAt={nodeStartedAt}
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
                nodeStartedAt={nodeStartedAt}
                onStart={addJob}
                onCancel={cancelJob}
                onPromote={(values) => promoteFromTool('ffuf-custom', values)}
              />
            </div>

            <div className={`h-full ${tab === 'nuclei' ? '' : 'hidden'}`}>
              <ToolTab
                caseId={caseId}
                tool="nuclei"
                targets={targets}
                credentials={credentials}
                jobs={jobsOfTool('nuclei')}
                findings={findingsOfTool('nuclei')}
                statusOf={statusOf}
                nodeStatus={nodeStatus}
                jobProgress={jobProgress}
                nodeStartedAt={nodeStartedAt}
                onStart={addJob}
                onCancel={cancelJob}
                onPromote={(values) => promoteFromTool('nuclei', values)}
                schemeField
                wordlistField={false}
                credentialField={false}
                resultsView={(nucleiFindings) => <NucleiResults findings={nucleiFindings} />}
              />
            </div>

            <div className={`h-full overflow-hidden ${tab === 'jwtscan' ? '' : 'hidden'}`}>
              <JwtScan caseId={caseId} targets={targets} credentials={credentials} prefill={jwtPrefill} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'probe' ? '' : 'hidden'}`}>
              <Probe caseId={caseId} targets={targets} credentials={credentials} prefill={probePrefill} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'domainscan' ? '' : 'hidden'}`}>
              <DomainScan caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'secrets' ? '' : 'hidden'}`}>
              <SecretScan caseId={caseId} targets={targets} credentials={credentials} prefill={secretScanPrefill} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'breach' ? '' : 'hidden'}`}>
              <BreachCheck caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'bypass403' ? '' : 'hidden'}`}>
              <Bypass403 caseId={caseId} targets={targets} credentials={credentials} prefill={bypass403Prefill} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'gitdump' ? '' : 'hidden'}`}>
              <GitDump caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'pwreset' ? '' : 'hidden'}`}>
              <PwReset caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'graphqlenum' ? '' : 'hidden'}`}>
              <GraphqlEnum caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'apienum' ? '' : 'hidden'}`}>
              <ApiEnum caseId={caseId} targets={targets} credentials={credentials} requestSaveTargets={requestSaveTargets} onTargetsChanged={refreshTargets} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'corsscan' ? '' : 'hidden'}`}>
              <Cors caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'openredirect' ? '' : 'hidden'}`}>
              <OpenRedirect caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'ssrf' ? '' : 'hidden'}`}>
              <Ssrf caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'csrf' ? '' : 'hidden'}`}>
              <Csrf caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'sstiscan' ? '' : 'hidden'}`}>
              <SstiScan caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'pathtraversal' ? '' : 'hidden'}`}>
              <PathTraversal caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'idor' ? '' : 'hidden'}`}>
              <Idor caseId={caseId} targets={targets} credentials={credentials} cookieVault={cookieVault} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'xxe' ? '' : 'hidden'}`}>
              <Xxe caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'xss' ? '' : 'hidden'}`}>
              <XssScan caseId={caseId} targets={targets} credentials={credentials} />
            </div>

            <div className={`h-full overflow-hidden ${tab === 'tester' ? '' : 'hidden'}`}>
              <Tester caseId={caseId} targets={targets} credentials={credentials} cookieVault={cookieVault} prefill={testerPrefill} />
            </div>

            <div className={`h-full overflow-y-auto ${tab === 'collaborator' ? '' : 'hidden'}`}>
              <Collaborator />
            </div>

          </div>
        </div>

        {pendingPromote && (
          <SaveToListModal
            lists={targetLists}
            itemLabel={`${pendingPromote.values.length} target${pendingPromote.values.length === 1 ? '' : 's'}`}
            onPick={confirmPromote}
            onCreateList={createTargetList}
            onClose={() => setPendingPromote(null)}
          />
        )}
      </div>
    </ScanIndicatorContext.Provider>
  )
}

// --- Targets tab ---

// parseTargetValues splits a batch of pasted/typed/imported targets into
// individual values. Both newlines and commas count as separators, so a list
// copied in either shape (one per line, or comma-joined) works. Entries are
// trimmed, blanks dropped, and duplicates within the batch collapsed so the
// same host pasted twice is only added once.
function parseTargetValues(raw: string): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  // A run of any mix of newlines and commas is a single separator, so
  // "a,b\n\nc," still yields exactly [a, b, c].
  for (const part of raw.split(/[\n,]+/)) {
    const v = part.trim()
    // Skip blanks and values already seen earlier in this same batch.
    if (!v || seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}

// TargetsTab is where the case's target lists themselves are managed --
// one tab per list (plus "+ New list"), like a row of Spotify playlists.
// Unlike SaveToListModal (the "which list?" prompt every other save flow
// goes through), adding a target here always goes straight into whichever
// list tab is currently open -- you're already looking at the destination.
function TargetsTab({
  caseId,
  targets,
  lists,
  onChange,
  onListsChanged,
}: {
  caseId: string
  targets: Target[]
  lists: TargetList[]
  onChange: () => void
  onListsChanged: () => void
}) {
  const { openMenu } = useContextMenu()
  // Falls back to the first list whenever the explicitly picked one is
  // unset or has been deleted out from under it, rather than tracking that
  // fallback as its own state (which would need an effect to stay in sync
  // once lists loads or a list gets deleted).
  const [pickedListId, setPickedListId] = useState<string | null>(null)
  const activeListId = pickedListId && lists.some((l) => l.id === pickedListId) ? pickedListId : (lists[0]?.id ?? null)

  const [value, setValue] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')
  // Hidden <input type="file"> driven by the "Import file" button, so the
  // import affordance reads as a normal button rather than a bare file picker.
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [creatingList, setCreatingList] = useState(false)
  const [newListName, setNewListName] = useState('')
  const [newListKind, setNewListKind] = useState<TargetListKind>('domain')

  // Ping verdicts are keyed by target id, so a row keeps its result while the
  // user switches lists. Target ids are unique, so stale entries are harmless.
  const [pingResults, setPingResults] = useState<Record<string, TargetPingResult>>({})
  const [pinging, setPinging] = useState(false)

  const createList = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = newListName.trim()
    if (!trimmed) return
    try {
      const list = await api.createTargetList(caseId, trimmed, newListKind)
      onListsChanged()
      setPickedListId(list.id)
      setCreatingList(false)
      setNewListName('')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  const renameList = async (list: TargetList) => {
    const name = window.prompt('Rename list', list.name)
    if (!name || !name.trim() || name.trim() === list.name) return
    try {
      await api.renameTargetList(list.id, name.trim())
      onListsChanged()
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  const deleteList = async (list: TargetList) => {
    try {
      await api.deleteTargetList(list.id)
      onListsChanged()
      onChange()
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  // pingList checks every target in one list and records each verdict as it
  // arrives, so rows light up one by one rather than all at once at the end.
  // Each verdict is merged into the existing map, so other lists' results stay.
  const pingList = async (listId: string) => {
    setPinging(true)
    try {
      await api.pingTargetList(listId, (r) => {
        // Keyed by target id so the verdict lands on the right row.
        setPingResults((prev) => ({ ...prev, [r.targetId]: r }))
      })
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setPinging(false)
    }
  }

  const add = async (e: React.FormEvent) => {
    e.preventDefault()
    const values = parseTargetValues(value)
    if (values.length === 0 || !activeListId) return
    setAdding(true)
    setError('')
    // Collect per-value failures so one bad entry (e.g. out of scope) doesn't
    // discard the rest of the batch or hide which ones didn't make it.
    const failures: string[] = []
    await Promise.all(
      values.map(async (v) => {
        try {
          await api.addTarget(caseId, v, activeListId)
        } catch (err) {
          failures.push(`${v}: ${err instanceof Error ? err.message : String(err)}`)
        }
      }),
    )
    const added = values.length - failures.length
    // Only clear the box and refresh when something actually landed.
    if (added > 0) {
      setValue('')
      onChange()
      // Toast only for real batches; a single add stays as quiet as before.
      if (added > 1) showToast(`Added ${added} targets to ${activeList?.name ?? 'list'}`, 'success')
    }
    if (failures.length > 0) {
      setError(`${failures.length} of ${values.length} failed:\n${failures.join('\n')}`)
    }
    setAdding(false)
  }

  // importFile loads a target file from disk and merges its lines into the
  // input box, so the user can review/trim the batch before hitting Add rather
  // than having the file committed straight to the list.
  const importFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    // Clear the picker so choosing the same file again still fires onChange.
    e.target.value = ''
    if (!file) return
    try {
      const text = await file.text()
      // Append to whatever is already typed rather than clobbering it, keeping
      // a newline between the existing entry and the imported block.
      setValue((prev) => (prev.trim() ? `${prev.trim()}\n${text}` : text))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
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

  const activeList = lists.find((l) => l.id === activeListId)
  const listTargets = targets.filter((t) => t.listId === activeListId)
  // Directory and file lists hold local paths, so there is nothing to ping.
  const pingable = activeList !== undefined && activeList.kind !== 'directory' && activeList.kind !== 'file'
  // Only this list's targets that have a verdict count toward the summary.
  const checked = listTargets.map((t) => pingResults[t.id]).filter((r): r is TargetPingResult => r !== undefined)
  const aliveCount = checked.filter((r) => r.alive).length

  return (
    <div className="mx-auto max-w-3xl space-y-4 px-4 py-6">
      <div className="flex flex-wrap items-center gap-1.5 border-b border-neutral-800 pb-2">
        {lists.map((l) => (
          <button
            key={l.id}
            type="button"
            onClick={() => setPickedListId(l.id)}
            onContextMenu={(e) => {
              e.stopPropagation()
              openMenu(e, [
                { label: 'Rename list', onSelect: () => renameList(l) },
                { label: 'Delete list', onSelect: () => deleteList(l), danger: true },
              ])
            }}
            className={`rounded border-b-2 px-3 py-1.5 text-xs font-medium ${
              activeListId === l.id ? 'border-sky-500 text-sky-300' : 'border-transparent text-neutral-400 hover:text-neutral-200'
            }`}
          >
            {l.name} <span className="text-neutral-600">{targets.filter((t) => t.listId === l.id).length}</span>
          </button>
        ))}
        {!creatingList ? (
          <button
            type="button"
            onClick={() => setCreatingList(true)}
            className="rounded border border-dashed border-neutral-700 px-2 py-1 text-xs text-neutral-500 hover:border-sky-600 hover:text-sky-400"
          >
            + New list
          </button>
        ) : (
          <form onSubmit={createList} className="flex items-center gap-1">
            <input
              autoFocus
              value={newListName}
              onChange={(e) => setNewListName(e.target.value)}
              placeholder="List name…"
              className="w-32 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
            />
            <select
              value={newListKind}
              onChange={(e) => setNewListKind(e.target.value as TargetListKind)}
              className="rounded border border-neutral-700 bg-neutral-900 px-1 py-1 text-xs text-neutral-200 outline-none focus:border-sky-500"
            >
              {TARGET_LIST_KINDS.map((k) => (
                <option key={k} value={k}>
                  {TARGET_LIST_KIND_LABELS[k]}
                </option>
              ))}
            </select>
            <button type="submit" disabled={!newListName.trim()} className="rounded bg-sky-600 px-2 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50">
              Create
            </button>
            <button
              type="button"
              onClick={() => {
                setCreatingList(false)
                setNewListName('')
              }}
              className="text-xs text-neutral-500 hover:text-neutral-300"
            >
              Cancel
            </button>
          </form>
        )}
      </div>

      {lists.length === 0 ? (
        <p className="px-3 py-8 text-center text-xs text-neutral-600">No target lists yet — create one above to start saving targets.</p>
      ) : (
        <>
          <form onSubmit={add} className="flex gap-2">
            <textarea
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                // Cmd/Ctrl+Enter submits; a bare Enter adds a newline so the
                // box can hold a multi-line batch.
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault()
                  add(e as unknown as React.FormEvent)
                }
              }}
              rows={2}
              placeholder={activeList ? `${TARGET_LIST_KIND_PLACEHOLDERS[activeList.kind]} — one per line or comma-separated` : ''}
              className="flex-1 resize-y rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm text-neutral-100 outline-none focus:border-sky-500"
            />
            <div className="flex flex-col gap-2">
              <button
                type="submit"
                disabled={adding || parseTargetValues(value).length === 0}
                className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
              >
                {adding ? 'Adding…' : `Add to ${activeList?.name ?? 'list'}`}
              </button>
              {/* Hidden picker; the visible button below triggers it. */}
              <input ref={fileInputRef} type="file" accept=".txt,.csv,.lst,text/*" onChange={importFile} className="hidden" />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm font-medium text-neutral-300 hover:border-sky-600 hover:text-sky-400"
              >
                Import file
              </button>
            </div>
          </form>
          {error && <p className="whitespace-pre-wrap text-sm text-red-400">{error}</p>}

          <div className="rounded-lg border border-neutral-800">
            <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
              <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">{activeList?.name}</h2>
              <span className="text-xs text-neutral-600">{listTargets.length}</span>
              {pingable && listTargets.length > 0 && (
                <div className="ml-auto flex items-center gap-3">
                  {checked.length > 0 && (
                    <span className="text-xs text-neutral-500">
                      {aliveCount} alive · {checked.length - aliveCount} unreachable
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => activeListId && pingList(activeListId)}
                    disabled={pinging}
                    className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:border-sky-600 hover:text-sky-400 disabled:opacity-50"
                  >
                    {pinging ? 'Checking…' : 'Check alive'}
                  </button>
                </div>
              )}
            </div>
            {listTargets.length === 0 ? (
              <p className="px-3 py-8 text-center text-xs text-neutral-600">
                No targets yet — add one above, or run a tool and save some of its results here.
              </p>
            ) : (
              <div className="divide-y divide-neutral-900">
                {listTargets.map((t) => (
                  <div
                    key={t.id}
                    onContextMenu={(e) => {
                      e.stopPropagation()
                      openMenu(e, [
                        { label: 'Copy value', onSelect: () => copyToClipboard(t.value, 'Copied target') },
                        { label: 'Send to JWT', onSelect: () => sendToJwtScanner(t.value) },
                        { label: 'Send to Probe', onSelect: () => sendToProbe(t.value) },
                        { label: 'Send to Secrets', onSelect: () => sendToSecretScan(t.value) },
                        { label: 'Send to 403 Bypass', onSelect: () => sendToBypass403(t.value) },
                        { label: 'Send to Tester', onSelect: () => sendToTester(t.value) },
                        'separator',
                        { label: 'Remove target', onSelect: () => remove(t), danger: true },
                      ])
                    }}
                    className="flex items-center gap-3 px-3 py-2 text-sm hover:bg-neutral-900/60"
                  >
                    <span className="min-w-0 flex-1 truncate font-mono text-neutral-200">{t.value}</span>
                    {pingResults[t.id] && <PingStatus ping={pingResults[t.id]} />}
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
        </>
      )}
    </div>
  )
}

// PingStatus is the alive/unreachable badge on a target row after a list ping.
// An unreachable row shows the transport error as its tooltip.
function PingStatus({ ping }: { ping: TargetPingResult }) {
  return (
    <span
      title={ping.alive ? ping.url : ping.error}
      className={`shrink-0 rounded border px-1.5 py-0.5 text-xs ${
        ping.alive ? 'border-emerald-800 text-emerald-400' : 'border-red-900 text-red-400'
      }`}
    >
      {ping.alive ? `alive · ${ping.statusCode}` : 'unreachable'}
    </span>
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
  requestSaveTargets,
}: {
  caseId: string
  targets: Target[]
  jobs: Job[]
  statusOf: (job: Job) => RunStatus
  checks: Record<string, Check>
  onStart: (job: Job) => void
  onCancel: (job: Job) => void
  onTargetsChanged: () => void
  requestSaveTargets: (values: string[], save: (listId: string) => Promise<void>) => void
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

  const saveSubdomains = (values: string[]) => {
    requestSaveTargets(values, async (listId) => {
      await Promise.all(values.map((v) => api.addTarget(caseId, v, listId)))
      showToast(`Saved ${values.length} target${values.length === 1 ? '' : 's'} to the case`, 'success')
      onTargetsChanged()
    })
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
  nodeStartedAt,
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
  resultsView,
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
  nodeStartedAt: Record<string, number>
  onStart: (job: Job) => void
  onCancel: (job: Job) => void
  onPromote: (values: string[]) => void
  deriveTargetValue?: (f: Finding) => string
  schemeField?: boolean
  hostSuffixField?: boolean
  recursiveField?: boolean
  // wordlistField hides the wordlist-file tuning input for tools that
  // don't fuzz off a wordlist at all (subfinder/katana) --
  // true (shown) for every wordlist-driven tool that predates
  // this flag.
  wordlistField?: boolean
  // credentialField hides the saved-credential picker for tools that never
  // issue an authenticated request to the target at all (subfinder,
  // which only ever query third-party OSINT sources) -- true (shown) for
  // every tool that predates this flag.
  credentialField?: boolean
  // disabledMessage, when set, replaces this tab's launcher with a static
  // notice and blocks starting a new job entirely -- for a tool that's
  // known broken right now rather than one the user just hasn't run yet.
  // Past jobs/results (if any) still render below it as usual.
  disabledMessage?: string
  // resultsView, when set, replaces the default ResultsTable in the results
  // pane -- for a tool whose findings need a purpose-built display (nuclei's
  // severity-grouped view) rather than the generic status/size/words table
  // every wordlist/crawl-style tool shares. The per-target progress panel
  // alongside it is unaffected either way.
  resultsView?: (findings: Finding[]) => React.ReactNode
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
        const startedAt = nodeStartedAt[key] ?? null
        const detail = job.nodes?.find((n) => n.nodeId === nodeId)
        rows.push({
          key, target, status, done, total, etaSeconds: estimateEtaSeconds(done, total, startedAt), startedAt,
          wordlist: detail?.wordlist, extensions: detail?.extensions, candidates: detail?.candidates,
          threads: detail?.threads, timeoutSeconds: detail?.timeoutSeconds, rateLimit: detail?.rateLimit,
          runId: job.runId, nodeId,
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
        const startedAt = nodeStartedAt[key] ?? null
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
          {resultsView ? (
            resultsView(findings)
          ) : (
            <ResultsTable findings={findings} caseId={caseId} facetPlacement="right" selectable onPromote={onPromote} deriveTargetValue={deriveTargetValue} />
          )}
        </div>
      </div>
    </div>
  )
}
