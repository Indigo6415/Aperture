import { useEffect, useRef, useState } from 'react'
import { api, screenshotPreviewEnabled, watchRun, watchScan } from '../api'
import type { Check, CheckKind, Finding, NodeStatus, RunStatus, Scan, ScanKind, ScanRun } from '../types'
import { STATUS_META } from '../statusMeta'
import { statusHexColor } from '../statusColor'
import { extensionOf, hostnameOf } from '../url'
import { isDangerousExtension } from '../extensions'
import { estimateEtaSeconds } from '../eta'
import { useScanGraph } from '../useScanGraph'
import { FacetFilterBar, type FacetDimension } from './FacetFilterBar'
import { ResultsTable, Thumbnail } from './ResultsTable'
import { ProgressBar } from './ProgressBar'
import { TargetProgressPanel, type TargetProgress } from './TargetProgressPanel'
import { SummaryCard } from './SummaryCard'
import { GraphCanvas } from './GraphCanvas'
import { PortsTable } from './PortsTable'
import { VulnTable } from './VulnTable'

const CHECK_LABELS: Record<CheckKind, string> = {
  dns: 'DNS',
  tls: 'TLS',
  http: 'HTTP',
  subdomains: 'Subdomains',
  whois: 'WHOIS',
  takeover: 'Takeover',
  dnsdumpster: 'DNSDumpster',
}

const STATUS_DOT: Record<Check['status'] | 'pending', string> = {
  pending: '#6b7280',
  running: '#facc15',
  done: '#34d399',
  error: '#f87171',
}

function keyFor(domain: string, kind: CheckKind): string {
  return `${domain}::${kind}`
}

type Tab = 'overview' | 'subdomains' | 'vhosts' | 'content-discovery' | 'ports' | 'services' | 'vulnerabilities'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'subdomains', label: 'Subdomains' },
  { id: 'vhosts', label: 'Virtual Hosts' },
  { id: 'content-discovery', label: 'Content Discovery' },
  { id: 'ports', label: 'Ports' },
  { id: 'services', label: 'Service Profile' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
]

// ScanView is one scan's dashboard: a left navbar switching between the
// scanners a scan runs (apex recon, subdomain bruteforce, virtual-host
// bruteforce, content discovery), each rendered as its own tab so the user
// can see how each one is performing independently instead of one long
// scrolling page.
export function ScanView({ scanId, onOpenGraph }: { scanId: string; onOpenGraph: () => void }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [checks, setChecks] = useState<Record<string, Check>>({})
  const [scanRuns, setScanRuns] = useState<ScanRun[]>([])
  const [runFindings, setRunFindings] = useState<Record<string, Finding[]>>({})
  const [runStatus, setRunStatus] = useState<Record<string, RunStatus>>({})
  // Keyed by `${runId}:${nodeId}` since one run (e.g. content discovery)
  // can have several source nodes (one ffuf+feroxbuster pair per target)
  // each reporting their own progress.
  const [runProgress, setRunProgress] = useState<Record<string, { done: number; total: number }>>({})
  // Per-node lifecycle state, same key scheme as runProgress -- lets the
  // Content Discovery tab tell a target still queued behind
  // maxConcurrentSourceNodes apart from one actually scanning with 0
  // progress reported yet.
  const [nodeStatus, setNodeStatus] = useState<Record<string, NodeStatus>>({})
  // Wall-clock time a node first went 'running', used to derive an ETA
  // from its done/total rate so far -- a plain ref (not state) since it's
  // read at render time, not something that should itself trigger one.
  const nodeStartedAtRef = useRef<Record<string, number>>({})
  const [tab, setTab] = useState<Tab>('overview')
  const [restartingScan, setRestartingScan] = useState(false)
  const [cancellingScan, setCancellingScan] = useState(false)
  const [restartError, setRestartError] = useState('')
  const [reportFormat, setReportFormat] = useState<'json' | 'html' | 'pdf'>('html')

  const stopScanWatch = useRef<() => void>(() => {})
  const stopRunWatches = useRef<Record<string, () => void>>({})

  const watchTheRun = (runId: string) => {
    if (stopRunWatches.current[runId]) return // already watching
    api.getRun(runId).then((r) => setRunStatus((prev) => ({ ...prev, [runId]: r.status })))
    api.listFindings(runId).then((all) => setRunFindings((prev) => ({ ...prev, [runId]: all })))
    stopRunWatches.current[runId] = watchRun(runId, (ev) => {
      if (ev.type === 'finding' && ev.finding) {
        const finding = ev.finding
        setRunFindings((prev) => ({ ...prev, [runId]: [...(prev[runId] ?? []), finding] }))
      } else if (ev.type === 'progress' && ev.nodeId) {
        const key = `${runId}:${ev.nodeId}`
        // A reconnect (page reload mid-run) never replays the 'status'
        // event that would normally stamp this -- progress ticks keep
        // streaming regardless, so treat the first one this tab sees as a
        // (slightly late) start reference rather than leaving ETA stuck
        // at "unknown" for the rest of the run.
        if (!nodeStartedAtRef.current[key]) nodeStartedAtRef.current[key] = Date.now()
        setRunProgress((prev) => ({ ...prev, [key]: { done: ev.done ?? 0, total: ev.total ?? 0 } }))
      } else if (ev.type === 'status' && ev.nodeId && ev.status) {
        const key = `${runId}:${ev.nodeId}`
        if (ev.status === 'running' && !nodeStartedAtRef.current[key]) nodeStartedAtRef.current[key] = Date.now()
        setNodeStatus((prev) => ({ ...prev, [key]: ev.status! }))
      } else if (ev.type === 'done') {
        setRunStatus((prev) => ({
          ...prev,
          [runId]: ev.status === 'failed' ? 'failed' : ev.status === 'cancelled' ? 'cancelled' : 'succeeded',
        }))
      }
    })
  }

  useEffect(() => {
    let cancelled = false
    setScan(null)
    setChecks({})
    setScanRuns([])
    setRunFindings({})
    setRunStatus({})
    setRunProgress({})
    setNodeStatus({})
    nodeStartedAtRef.current = {}
    setTab('overview')
    Object.values(stopRunWatches.current).forEach((stop) => stop())
    stopRunWatches.current = {}

    api.getScan(scanId).then((s) => {
      if (cancelled) return
      setScan(s)
      const byKey: Record<string, Check> = {}
      for (const c of s.checks ?? []) byKey[keyFor(c.domain, c.kind)] = c
      setChecks(byKey)
    })

    api.listScanRuns(scanId).then((runs) => {
      if (cancelled) return
      setScanRuns(runs)
      for (const r of runs) watchTheRun(r.runId)
    })

    stopScanWatch.current()
    stopScanWatch.current = watchScan(scanId, (ev) => {
      if (ev.type === 'check' && ev.check) {
        const check = ev.check
        setChecks((prev) => ({ ...prev, [keyFor(check.domain, check.kind)]: check }))
      } else if (ev.type === 'scanRun' && ev.kind && ev.flowId && ev.runId) {
        const run: ScanRun = {
          kind: ev.kind,
          flowId: ev.flowId,
          runId: ev.runId,
          status: 'running',
          targets: ev.targets,
          createdAt: new Date().toISOString(),
        }
        setScanRuns((prev) => [...prev, run])
        watchTheRun(ev.runId)
      }
    })

    return () => {
      cancelled = true
      stopScanWatch.current()
      Object.values(stopRunWatches.current).forEach((stop) => stop())
      stopRunWatches.current = {}
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  const statusOf = (run: ScanRun): RunStatus => runStatus[run.runId] ?? run.status

  const runsOfKind = (kind: ScanKind) => scanRuns.filter((r) => r.kind === kind)

  const findingsOfKind = (kind: ScanKind): Finding[] => {
    const runs = runsOfKind(kind)
    const byKey = new Map<string, Finding>()
    for (const run of runs) {
      for (const f of runFindings[run.runId] ?? []) {
        byKey.set(`${f.url}|${f.statusCode}`, f)
      }
    }
    return [...byKey.values()]
  }

  const kindStatus = (kind: ScanKind): RunStatus => {
    const runs = runsOfKind(kind)
    if (runs.length === 0) return 'pending'
    const statuses = runs.map(statusOf)
    if (statuses.includes('running')) return 'running'
    if (statuses.includes('failed')) return 'failed'
    if (statuses.includes('cancelled')) return 'cancelled'
    return 'succeeded'
  }

  // kindProgress sums progress across every node of every currently-running
  // run of a kind (a kind can have more than one run in flight if a restart
  // is fired while an earlier run of the same kind hasn't finished yet).
  // If any contributing node reports an unknowable total (total === 0,
  // e.g. feroxbuster), the aggregate is indeterminate too.
  const kindProgress = (kind: ScanKind): { done: number; total: number } | null => {
    const runningRunIds = new Set(runsOfKind(kind).filter((r) => statusOf(r) === 'running').map((r) => r.runId))
    if (runningRunIds.size === 0) return null
    let done = 0
    let total = 0
    let indeterminate = false
    for (const [key, p] of Object.entries(runProgress)) {
      const runId = key.slice(0, key.lastIndexOf(':'))
      if (!runningRunIds.has(runId)) continue
      done += p.done
      if (p.total === 0) indeterminate = true
      else total += p.total
    }
    return { done, total: indeterminate ? 0 : total }
  }

  // nodeStatusFallback covers a node this browser tab never saw a "status"
  // event for -- most commonly a fresh page load reconnecting mid-run or
  // after a run has already finished, since node status is pure live
  // pub/sub (nothing persists it server-side the way findings/run status
  // are). Progress events aren't persisted either, but they keep streaming
  // for as long as the node is genuinely still running, so a live
  // progress entry is trusted over the run's own (possibly stale) status
  // first; short of that, a run that isn't 'running' anymore means every
  // one of its nodes reached some final state, so its own status is a
  // reasonable stand-in even though it can't say *which* final state a
  // specific node landed in (e.g. one node failing when the run itself
  // reads "failed").
  const nodeStatusFallback = (key: string, runStatus: RunStatus): NodeStatus => {
    if (nodeStatus[key]) return nodeStatus[key]
    if (runProgress[key]) return 'running'
    return runStatus === 'running' ? 'pending' : runStatus
  }

  // contentDiscoveryTargets builds one row per target host across every
  // content-discovery run this scan has started (the initial apex-only
  // run, plus any later "scan selected subdomains" runs) -- ffuf-<i> and
  // feroxbuster-<i> both cover run.targets[i] (buildContentDiscoveryFlow
  // builds both in that same index order), so their progress and status
  // combine into one row per target instead of kindProgress's single
  // aggregate, which any one feroxbuster node (total always initially
  // unbounded due to recursion) used to force permanently indeterminate.
  const contentDiscoveryTargets = (): TargetProgress[] => {
    const rows: TargetProgress[] = []
    for (const run of runsOfKind('content-discovery')) {
      const targets = run.targets ?? []
      const runStatus = statusOf(run)
      for (let i = 0; i < targets.length; i++) {
        const ffufKey = `${run.runId}:ffuf-${i}`
        const feroxKey = `${run.runId}:feroxbuster-${i}`
        const ffufStatus = nodeStatusFallback(ffufKey, runStatus)
        const feroxStatus = nodeStatusFallback(feroxKey, runStatus)
        const ffufP = runProgress[ffufKey]
        const feroxP = runProgress[feroxKey]

        let status: TargetProgress['status'] = 'pending'
        if (ffufStatus === 'failed' || feroxStatus === 'failed') status = 'failed'
        else if (ffufStatus === 'running' || feroxStatus === 'running') status = 'running'
        else if (ffufStatus === 'succeeded' && feroxStatus === 'succeeded') status = 'succeeded'
        else if (ffufStatus === 'cancelled' || feroxStatus === 'cancelled') status = 'cancelled'
        else if (ffufStatus === 'queued' || feroxStatus === 'queued') status = 'queued'

        const done = (ffufP?.done ?? 0) + (feroxP?.done ?? 0)
        // Sum only the totals that are actually known -- treating an
        // unknown one (0) as a real value would silently shrink the
        // combined total instead of marking it indeterminate.
        const knownTotals = [ffufP, feroxP].filter((p): p is { done: number; total: number } => !!p && p.total > 0)
        const total = knownTotals.reduce((sum, p) => sum + p.total, 0)

        const starts = [nodeStartedAtRef.current[ffufKey], nodeStartedAtRef.current[feroxKey]].filter((t): t is number => t !== undefined)
        const startedAt = starts.length > 0 ? Math.min(...starts) : null
        const etaSeconds = estimateEtaSeconds(done, total, startedAt)

        rows.push({ key: `${run.runId}:${i}`, target: targets[i], status, done, total, etaSeconds })
      }
    }
    return rows
  }

  const restartScan = async () => {
    setRestartingScan(true)
    setRestartError('')
    try {
      await api.restartScan(scanId)
    } catch (err) {
      // Most commonly a 409: the scan (or one of its scanners) is already
      // running, so the backend refused to spawn a second overlapping copy
      // -- see handleRestartScan's doc comment.
      setRestartError(err instanceof Error ? err.message : String(err))
    } finally {
      setRestartingScan(false)
    }
  }

  const cancelScan = async () => {
    setCancellingScan(true)
    try {
      await api.cancelScan(scanId)
    } finally {
      setCancellingScan(false)
    }
  }

  // Called unconditionally (before the "still loading" early return below)
  // to satisfy the rules of hooks -- useScanGraph itself no-ops until both
  // scanId and domain are non-empty. Also doubles as this header's overall
  // progress bar source, since it's already watching every run's progress
  // events to build the graph -- no extra sockets needed.
  const { nodes: graphNodes, edges: graphEdges, progress: overallProgress } = useScanGraph(scanId, scan?.domain ?? '')

  // The Overview tab's embedded preview is a quick "shape of the site" at a
  // glance, not a tool for digging through every discovered page -- page
  // nodes (usually the vast majority once content discovery runs) are left
  // for the full graph (onOpenGraph) to show, where they can be filtered.
  const previewNodes = graphNodes.filter((n) => n.type !== 'page')
  const previewNodeIds = new Set(previewNodes.map((n) => n.id))
  const previewEdges = graphEdges.filter((e) => {
    const sourceId = typeof e.source === 'object' ? e.source.id : e.source
    const targetId = typeof e.target === 'object' ? e.target.id : e.target
    return previewNodeIds.has(String(sourceId)) && previewNodeIds.has(String(targetId))
  })

  if (!scan) {
    return <div className="p-8 text-neutral-500">Loading…</div>
  }

  const apexChecks: CheckKind[] = ['dns', 'tls', 'http', 'whois']
  // dnsdumpster only gets a card once it's actually run -- unlike the four
  // above, it's entirely optional (skipped whenever no API key is
  // configured, see Settings), so showing it unconditionally would leave a
  // permanently "Queued…" card for every scan that never has one.
  if (checks[keyFor(scan.domain, 'dnsdumpster')]) apexChecks.push('dnsdumpster')
  const subdomainsCheck = checks[keyFor(scan.domain, 'subdomains')]
  const passiveSubdomains = (subdomainsCheck?.data?.subdomains as string[] | undefined) ?? []
  const subdomainRows = buildSubdomainRows(scan.domain, passiveSubdomains, checks, findingsOfKind('subdomain-bruteforce'))
  const vhostFindings = findingsOfKind('vhost-bruteforce')
  const contentFindings = findingsOfKind('content-discovery')
  const portFindings = findingsOfKind('port-scan')
  const serviceFindings = findingsOfKind('service-profile')
  const vulnFindings = findingsOfKind('vuln-scan')
  const apexDNSDone = checks[keyFor(scan.domain, 'dns')]?.status === 'done'
  const hasVHostRun = runsOfKind('vhost-bruteforce').length > 0
  const cloudflare = Boolean(checks[keyFor(scan.domain, 'http')]?.data?.cloudflare)

  // Critical files: content-discovery + vhost findings whose URL extension
  // is on the "worth a second look" list (backups, configs, credentials,
  // archives). Restricted to status 200 -- a 403/404 on a dangerous
  // extension isn't an exposed file, it's just noise -- sorted by URL since
  // every remaining row shares the same status code.
  const criticalFindings = [...contentFindings, ...vhostFindings]
    .filter((f) => f.statusCode === 200 && isDangerousExtension(extensionOf(f.url)))
    .sort((a, b) => a.url.localeCompare(b.url))

  // Page count per subdomain, for the subdomain list below -- counts
  // content-discovery findings (path bruteforce results) whose hostname
  // matches, so "pages" means "paths found on that host," not vhost hits.
  const pageCountByHost = new Map<string, number>()
  for (const f of contentFindings) {
    const h = hostnameOf(f.url)
    if (!h) continue
    pageCountByHost.set(h, (pageCountByHost.get(h) ?? 0) + 1)
  }
  const subdomainsWithPages = [...subdomainRows]
    .map((r) => ({ ...r, pages: pageCountByHost.get(r.hostname) ?? 0 }))
    .sort((a, b) => b.pages - a.pages || a.hostname.localeCompare(b.hostname))

  const hasPortScanRun = runsOfKind('port-scan').length > 0
  const hasServiceProfileRun = runsOfKind('service-profile').length > 0
  const hasVulnScanRun = runsOfKind('vuln-scan').length > 0

  const counts: Record<Tab, number | null> = {
    overview: null,
    subdomains: subdomainRows.length,
    vhosts: vhostFindings.length,
    'content-discovery': contentFindings.length,
    ports: portFindings.length,
    services: serviceFindings.length,
    vulnerabilities: vulnFindings.length,
  }
  const dots: Record<Tab, string> = {
    overview: apexChecks.every((k) => checks[keyFor(scan.domain, k)]?.status === 'done') ? STATUS_DOT.done : STATUS_DOT.running,
    subdomains: STATUS_META[kindStatus('subdomain-bruteforce')].dot,
    vhosts: hasVHostRun ? STATUS_META[kindStatus('vhost-bruteforce')].dot : STATUS_DOT.pending,
    'content-discovery': STATUS_META[kindStatus('content-discovery')].dot,
    ports: hasPortScanRun ? STATUS_META[kindStatus('port-scan')].dot : STATUS_DOT.pending,
    services: hasServiceProfileRun ? STATUS_META[kindStatus('service-profile')].dot : STATUS_DOT.pending,
    vulnerabilities: hasVulnScanRun ? STATUS_META[kindStatus('vuln-scan')].dot : STATUS_DOT.pending,
  }

  // Anything still in flight -- apex recon (checks not yet present are still
  // pending, same convention as `dots.overview` above) or any of the
  // scanners -- means there's something for "Cancel scan" to stop.
  const reconCheckKinds: CheckKind[] = ['dns', 'tls', 'http', 'subdomains', 'whois']
  const reconRunning = reconCheckKinds.some((k) => {
    const c = checks[keyFor(scan.domain, k)]
    return !c || c.status === 'running'
  })
  const scannerKinds: ScanKind[] = [
    'content-discovery',
    'subdomain-bruteforce',
    'vhost-bruteforce',
    'port-scan',
    'service-profile',
    'vuln-scan',
  ]
  const scanRunning = reconRunning || scannerKinds.some((k) => kindStatus(k) === 'running')

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-3 border-b border-neutral-800 bg-neutral-950 px-4 py-2">
        {/* Returns to this scan's own overview, not the app-wide scan list
            -- that's one click away via the "Aperture" logo in the top nav. */}
        <button onClick={() => setTab('overview')} className="text-sm text-neutral-400 hover:text-neutral-200">
          ← Dashboard
        </button>
        <h1 className="font-mono text-sm font-medium text-neutral-100">{scan.domain}</h1>
        {cloudflare && (
          <span title="Fronted by Cloudflare (detected via response headers)" className="rounded border border-orange-800 bg-orange-950/40 px-1.5 py-0.5 text-xs font-medium text-orange-400">
            ☁ Cloudflare
          </span>
        )}
        <span className="text-xs text-neutral-500">{new Date(scan.createdAt).toLocaleString()}</span>
        {overallProgress && <ProgressBar done={overallProgress.done} total={overallProgress.total} />}
        {restartError && <span className="text-xs text-red-400">{restartError}</span>}
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
            href={api.reportUrl(scanId, reportFormat)}
            className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:border-sky-500 hover:text-sky-400"
          >
            Download report
          </a>
          {scanRunning && (
            <button
              onClick={cancelScan}
              disabled={cancellingScan}
              className="rounded border border-red-900 px-2.5 py-1 text-xs text-red-400 hover:border-red-500 hover:text-red-300 disabled:opacity-50"
            >
              {cancellingScan ? 'Cancelling…' : 'Cancel scan'}
            </button>
          )}
          <button
            onClick={restartScan}
            disabled={restartingScan}
            className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:border-sky-500 hover:text-sky-400 disabled:opacity-50"
          >
            {restartingScan ? 'Restarting…' : 'Restart scan'}
          </button>
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
            rendering) so switching tabs to peek at another scanner doesn't
            reset the Subdomains tab's filter selection right before you
            meant to click "Scan selected". */}
        <div className="flex-1 overflow-hidden">
          <div className={`h-full overflow-y-auto ${tab === 'overview' ? '' : 'hidden'}`}>
            <div className="mx-auto max-w-5xl space-y-6 px-4 py-6">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {apexChecks.map((kind) => (
                  <CheckCard key={kind} kind={kind} check={checks[keyFor(scan.domain, kind)]} />
                ))}
              </div>
              <p className="text-xs text-neutral-500">
                {subdomainsCheck?.status === 'done'
                  ? `${passiveSubdomains.length} subdomain${passiveSubdomains.length === 1 ? '' : 's'} found via certificate transparency`
                  : subdomainsCheck?.status === 'error'
                    ? `Certificate-transparency lookup failed: ${subdomainsCheck.error}`
                    : 'Looking up subdomains via certificate transparency…'}{' '}
                — see the Subdomains tab for the full picture, including active bruteforce results.
              </p>

              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <SummaryCard label="Subdomains" value={subdomainRows.length} />
                <SummaryCard label="Pages found" value={contentFindings.length} />
                <SummaryCard label="Virtual hosts" value={vhostFindings.length} />
                <SummaryCard label="Critical files" value={criticalFindings.length} accent={criticalFindings.length > 0} />
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-lg border border-neutral-800">
                  <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
                    <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">⚠️ Critical files</h2>
                    <span className="text-xs text-neutral-600">{criticalFindings.length}</span>
                    {criticalFindings.length > 0 && (
                      <button onClick={() => setTab('content-discovery')} className="ml-auto text-xs text-sky-400 hover:text-sky-300">
                        View in Content Discovery →
                      </button>
                    )}
                  </div>
                  {criticalFindings.length === 0 ? (
                    <p className="px-3 py-6 text-center text-xs text-neutral-600">No backups, configs, or other sensitive files found (yet).</p>
                  ) : (
                    <div className="max-h-64 divide-y divide-neutral-900 overflow-y-auto">
                      {criticalFindings.map((f) => {
                        const ext = extensionOf(f.url)
                        return (
                          <div key={`${f.sourceNodeId}:${f.id}`} className="flex items-center gap-2 bg-red-950/20 px-3 py-1.5 text-xs">
                            <span className="font-mono" style={{ color: statusHexColor(f.statusCode) }}>
                              {f.statusCode}
                            </span>
                            <span className="truncate font-mono text-neutral-200" title={f.url}>
                              {f.url}
                            </span>
                            <span className="ml-auto shrink-0 rounded border border-red-800 px-1 font-mono font-semibold text-red-400">.{ext}</span>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>

                <button onClick={onOpenGraph} className="block rounded-lg border border-neutral-800 text-left hover:border-sky-600">
                  <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
                    <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Site graph</h2>
                    <span className="ml-auto text-xs text-sky-400">Open full graph →</span>
                  </div>
                  <div className="h-56">
                    {previewNodes.length === 0 ? (
                      <p className="px-3 py-6 text-center text-xs text-neutral-600">Nothing to graph yet.</p>
                    ) : (
                      <GraphCanvas nodes={previewNodes} edges={previewEdges} interactive={false} />
                    )}
                  </div>
                </button>
              </div>

              <div className="rounded-lg border border-neutral-800">
                <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
                  <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Subdomains</h2>
                  <span className="text-xs text-neutral-600">{subdomainsWithPages.length}</span>
                  {subdomainsWithPages.length > 0 && (
                    <button onClick={() => setTab('subdomains')} className="ml-auto text-xs text-sky-400 hover:text-sky-300">
                      Full subdomains tab →
                    </button>
                  )}
                </div>
                {subdomainsWithPages.length === 0 ? (
                  <p className="px-3 py-6 text-center text-xs text-neutral-600">No subdomains found yet.</p>
                ) : (
                  <div className="max-h-72 overflow-y-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="sticky top-0 bg-neutral-950">
                        <tr>
                          <th className="border-b border-neutral-800 px-3 py-1.5 font-medium uppercase tracking-wide text-neutral-500">Hostname</th>
                          <th className="border-b border-neutral-800 px-3 py-1.5 font-medium uppercase tracking-wide text-neutral-500">Status</th>
                          <th className="border-b border-neutral-800 px-3 py-1.5 font-medium uppercase tracking-wide text-neutral-500">Pages found</th>
                        </tr>
                      </thead>
                      <tbody>
                        {subdomainsWithPages.map((r) => (
                          <tr key={r.hostname} className="border-b border-neutral-900">
                            <td className="px-3 py-1 font-mono text-neutral-200">{r.hostname}</td>
                            <td className="px-3 py-1 font-mono" style={{ color: r.statusCode ? statusHexColor(r.statusCode) : undefined }}>
                              {r.statusCode ?? '—'}
                            </td>
                            <td className="px-3 py-1 text-neutral-400">{r.pages}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className={`h-full ${tab === 'subdomains' ? '' : 'hidden'}`}>
            <SubdomainsTab
              scanId={scanId}
              domain={scan.domain}
              rows={subdomainRows}
              runStatus={kindStatus('subdomain-bruteforce')}
              progress={kindProgress('subdomain-bruteforce')}
            />
          </div>

          <div className={`flex h-full flex-col ${tab === 'vhosts' ? '' : 'hidden'}`}>
            <ScannerToolbar scanId={scanId} kind="vhost-bruteforce" label="Restart" progress={kindProgress('vhost-bruteforce')} />
            {!hasVHostRun && apexDNSDone && (
              <p className="px-3 py-6 text-center text-xs text-neutral-600">No IPv4 address found for the apex domain — virtual-host bruteforce was skipped.</p>
            )}
            {!hasVHostRun && !apexDNSDone && <p className="px-3 py-6 text-center text-xs text-neutral-600">Waiting for DNS resolution…</p>}
            {hasVHostRun && (
              <div className="flex-1 overflow-hidden">
                <ResultsTable findings={vhostFindings} scanId={scanId} />
              </div>
            )}
          </div>

          <div className={`flex h-full flex-col ${tab === 'content-discovery' ? '' : 'hidden'}`}>
            {/* No aggregate progress bar here -- kindProgress collapses every
                target into one bar and one feroxbuster node's unbounded
                total (see contentDiscoveryTargets above it) is enough to
                make the whole thing indeterminate. The per-target panel
                below replaces it. */}
            <ScannerToolbar scanId={scanId} kind="content-discovery" label="Restart (apex)" progress={null} />
            <TargetProgressPanel targets={contentDiscoveryTargets()} />
            <div className="flex-1 overflow-hidden">
              <ResultsTable findings={contentFindings} scanId={scanId} facetPlacement="right" />
            </div>
          </div>

          <div className={`flex h-full flex-col ${tab === 'ports' ? '' : 'hidden'}`}>
            {!hasPortScanRun && apexDNSDone && (
              <p className="px-3 py-6 text-center text-xs text-neutral-600">No IPv4 address found for the apex domain — port scan was skipped.</p>
            )}
            {!hasPortScanRun && !apexDNSDone && <p className="px-3 py-6 text-center text-xs text-neutral-600">Waiting for DNS resolution…</p>}
            {hasPortScanRun && (
              <>
                <div className="flex items-center gap-3 border-b border-neutral-800 px-3 py-2">
                  {kindProgress('port-scan') && <ProgressBar done={kindProgress('port-scan')!.done} total={kindProgress('port-scan')!.total} />}
                </div>
                <div className="flex-1 overflow-hidden">
                  <PortsTable findings={portFindings} />
                </div>
              </>
            )}
          </div>

          <div className={`flex h-full flex-col ${tab === 'services' ? '' : 'hidden'}`}>
            {!hasServiceProfileRun && (
              <p className="px-3 py-6 text-center text-xs text-neutral-600">
                Runs automatically once the port scan finds open ports — see the Ports tab.
              </p>
            )}
            {hasServiceProfileRun && (
              <>
                <div className="flex items-center gap-3 border-b border-neutral-800 px-3 py-2">
                  {kindProgress('service-profile') && (
                    <ProgressBar done={kindProgress('service-profile')!.done} total={kindProgress('service-profile')!.total} />
                  )}
                </div>
                <div className="flex-1 overflow-hidden">
                  <PortsTable findings={serviceFindings} showVersion />
                </div>
              </>
            )}
          </div>

          <div className={`flex h-full flex-col ${tab === 'vulnerabilities' ? '' : 'hidden'}`}>
            {!hasVulnScanRun && (
              <p className="px-3 py-6 text-center text-xs text-neutral-600">
                Runs automatically once content discovery finds something to check — see the Content Discovery tab.
              </p>
            )}
            {hasVulnScanRun && (
              <>
                <div className="flex items-center gap-3 border-b border-neutral-800 px-3 py-2">
                  {kindProgress('vuln-scan') && <ProgressBar done={kindProgress('vuln-scan')!.done} total={kindProgress('vuln-scan')!.total} />}
                </div>
                <div className="flex-1 overflow-hidden">
                  <VulnTable findings={vulnFindings} />
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ScannerToolbar is the "Restart <scanner>" button + its live progress bar,
// shared by the Vhosts and Content Discovery tabs (the Subdomains tab has
// its own toolbar row combined with the "Scan selected" controls).
function ScannerToolbar({
  scanId,
  kind,
  label,
  progress,
}: {
  scanId: string
  kind: ScanKind
  label: string
  progress: { done: number; total: number } | null
}) {
  const [restarting, setRestarting] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const restart = async () => {
    setRestarting(true)
    setError('')
    setNotice('')
    try {
      const res = await api.restartScanRun(scanId, kind)
      // skipped means every target this scanner would cover is already
      // running or already scanned -- see handleRestartScanRun -- which
      // isn't an error, just nothing new to do.
      if (res.skipped) setNotice(res.message ?? 'nothing new to scan')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setRestarting(false)
    }
  }

  return (
    <div className="flex items-center gap-3 border-b border-neutral-800 px-3 py-2">
      <button
        onClick={restart}
        disabled={restarting}
        className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:border-sky-500 hover:text-sky-400 disabled:opacity-50"
      >
        {restarting ? 'Restarting…' : label}
      </button>
      {progress && <ProgressBar done={progress.done} total={progress.total} />}
      {error && <span className="text-xs text-red-400">{error}</span>}
      {notice && <span className="text-xs text-neutral-500">{notice}</span>}
    </div>
  )
}

function CheckCard({ kind, check }: { kind: CheckKind; check?: Check }) {
  const status = check?.status ?? 'pending'
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: STATUS_DOT[status] }} />
        <span className="text-xs font-semibold uppercase tracking-wide text-neutral-400">{CHECK_LABELS[kind]}</span>
      </div>
      {status === 'pending' && <p className="text-xs text-neutral-600">Queued…</p>}
      {status === 'running' && <p className="text-xs text-neutral-500">Checking…</p>}
      {status === 'error' && <p className="text-xs text-red-400">{check?.error || 'failed'}</p>}
      {status === 'done' && check?.data && <CheckSummary kind={kind} data={check.data} />}
    </div>
  )
}

function CheckSummary({ kind, data }: { kind: CheckKind; data: Record<string, unknown> }) {
  switch (kind) {
    case 'dns': {
      const a = (data.a as string[]) ?? []
      const ns = (data.ns as string[]) ?? []
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate font-mono">{a.length ? a.join(', ') : 'no A records'}</p>
          <p className="text-neutral-500">{ns.length} nameserver{ns.length === 1 ? '' : 's'}</p>
        </div>
      )
    }
    case 'tls': {
      const days = data.daysRemaining as number | undefined
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate">{(data.issuer as string) || 'unknown issuer'}</p>
          <p className={days !== undefined && days < 14 ? 'text-amber-400' : 'text-neutral-500'}>
            {days !== undefined ? `${days} days remaining` : ''}
          </p>
        </div>
      )
    }
    case 'http': {
      const code = data.statusCode as number | undefined
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p>
            <span className="font-mono">{code}</span> · {(data.scheme as string)?.toUpperCase()}
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
    case 'dnsdumpster': {
      const subdomains = (data.subdomains as string[]) ?? []
      const ns = (data.ns as unknown[]) ?? []
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p>{(data.totalARecords as number) ?? 0} A records</p>
          <p className="text-neutral-500">
            {subdomains.length} hostname{subdomains.length === 1 ? '' : 's'} · {ns.length} nameserver{ns.length === 1 ? '' : 's'}
          </p>
        </div>
      )
    }
    default:
      return null
  }
}

// --- Subdomains tab ---

interface SubdomainRow {
  hostname: string
  statusCode?: number
  contentLength?: number
  words?: number
  lines?: number
  passive: boolean
  active: boolean
  // takeoverProvider is set when recon flagged this subdomain's CNAME as a
  // possible dangling-CNAME takeover -- see recon.detectTakeover.
  takeoverProvider?: string
}

// buildSubdomainRows merges crt.sh's passive discovery (subdomain names +
// their per-subdomain DNS/TLS/HTTP recon check, which only carries a status
// code) with ffuf's active bruteforce (full status/size/words/lines, since
// those are ordinary content-discovery-shaped Findings) into one row per
// hostname.
function buildSubdomainRows(
  apexDomain: string,
  passive: string[],
  checks: Record<string, Check>,
  activeFindings: Finding[],
): SubdomainRow[] {
  const rows = new Map<string, SubdomainRow>()

  for (const hostname of passive) {
    const http = checks[keyFor(hostname, 'http')]
    const statusCode = http?.status === 'done' ? (http.data?.statusCode as number | undefined) : undefined
    const takeover = checks[keyFor(hostname, 'takeover')]
    const takeoverProvider = takeover?.status === 'done' ? (takeover.data?.provider as string | undefined) : undefined
    rows.set(hostname, { hostname, statusCode, passive: true, active: false, takeoverProvider })
  }

  for (const f of activeFindings) {
    let hostname: string
    try {
      hostname = new URL(f.url).hostname
    } catch {
      continue
    }
    if (hostname === apexDomain) continue
    const existing = rows.get(hostname)
    rows.set(hostname, {
      hostname,
      statusCode: f.statusCode,
      contentLength: f.contentLength,
      words: f.words,
      lines: f.lines,
      passive: existing?.passive ?? false,
      active: true,
      takeoverProvider: existing?.takeoverProvider,
    })
  }

  return [...rows.values()].sort((a, b) => a.hostname.localeCompare(b.hostname))
}

const SUBDOMAIN_DIMENSIONS: FacetDimension<SubdomainRow>[] = [
  { key: 'statusCode', label: 'Status', getValue: (r) => r.statusCode, colorFor: (v) => statusHexColor(Number(v)) },
  { key: 'contentLength', label: 'Size', getValue: (r) => r.contentLength },
  { key: 'words', label: 'Words', getValue: (r) => r.words },
  { key: 'lines', label: 'Lines', getValue: (r) => r.lines },
]

function SubdomainsTab({
  scanId,
  domain,
  rows,
  runStatus,
  progress,
}: {
  scanId: string
  domain: string
  rows: SubdomainRow[]
  runStatus: RunStatus
  progress: { done: number; total: number } | null
}) {
  const [kept, setKept] = useState<SubdomainRow[]>(rows)
  const [starting, setStarting] = useState(false)
  const [startMessage, setStartMessage] = useState('')
  const [restarting, setRestarting] = useState(false)

  const scanSelected = async () => {
    setStarting(true)
    setStartMessage('')
    try {
      const res = await api.runContentDiscovery(scanId, [domain, ...kept.map((r) => r.hostname)])
      // A selection that's entirely already-covered targets (running or
      // previously succeeded) doesn't start a new run at all -- see
      // handleScanContentDiscovery -- so re-clicking after adding just a
      // couple more subdomains only scans those, not the whole selection
      // again.
      setStartMessage(res.skipped ? (res.message ?? 'Nothing new to scan') : 'Started — see Content Discovery tab')
    } catch (err) {
      setStartMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  const restartBruteforce = async () => {
    setRestarting(true)
    try {
      await api.restartScanRun(scanId, 'subdomain-bruteforce')
    } finally {
      setRestarting(false)
    }
  }

  if (rows.length === 0) {
    return (
      <p className="px-3 py-6 text-center text-xs text-neutral-600">
        {runStatus === 'running' || runStatus === 'pending' ? 'Looking for subdomains…' : 'No subdomains found.'}
      </p>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <FacetFilterBar items={rows} dimensions={SUBDOMAIN_DIMENSIONS} onChange={setKept} />
      <div className="flex items-center gap-3 border-b border-neutral-800 px-3 py-2">
        <button
          onClick={restartBruteforce}
          disabled={restarting}
          className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-300 hover:border-sky-500 hover:text-sky-400 disabled:opacity-50"
        >
          {restarting ? 'Restarting…' : 'Restart bruteforce'}
        </button>
        {progress && <ProgressBar done={progress.done} total={progress.total} />}
        <span className="text-xs text-neutral-500">
          {kept.length} of {rows.length} subdomain{rows.length === 1 ? '' : 's'} selected
        </span>
        <button
          onClick={scanSelected}
          disabled={starting || kept.length === 0}
          className="ml-auto rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          {starting ? 'Starting…' : `Scan selected (${kept.length})`}
        </button>
        {startMessage && (
          <span className={`text-xs ${startMessage.startsWith('Started') ? 'text-emerald-400' : 'text-neutral-500'}`}>{startMessage}</span>
        )}
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-neutral-950">
            <tr>
              {screenshotPreviewEnabled && (
                <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Preview</th>
              )}
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Hostname</th>
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Status</th>
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Size</th>
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Words</th>
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Lines</th>
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Source</th>
              <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Takeover risk</th>
            </tr>
          </thead>
          <tbody>
            {kept.map((r) => (
              <tr key={r.hostname} className={`border-b border-neutral-900 hover:bg-neutral-900/60 ${r.takeoverProvider ? 'bg-red-950/20' : ''}`}>
                {screenshotPreviewEnabled && (
                  <td className="px-3 py-1.5">
                    <Thumbnail scanId={scanId} hostname={r.hostname} />
                  </td>
                )}
                <td className="px-3 py-1.5 font-mono text-neutral-200">{r.hostname}</td>
                <td className="px-3 py-1.5 font-mono" style={{ color: r.statusCode ? statusHexColor(r.statusCode) : undefined }}>
                  {r.statusCode ?? '—'}
                </td>
                <td className="px-3 py-1.5 text-neutral-400">{r.contentLength ?? '—'}</td>
                <td className="px-3 py-1.5 text-neutral-400">{r.words ?? '—'}</td>
                <td className="px-3 py-1.5 text-neutral-400">{r.lines ?? '—'}</td>
                <td className="px-3 py-1.5 text-xs text-neutral-500">
                  {r.passive && r.active ? 'crt.sh + ffuf' : r.active ? 'ffuf' : 'crt.sh'}
                </td>
                <td className="px-3 py-1.5 text-xs">
                  {r.takeoverProvider ? (
                    <span
                      title="CNAME points at this provider and either doesn't resolve or matches its 'unclaimed' page -- likely claimable by an attacker"
                      className="rounded border border-red-500 bg-red-950/50 px-1.5 py-0.5 font-semibold text-red-300"
                    >
                      ⚠ {r.takeoverProvider}
                    </span>
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
