import { useEffect, useMemo, useState } from 'react'
import { api, ApiError, watchApiEnumScan } from '../api'
import type {
  ApiEnumResponse,
  ApiEnumStats,
  ApiEnumTarget,
  ApiGraphqlSummary,
  ApiInjectionPoint,
  ApiMethodProbe,
  ApiParam,
  ApiRoute,
  ApiSchemaInfo,
  Credential,
  JobOptionsPreset,
  Target,
} from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { BatchResultsPanel, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { applyScanEvent, emptyProgress, finishProgress, type ScanProgress } from '../scanProgress'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { JOB_PRESETS } from '../presets'
import { CopyButton } from './CopyButton'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToTester } from '../testerHandoff'
import { showToast } from '../toast'

// ApiEnumPhaseState is the running-scan progress this component renders
// while a run works through its phases -- mirrors apienum.PhaseEvent, kept
// as a small local type so the component doesn't have to import the
// RunEvent-nested shape directly everywhere it's read.
import { ScanErrorNotice } from './ScanErrorNotice'

interface ApiEnumPhaseState {
  phase: string
  done: number
  total: number
}

// TargetScanState is one target's place in a (possibly multi-target) run
// -- same shape/reasoning as Probe.tsx's TargetScanState, except routes
// accumulate live from streamed "apiEnumRoute" events (same pattern Probe
// uses for ProbeModuleResult) rather than arriving all at once.
interface TargetScanState {
  status: 'running' | 'done' | 'error'
  // progress is the run's live per-route state (see scanProgress.ts), shown as
  // a grid of squares on the target's card.
  progress?: ScanProgress
  phase?: ApiEnumPhaseState
  routes: ApiRoute[]
  target?: ApiEnumTarget
  schema?: ApiSchemaInfo
  graphql?: ApiGraphqlSummary
  injectionPoints?: ApiInjectionPoint[]
  stats?: ApiEnumStats
  error?: string
}

const PHASE_LABELS: Record<string, string> = {
  spec: 'Checking for an OpenAPI/Swagger spec',
  graphql: 'Probing for GraphQL + introspection',
  crawl: 'Crawling the site + downloading scripts',
  bruteforce: 'Brute-forcing common API paths',
  characterize: 'Characterizing discovered routes',
}

// ApiEnum is Aperture's API enumerator (see internal/apienum): finds API
// endpoints via an exposed OpenAPI/Swagger spec, GraphQL introspection, a
// same-origin crawl, JS bundle mining, and a wordlist brute force, then
// characterizes each one's method support, auth requirement, content-type
// negotiation, and response shape -- and flags parameters worth a closer
// look into a staged injection-point list rather than attacking them
// itself. requestSaveTargets/onTargetsChanged let the injection-point
// panel hand selected entries off into a case target list (see CaseView's
// identical wiring for the Identify tab).
export function ApiEnum({
  caseId,
  targets,
  credentials,
  requestSaveTargets,
  onTargetsChanged,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  requestSaveTargets: (values: string[], save: (listId: string) => Promise<void>) => void
  onTargetsChanged: () => void
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [preset, setPreset] = useState<JobOptionsPreset>('custom')
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [crawlDepth, setCrawlDepth] = useState('')
  const [maxPages, setMaxPages] = useState('')
  const [extraWordlist, setExtraWordlist] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('apienum.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

  // Restores this case's most recent API enum run per target on mount/
  // reload -- see saveCaseScan in internal/api/handlers_apienum.go. Past
  // runs are also browsable via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<ApiEnumResponse>(caseId, 'apienum').then((list) => {
      if (cancelled) return
      const restored = latestByTarget(list)
      if (restored.length === 0) return
      setScans((prev) => {
        const next = { ...prev }
        for (const r of restored) {
          if (next[r.scan.target]) continue
          next[r.scan.target] = {
            status: 'done', routes: r.data.routes, target: r.data.target, schema: r.data.schema,
            graphql: r.data.graphql, injectionPoints: r.data.injectionPoints, stats: r.data.stats,
          }
        }
        return next
      })
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])
  const extraWordlistEntries = useMemo(() => extraWordlist.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [extraWordlist])

  const running = Object.values(scans).some((s) => s.status === 'running')
  const canRun = runTargets.length > 0 && !running

  const runScan = () => {
    if (!canRun) return
    const list = runTargets
    setScans(Object.fromEntries(list.map((t) => [t, { status: 'running' as const, routes: [], progress: emptyProgress() }])))
    for (const t of list) runOneScan(t)
  }

  const runOneScan = async (targetValue: string) => {
    const collected: ApiRoute[] = []
    let stopWatch: () => void = () => {}
    try {
      const { scanId } = await api.apiEnumScan({
        target: targetValue,
        preset: preset === 'custom' ? undefined : preset,
        credentialId,
        crawlDepth: crawlDepth ? Number(crawlDepth) : undefined,
        maxPages: maxPages ? Number(maxPages) : undefined,
        extraWordlist: extraWordlistEntries.length > 0 ? extraWordlistEntries : undefined,
        caseId,
      })
      await new Promise<void>((resolve, reject) => {
        stopWatch = watchApiEnumScan(scanId, (ev) => {
          // Every event also feeds the per-route progress grid; the branches
          // below handle the parts only this view needs (phase, route list, result).
          if (ev.type !== 'done') {
            setScans((prev) => {
              const cur = prev[targetValue]
              if (!cur) return prev
              return { ...prev, [targetValue]: { ...cur, progress: applyScanEvent(cur.progress ?? emptyProgress(), ev) } }
            })
          }
          if (ev.type === 'apiEnumPhase' && ev.apiEnumPhase) {
            const phase = ev.apiEnumPhase
            setScans((prev) => {
              const cur = prev[targetValue]
              if (!cur) return prev
              return { ...prev, [targetValue]: { ...cur, phase } }
            })
          } else if (ev.type === 'apiEnumRoute' && ev.apiEnumRoute) {
            collected.push(ev.apiEnumRoute)
            setScans((prev) => {
              const cur = prev[targetValue]
              if (!cur) return prev
              return { ...prev, [targetValue]: { ...cur, routes: [...collected] } }
            })
          } else if (ev.type === 'done') {
            if (ev.status === 'failed') {
              reject(new Error(ev.message || 'API enumeration failed'))
            } else if (ev.apiEnumTarget) {
              setScans((prev) => ({
                ...prev,
                [targetValue]: {
                  ...prev[targetValue], status: 'done', routes: collected, target: ev.apiEnumTarget,
                  progress: finishProgress(prev[targetValue]?.progress ?? emptyProgress()),
                  schema: ev.apiEnumSchema, graphql: ev.apiEnumGraphql, injectionPoints: ev.apiEnumInjectionPoints, stats: ev.apiEnumStats,
                },
              }))
              resolve()
            } else {
              reject(new Error('API enumeration ended without a result'))
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

  const runLabel = runTargets.length > 1 ? `Enumerate (${runTargets.length})` : 'Enumerate'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="API Enumerator"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">API Enumerator</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Finds API endpoints via an exposed OpenAPI/Swagger spec, GraphQL introspection, a same-origin crawl, the JS bundles
            that crawl turns up, and a wordlist brute force of common API paths -- then characterizes each one's methods, auth
            requirement, content-type negotiation, and response shape. Flags interesting parameters into a staged list for you
            to review and hand off -- never attacks them itself. Authorized testing only.
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
          <span className="text-[11px] text-neutral-600">Also paces the enumeration itself -- see "stealth" for the most conservative request rate.</span>
        </div>

        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <button type="button" onClick={() => setAdvancedOpen((v) => !v)} className="text-left text-xs text-neutral-500 hover:text-neutral-300">
          {advancedOpen ? '▾' : '▸'} Advanced (crawl depth, page cap, extra wordlist)
        </button>
        {advancedOpen && (
          <div className="space-y-2 rounded border border-neutral-800 p-2">
            <div className="flex gap-2">
              <label className="flex-1">
                <span className="text-[11px] text-neutral-500">Crawl depth (default 2, max 4)</span>
                <input value={crawlDepth} onChange={(e) => setCrawlDepth(e.target.value)} placeholder="2" className={`mt-0.5 ${inputBase}`} />
              </label>
              <label className="flex-1">
                <span className="text-[11px] text-neutral-500">Max pages (default 20, max 50)</span>
                <input value={maxPages} onChange={(e) => setMaxPages(e.target.value)} placeholder="20" className={`mt-0.5 ${inputBase}`} />
              </label>
            </div>
            <label className="block">
              <span className="text-[11px] text-neutral-500">Extra wordlist entries (added to the bundled default)</span>
              <textarea
                value={extraWordlist}
                onChange={(e) => setExtraWordlist(e.target.value)}
                placeholder="internal-api, legacy/v0, beta"
                rows={2}
                className={`mt-0.5 ${inputBase}`}
              />
            </label>
          </div>
        )}

        <button
          onClick={runScan}
          disabled={!canRun}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {running ? 'Enumerating…' : runLabel}
        </button>
      </CollapsibleFormPanel>

      <div className="min-w-0 flex-1 space-y-4">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'scan' ? (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more targets, then run.
              </div>
            )}

            {hasScans && (
              <BatchResultsPanel
                getProgress={(scan) => scan.progress}
                entries={Object.entries(scans)}
                getSummary={apiEnumSummary}
                renderCard={(t, scan) => (
                  <TargetScanCard caseId={caseId} target={t} scan={scan} requestSaveTargets={requestSaveTargets} onTargetsChanged={onTargetsChanged} />
                )}
              />
            )}
          </>
        ) : (
          <ScanHistoryPanel
            caseId={caseId}
            tool="apienum"
            toState={(data: ApiEnumResponse) => ({
              status: 'done' as const, routes: data.routes, target: data.target, schema: data.schema,
              graphql: data.graphql, injectionPoints: data.injectionPoints, stats: data.stats,
            })}
            getSummary={apiEnumSummary}
            renderCard={(t, scan) => (
              <TargetScanCard caseId={caseId} target={t} scan={scan} requestSaveTargets={requestSaveTargets} onTargetsChanged={onTargetsChanged} />
            )}
          />
        )}
      </div>
    </div>
  )
}

function apiEnumSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'running') return { label: scan.phase ? PHASE_LABELS[scan.phase.phase] ?? 'Running…' : 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger' }
  const points = scan.injectionPoints?.length ?? 0
  const routes = scan.stats?.routesFound ?? scan.routes.length
  if (routes === 0) return { label: 'No routes found', tone: 'neutral' }
  if (points === 0) return { label: `${routes} route${routes === 1 ? '' : 's'}`, tone: 'clean' }
  return { label: `${routes} route${routes === 1 ? '' : 's'} · ${points} flagged`, tone: 'warn' }
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

function TargetScanCard({
  caseId,
  target,
  scan,
  requestSaveTargets,
  onTargetsChanged,
}: {
  caseId: string
  target: string
  scan: TargetScanState
  requestSaveTargets: (values: string[], save: (listId: string) => Promise<void>) => void
  onTargetsChanged: () => void
}) {
  const confirmedCount = scan.routes.filter((r) => r.confirmed).length
  const uncertainCount = scan.routes.length - confirmedCount

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="break-all font-mono text-sm text-neutral-200">{target}</span>
        <ScanStatusBadge status={scan.status} />
      </div>

      {scan.status === 'error' && <ScanErrorNotice message={scan.error} />}

      {scan.status === 'done' && (
        <>
          {scan.target && <TargetSummaryCard target={scan.target} />}

          <div className="grid grid-cols-4 gap-2">
            <StatTile label="Routes" value={scan.stats?.routesFound ?? scan.routes.length} />
            <StatTile label="Confirmed" value={scan.stats?.confirmedRoutes ?? confirmedCount} tone="clean" />
            <StatTile label="Uncertain" value={scan.stats?.uncertainRoutes ?? uncertainCount} tone="neutral" />
            <StatTile label="Flagged params" value={scan.stats?.injectionPoints ?? scan.injectionPoints?.length ?? 0} tone="warn" />
          </div>

          {scan.schema?.found && (
            <div className="rounded-lg border border-sky-900/60 bg-sky-950/20 p-3 text-xs text-sky-200">
              <span className="font-medium">{scan.schema.kind === 'openapi' ? 'OpenAPI' : 'Swagger'} spec found</span> at{' '}
              <code className="break-all">{scan.schema.url}</code> -- {scan.schema.routeCount} route{scan.schema.routeCount === 1 ? '' : 's'} described directly.
            </div>
          )}
          {scan.graphql?.found && (
            <div className="rounded-lg border border-fuchsia-900/60 bg-fuchsia-950/20 p-3 text-xs text-fuchsia-200">
              <span className="font-medium">GraphQL endpoint</span> at <code className="break-all">{scan.graphql.url}</code>
              {scan.graphql.introspectionOn ? (
                <> -- introspection enabled, {scan.graphql.queries?.length ?? 0} quer{(scan.graphql.queries?.length ?? 0) === 1 ? 'y' : 'ies'} and{' '}
                  {scan.graphql.mutations?.length ?? 0} mutation{(scan.graphql.mutations?.length ?? 0) === 1 ? '' : 's'} recovered. See the GraphQL
                  Enumeration tool for a full schema dive and misconfiguration checks.</>
              ) : (
                <> -- introspection appears disabled.</>
              )}
            </div>
          )}

          {scan.routes.length === 0 ? (
            <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">No routes discovered.</div>
          ) : (
            <RouteTree routes={scan.routes} />
          )}

          {scan.injectionPoints && scan.injectionPoints.length > 0 && scan.target && (
            <InjectionPointsPanel
              caseId={caseId}
              points={scan.injectionPoints}
              baseUrl={scan.target.url}
              requestSaveTargets={requestSaveTargets}
              onTargetsChanged={onTargetsChanged}
            />
          )}
        </>
      )}
    </div>
  )
}

function TargetSummaryCard({ target }: { target: ApiEnumTarget }) {
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
      </div>
    </div>
  )
}

function StatTile({ label, value, tone }: { label: string; value: number; tone?: 'clean' | 'warn' | 'neutral' }) {
  const color = tone === 'clean' ? 'text-emerald-400' : tone === 'warn' ? 'text-amber-400' : 'text-neutral-200'
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-center">
      <p className={`text-2xl font-semibold ${color}`}>{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-neutral-500">{label}</p>
    </div>
  )
}

// --- Route tree ---

const METHOD_STYLES: Record<string, string> = {
  GET: 'border-sky-700 bg-sky-950/60 text-sky-300',
  POST: 'border-emerald-700 bg-emerald-950/60 text-emerald-300',
  PUT: 'border-amber-700 bg-amber-950/60 text-amber-300',
  PATCH: 'border-orange-700 bg-orange-950/60 text-orange-300',
  DELETE: 'border-red-700 bg-red-950/60 text-red-300',
  OPTIONS: 'border-neutral-700 bg-neutral-900 text-neutral-400',
  HEAD: 'border-neutral-700 bg-neutral-900 text-neutral-400',
}

function MethodBadge({ method, allowed }: { method: string; allowed?: boolean }) {
  const style = METHOD_STYLES[method] ?? 'border-neutral-700 bg-neutral-900 text-neutral-400'
  return (
    <span className={`rounded border px-1.5 py-0 text-[10px] font-semibold uppercase tracking-wide ${style} ${allowed === false ? 'opacity-40 line-through' : ''}`}>
      {method}
    </span>
  )
}

type RouteFilter = 'all' | 'confirmed' | 'uncertain'

// RouteTree groups routes by their base path (Route.group) into a
// collapsible tree -- see the package doc's "tree/grouped view by base
// path, not a flat list" goal -- with a confirmed/uncertain filter (the
// doc's "separate uncertain/needs verification bucket" goal) and a text
// filter for jumping to a specific path in a large tree.
function RouteTree({ routes }: { routes: ApiRoute[] }) {
  const [filter, setFilter] = useState<RouteFilter>('all')
  const [search, setSearch] = useState('')
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set())

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return routes.filter((r) => {
      if (filter === 'confirmed' && !r.confirmed) return false
      if (filter === 'uncertain' && r.confirmed) return false
      if (q && !r.path.toLowerCase().includes(q)) return false
      return true
    })
  }, [routes, filter, search])

  const groups = useMemo(() => {
    const m = new Map<string, ApiRoute[]>()
    for (const r of filtered) {
      const list = m.get(r.group) ?? []
      list.push(r)
      m.set(r.group, list)
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [filtered])

  const toggleGroup = (g: string) => {
    setOpenGroups((prev) => {
      const next = new Set(prev)
      if (next.has(g)) next.delete(g)
      else next.add(g)
      return next
    })
  }

  const confirmedCount = routes.filter((r) => r.confirmed).length

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1">
          {(['all', 'confirmed', 'uncertain'] as RouteFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`rounded border px-2 py-0.5 text-[11px] ${
                filter === f ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
              }`}
            >
              {f === 'all' ? `All (${routes.length})` : f === 'confirmed' ? `Confirmed (${confirmedCount})` : `Uncertain (${routes.length - confirmedCount})`}
            </button>
          ))}
        </div>
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter by path…" className={`max-w-xs flex-1 text-xs ${inputBase}`} />
      </div>

      <div className="divide-y divide-neutral-900 rounded-lg border border-neutral-800 bg-neutral-950/40">
        {groups.length === 0 ? (
          <p className="p-3 text-center text-xs text-neutral-600">No routes match this filter.</p>
        ) : (
          groups.map(([group, groupRoutes]) => {
            const open = openGroups.has(group)
            const flaggedInGroup = groupRoutes.reduce((n, r) => n + r.params.filter((p) => p.flagged).length, 0)
            return (
              <div key={group}>
                <button type="button" onClick={() => toggleGroup(group)} className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-neutral-900/60">
                  <span className="shrink-0 text-xs text-neutral-600">{open ? '▾' : '▸'}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-neutral-200">{group}</span>
                  <span className="shrink-0 text-[11px] text-neutral-500">{groupRoutes.length} route{groupRoutes.length === 1 ? '' : 's'}</span>
                  {flaggedInGroup > 0 && (
                    <span className="shrink-0 rounded border border-amber-700 bg-amber-950/60 px-1.5 py-0 text-[10px] text-amber-300">{flaggedInGroup} flagged</span>
                  )}
                </button>
                {open && (
                  <div className="divide-y divide-neutral-900 border-t border-neutral-800 bg-neutral-950/60 px-2">
                    {groupRoutes.map((r) => (
                      <RouteRow key={r.id} route={r} />
                    ))}
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

function RouteRow({ route }: { route: ApiRoute }) {
  const [expanded, setExpanded] = useState(false)
  const flaggedCount = route.params.filter((p) => p.flagged).length

  return (
    <div className="py-1.5">
      <button type="button" onClick={() => setExpanded((v) => !v)} className="flex w-full items-center gap-2 py-1 text-left">
        <span className="shrink-0 text-xs text-neutral-600">{expanded ? '▾' : '▸'}</span>
        <div className="flex shrink-0 gap-1">
          {route.methods.length > 0 ? route.methods.map((m) => <MethodBadge key={m.method} method={m.method} allowed={m.allowed} />) : <MethodBadge method="GET" />}
        </div>
        <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-neutral-300">{route.path}</span>
        {!route.confirmed && <span className="shrink-0 rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0 text-[10px] text-neutral-500">uncertain</span>}
        {route.auth.requiresAuth && (
          <span className="shrink-0 rounded border border-indigo-700 bg-indigo-950/60 px-1.5 py-0 text-[10px] text-indigo-300" title="Requires authentication">
            🔒 auth
          </span>
        )}
        {flaggedCount > 0 && (
          <span className="shrink-0 rounded border border-amber-700 bg-amber-950/60 px-1.5 py-0 text-[10px] text-amber-300">{flaggedCount} flagged</span>
        )}
      </button>

      {expanded && (
        <div className="ml-6 mb-1.5 space-y-2 rounded border border-neutral-800 bg-neutral-950 p-2 text-[11px]">
          <MethodTable methods={route.methods} />

          <div className="flex flex-wrap gap-x-4 gap-y-1 text-neutral-500">
            <span>
              Unauth → <span className="font-mono text-neutral-300">{route.auth.unauthenticatedStatus || '—'}</span>
            </span>
            {route.auth.authenticatedStatus !== undefined && (
              <span>
                Authed → <span className="font-mono text-neutral-300">{route.auth.authenticatedStatus}</span>
              </span>
            )}
            {route.contentTypesAccepted && route.contentTypesAccepted.length > 0 && (
              <span>
                Accepts → <span className="font-mono text-neutral-300">{route.contentTypesAccepted.join(', ')}</span>
              </span>
            )}
            {route.paginated && <span className="text-sky-400">paginated</span>}
            {route.rateLimitHeaders && Object.keys(route.rateLimitHeaders).length > 0 && (
              <span>
                Rate-limit headers → {Object.entries(route.rateLimitHeaders).map(([k, v]) => `${k}: ${v}`).join(', ')}
              </span>
            )}
          </div>

          {route.params.length > 0 && <ParamList params={route.params} />}
        </div>
      )}
    </div>
  )
}

function MethodTable({ methods }: { methods: ApiMethodProbe[] }) {
  if (methods.length === 0) return null
  return (
    <table className="w-full border-collapse text-left">
      <thead>
        <tr className="text-neutral-600">
          <th className="py-0.5 pr-2 font-normal">Method</th>
          <th className="py-0.5 pr-2 font-normal">Status</th>
          <th className="py-0.5 pr-2 font-normal">Content-Type</th>
          <th className="py-0.5 pr-2 font-normal">Shape</th>
          <th className="py-0.5 font-normal">Bytes</th>
        </tr>
      </thead>
      <tbody>
        {methods.map((m) => (
          <tr key={m.method} className={m.allowed ? 'text-neutral-300' : 'text-neutral-600'}>
            <td className="py-0.5 pr-2">
              <MethodBadge method={m.method} allowed={m.allowed} />
            </td>
            <td className="py-0.5 pr-2 font-mono">{m.statusCode || '—'}</td>
            <td className="py-0.5 pr-2 font-mono">{m.contentType || '—'}</td>
            <td className="py-0.5 pr-2">{m.bodyShape || '—'}</td>
            <td className="py-0.5">{m.responseBytes}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function ParamList({ params }: { params: ApiParam[] }) {
  return (
    <div>
      <p className="mb-1 text-neutral-600">Parameters</p>
      <ul className="space-y-0.5">
        {params.map((p, i) => (
          <li key={i} className={`flex flex-wrap items-center gap-1.5 ${p.flagged ? 'text-amber-300' : 'text-neutral-400'}`}>
            <span className="font-mono">{p.name}</span>
            <span className="text-neutral-600">({p.location})</span>
            <span className="text-neutral-600">{p.typeGuess}</span>
            {p.flagged && <span className="text-[10px] text-amber-500">{p.reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  )
}

// --- Injection point staging list ---

// InjectionPointsPanel is the package doc's core deliverable: every flagged
// parameter, staged for the operator to review and act on manually --
// selectable for export into a case target list (reusing CaseView's
// existing requestSaveTargets/SaveToListModal flow, the same "exportable
// as a list Aperture's existing scan-target format can ingest" handoff
// every other tool's promoted findings use) or sent individually to the
// Tester. Nothing here fires a payload.
function InjectionPointsPanel({
  caseId,
  points,
  baseUrl,
  requestSaveTargets,
  onTargetsChanged,
}: {
  caseId: string
  points: ApiInjectionPoint[]
  baseUrl: string
  requestSaveTargets: (values: string[], save: (listId: string) => Promise<void>) => void
  onTargetsChanged: () => void
}) {
  const { openMenu } = useContextMenu()
  const [selected, setSelected] = useState<Set<number>>(new Set())

  const toggle = (i: number) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }
  const toggleAll = () => {
    setSelected((prev) => (prev.size === points.length ? new Set() : new Set(points.map((_, i) => i))))
  }

  const urlFor = (p: ApiInjectionPoint) => `${baseUrl}${p.endpoint}`

  const saveSelected = () => {
    const chosen = points.filter((_, i) => selected.has(i))
    if (chosen.length === 0) return
    // Group by target value so several flagged params on the same
    // endpoint become one target with a combined note, instead of several
    // AddTarget calls silently colliding on the UNIQUE(case_id, value)
    // constraint and losing all but the first note.
    const byValue = new Map<string, string[]>()
    for (const p of chosen) {
      const value = urlFor(p)
      const note = `${p.method} ${p.param} (${p.location}) -- ${p.reason}${p.sample ? ` [sample: ${p.sample}]` : ''}`
      byValue.set(value, [...(byValue.get(value) ?? []), note])
    }
    const values = [...byValue.keys()]
    requestSaveTargets(values, async (listId) => {
      await Promise.all(values.map((v) => api.addTarget(caseId, v, listId, byValue.get(v)!.join('; '))))
      showToast(`Saved ${values.length} target${values.length === 1 ? '' : 's'} to the case`, 'success')
      onTargetsChanged()
    })
  }

  return (
    <div className="rounded-lg border border-amber-900/60 bg-amber-950/10">
      <div className="flex flex-wrap items-center gap-2 border-b border-amber-900/40 p-3">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-amber-300">
          Injection points staged ({points.length})
        </h2>
        <span className="text-[11px] text-neutral-500">Flagged for manual review -- nothing here was attacked.</span>
        <div className="ml-auto flex items-center gap-2">
          <button type="button" onClick={toggleAll} className="text-[11px] text-neutral-400 hover:text-neutral-200">
            {selected.size === points.length ? 'Deselect all' : 'Select all'}
          </button>
          <button
            type="button"
            disabled={selected.size === 0}
            onClick={saveSelected}
            className="rounded border border-sky-700 bg-sky-950/40 px-2 py-0.5 text-[11px] text-sky-300 hover:bg-sky-900/40 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Save {selected.size > 0 ? selected.size : ''} to list
          </button>
        </div>
      </div>
      <ul className="max-h-96 divide-y divide-amber-900/20 overflow-y-auto">
        {points.map((p, i) => (
          <li
            key={i}
            onContextMenu={(e) => {
              e.stopPropagation()
              openMenu(e, [
                { label: 'Copy URL', onSelect: () => copyToClipboard(urlFor(p), 'Copied URL') },
                { label: 'Send to Tester', onSelect: () => sendToTester(urlFor(p), p.method) },
              ])
            }}
            className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs"
          >
            <input type="checkbox" checked={selected.has(i)} onChange={() => toggle(i)} className="shrink-0" />
            <MethodBadge method={p.method} />
            <span className="min-w-0 flex-1 truncate font-mono text-neutral-300" title={urlFor(p)}>
              {p.endpoint}
            </span>
            <span className="shrink-0 font-mono text-amber-300">{p.param}</span>
            <span className="shrink-0 text-neutral-600">({p.location} · {p.typeGuess})</span>
            <span className="shrink-0 text-neutral-500">{p.reason}</span>
            <span onClick={(e) => e.stopPropagation()} className="ml-auto flex shrink-0 items-center gap-1">
              <CopyButton text={urlFor(p)} />
              <button
                onClick={() => sendToTester(urlFor(p), p.method)}
                className="rounded border border-neutral-700 px-1.5 py-0.5 text-[10px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
              >
                Send to Tester
              </button>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
