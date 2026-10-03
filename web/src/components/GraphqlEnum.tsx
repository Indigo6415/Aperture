import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type {
  Credential,
  GraphqlEnumFinding,
  GraphqlEnumModuleResult,
  GraphqlEnumResponse,
  GraphqlFieldSummary,
  GraphqlSchema,
  GraphqlTypeSummary,
  ProbeSeverity,
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
import { emptyProgress, runTrackedScan, type TrackedScan } from '../scanProgress'
import { SEVERITY_META, SEVERITY_ORDER } from '../severityColor'
import { sendToTester } from '../testerHandoff'

// TargetScanState is one endpoint's place in a (possibly multi-target) run
// -- same shape/reasoning as PwReset.tsx's TargetScanState.
import { ScanErrorNotice } from './ScanErrorNotice'

type TargetScanState = TrackedScan<GraphqlEnumResponse>

// GraphqlEnum is Aperture's GraphQL enumeration/misconfiguration scanner
// (see internal/graphqlenum): confirms the endpoint is actually GraphQL,
// pulls the full schema via introspection -- trying the documented bypasses
// when a plain request is blocked -- then runs a battery of checks (engine
// fingerprint, mutations executable over GET, schema leakage through error
// messages, unbounded query-shape DoS surfaces, CSRF-reachable content
// types, and Automatic Persisted Queries). Runs against every endpoint the
// user selects or types at once, same batch pattern as Probe/PwReset.
export function GraphqlEnum({
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

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('graphqlenum.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  // Restores this case's most recent GraphQL enum run per target on
  // mount/reload -- see saveCaseScan in internal/api/handlers_graphqlenum.go.
  // Every past run is also browsable via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<GraphqlEnumResponse>(caseId, 'graphqlenum').then((list) => {
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

  // runOneScan streams this target's run into its card, and lands the full
  // result once it finishes.
  const runOneScan = (targetValue: string) =>
    runTrackedScan<GraphqlEnumResponse>(
      () => api.graphqlEnum({
        // A target picked from the case list (or typed bare) has no scheme
        // -- graphqlenum.Run rejects that outright, same normalization as
        // Bypass403.tsx/PwReset.tsx.
        url: toAbsoluteUrl(targetValue),
        credentialId,
        caseId,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
    )

  const runLabel = runTargets.length > 1 ? `Run (${runTargets.length})` : 'Run'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="GraphQL Enumeration"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">GraphQL Enumeration</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Confirms the endpoint is GraphQL, pulls the full schema via introspection (trying the documented bypasses when a
            plain request is blocked), then checks for an identifiable engine, mutations executable over GET, schema leakage
            through error messages, unbounded alias/field/directive/batch query shapes, CSRF-reachable content types, and
            Automatic Persisted Queries. Never executes a real mutation or attempts a real denial-of-service flood.
            Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">GraphQL endpoints in this case</span>
          <div className="mt-1">
            <TargetPicker targets={targets} selected={selected} onChange={setSelected} />
          </div>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Additional endpoints</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            One-off URLs not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="https://target.htb/graphql"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

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
            tool="graphqlenum"
            toState={(data: GraphqlEnumResponse) => ({ status: 'done' as const, result: data })}
            getSummary={graphqlEnumSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        ) : (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more GraphQL endpoints, then run.
              </div>
            )}

            {hasScans && (
              <BatchResultsPanel
                entries={Object.entries(scans)}
                getSummary={graphqlEnumSummary}
                getProgress={(scan) => scan.progress}
                renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

// graphqlEnumSummary is one target's one-line compact-view badge once a
// batch covers more than BatchResultsPanel's threshold -- mirrors
// PwReset.tsx's pwResetSummary, plus the "not actually GraphQL" case.
function graphqlEnumSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger' }
  if (!scan.result?.baseline.confirmed) return { label: 'Not GraphQL', tone: 'neutral' }
  const modules = scan.result?.modules ?? []
  const total = modules.reduce((n, m) => n + m.findings.length, 0)
  if (total === 0) return { label: 'Clean', tone: 'clean' }
  const hasSevere = modules.some((m) => m.findings.length > 0 && (m.severity === 'critical' || m.severity === 'high'))
  return { label: `${total} issue${total === 1 ? '' : 's'}`, tone: hasSevere ? 'danger' : 'warn' }
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

// TargetScanCard is one endpoint's whole run lifecycle in a batch -- same
// role as PwReset.tsx's TargetScanCard.
function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const result = scan.result

  const severityCounts = useMemo(() => {
    const c: Record<ProbeSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const m of result?.modules ?? []) c[m.severity] += m.findings.length
    return c
  }, [result])

  const totalFindings = (result?.modules ?? []).reduce((n, m) => n + m.findings.length, 0)

  // Once at least one module found something, only list the categories that
  // actually hit -- same reasoning as PwReset.tsx's sortedModules.
  const sortedModules = useMemo(() => {
    const mods = result?.modules ?? []
    const rank: Record<ProbeSeverity, number> = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i])) as Record<ProbeSeverity, number>
    const relevant = totalFindings > 0 ? mods.filter((m) => m.findings.length > 0) : mods
    return [...relevant].sort((a, b) => rank[a.severity] - rank[b.severity] || a.name.localeCompare(b.name))
  }, [result, totalFindings])

  return (
    <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="break-all font-mono text-sm text-neutral-200">{target}</span>
        <ScanStatusBadge status={scan.status} />
      </div>

      {scan.status === 'error' && <ScanErrorNotice message={scan.error} />}

      {scan.status === 'done' && result && !result.baseline.confirmed && (
        <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
          HTTP {result.baseline.statusCode} to a <code className="font-mono text-neutral-400">{'{__typename}'}</code> probe
          didn't come back looking like GraphQL -- checked no further.
        </div>
      )}

      {scan.status === 'done' && result && result.baseline.confirmed && (
        <>
          <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
            <div className="flex flex-wrap gap-x-6 gap-y-1">
              <span>
                Confirmed GraphQL → <span className="font-mono text-neutral-200">{result.baseline.statusCode}</span>
                {result.baseline.typeName && (
                  <>
                    {' '}
                    · root type <span className="font-mono text-neutral-300">{result.baseline.typeName}</span>
                  </>
                )}
              </span>
            </div>
          </div>

          {result.schema && <SchemaBrowser schema={result.schema} />}

          <div className="grid grid-cols-5 gap-2">
            {SEVERITY_ORDER.map((sev) => (
              <SeverityTile key={sev} severity={sev} value={severityCounts[sev]} />
            ))}
          </div>

          {totalFindings === 0 ? (
            <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
              No issues found across {result.modules.length} check{result.modules.length === 1 ? '' : 's'}.
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

// SchemaBrowser renders the reconstructed schema (see
// internal/graphqlenum.Schema) as three root-field lists plus a flat type
// list -- collapsed by default except Queries, since that's usually the
// first thing an operator wants to skim.
function SchemaBrowser({ schema }: { schema: GraphqlSchema }) {
  const [open, setOpen] = useState(true)

  return (
    <div className="rounded-lg border border-sky-900/60 bg-sky-950/20">
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-2 p-3 text-left">
        <span className="text-xs text-neutral-600">{open ? '▾' : '▸'}</span>
        <span className="text-sm font-medium text-sky-300">Schema recovered via introspection ({schema.via})</span>
        <span className="ml-auto shrink-0 text-xs text-neutral-500">
          {schema.typeCount} type{schema.typeCount === 1 ? '' : 's'} · {schema.queries?.length ?? 0} quer
          {(schema.queries?.length ?? 0) === 1 ? 'y' : 'ies'} · {schema.mutations?.length ?? 0} mutation
          {(schema.mutations?.length ?? 0) === 1 ? '' : 's'}
        </span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-sky-900/40 p-3">
          {schema.truncated && (
            <p className="text-[11px] text-amber-400">
              Schema is larger than this view's cap -- showing the first {schema.queries ? 'entries' : 'types'} only.
            </p>
          )}
          <FieldSection title={`Queries (${schema.queryType ?? 'Query'})`} fields={schema.queries} />
          <FieldSection title={`Mutations (${schema.mutationType ?? 'Mutation'})`} fields={schema.mutations} />
          {schema.subscriptions && schema.subscriptions.length > 0 && (
            <FieldSection title={`Subscriptions (${schema.subscriptionType ?? 'Subscription'})`} fields={schema.subscriptions} />
          )}
          <TypeSection types={schema.types} />
        </div>
      )}
    </div>
  )
}

function FieldSection({ title, fields }: { title: string; fields?: GraphqlFieldSummary[] }) {
  const [expanded, setExpanded] = useState(true)
  if (!fields || fields.length === 0) {
    return <p className="text-xs text-neutral-600">{title}: none</p>
  }
  return (
    <div>
      <button onClick={() => setExpanded((v) => !v)} className="flex items-center gap-1.5 text-xs font-medium text-neutral-300">
        <span className="text-neutral-600">{expanded ? '▾' : '▸'}</span>
        {title} <span className="text-neutral-600">({fields.length})</span>
      </button>
      {expanded && (
        <ul className="mt-1 max-h-56 space-y-0.5 overflow-y-auto rounded border border-neutral-800 bg-neutral-950 p-2">
          {fields.map((f) => (
            <li key={f.name} className="flex items-start gap-1.5 font-mono text-[11px]">
              <span className={f.isDeprecated ? 'text-neutral-600 line-through' : 'text-sky-300'}>{f.name}</span>
              {f.args && f.args.length > 0 && <span className="text-neutral-500">({f.args.join(', ')})</span>}
              {f.returnType && <span className="text-neutral-600">: {f.returnType}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function TypeSection({ types }: { types?: GraphqlTypeSummary[] }) {
  const [expanded, setExpanded] = useState(false)
  if (!types || types.length === 0) return null
  return (
    <div>
      <button onClick={() => setExpanded((v) => !v)} className="flex items-center gap-1.5 text-xs font-medium text-neutral-300">
        <span className="text-neutral-600">{expanded ? '▾' : '▸'}</span>
        Types <span className="text-neutral-600">({types.length})</span>
      </button>
      {expanded && (
        <ul className="mt-1 grid max-h-64 grid-cols-2 gap-x-4 gap-y-0.5 overflow-y-auto rounded border border-neutral-800 bg-neutral-950 p-2 sm:grid-cols-3">
          {types.map((t) => (
            <li key={t.name} className="truncate font-mono text-[11px] text-neutral-400" title={t.description}>
              {t.name} <span className="text-neutral-600">· {t.kind.toLowerCase()} · {t.fieldCount}f</span>
            </li>
          ))}
        </ul>
      )}
    </div>
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

function ModuleCard({ module }: { module: GraphqlEnumModuleResult }) {
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

// FindingRow mirrors PwReset.tsx's FindingRow: an always-visible label/
// detail line, plus a toggleable "how it was found" panel for evidence/
// method/status when the backend sent any.
function FindingRow({ finding }: { finding: GraphqlEnumFinding }) {
  const [expanded, setExpanded] = useState(false)
  const hasExpandable = Boolean(finding.evidence || finding.method || finding.statusCode !== undefined || finding.request)

  return (
    <li className="py-2 text-xs">
      <div
        onClick={() => hasExpandable && setExpanded((v) => !v)}
        className={`flex items-start gap-2 ${hasExpandable ? 'cursor-pointer' : ''}`}
      >
        {hasExpandable && <span className="mt-0.5 shrink-0 text-neutral-600">{expanded ? '▾' : '▸'}</span>}
        <div className="min-w-0 flex-1">
          <p className="break-all text-neutral-300">{finding.label}</p>
          {finding.detail && <p className="mt-0.5 text-neutral-600">{finding.detail}</p>}
        </div>
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
          {finding.request && (
            <div onClick={(e) => e.stopPropagation()}>
              <button
                onClick={() => sendToTester(finding.request!.url, finding.request!.method || 'GET', finding.request!.headers, finding.request!.body)}
                className="rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
              >
                Send to Tester
              </button>
            </div>
          )}
        </div>
      )}
    </li>
  )
}
