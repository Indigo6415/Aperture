import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { Credential, ProbeSeverity, PwResetFinding, PwResetModuleResult, PwResetResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { BatchResultsPanel, stoppedSummary, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { CopyButton } from './CopyButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { emptyProgress, runTrackedScan, type TrackedScan, runBatch, stopTrackedScan, useScanBatch, stopAllScans } from '../scanProgress'
import { SEVERITY_META, SEVERITY_ORDER } from '../severityColor'
import { sendToTester } from '../testerHandoff'

// TargetScanState is one endpoint's place in a (possibly multi-target) run
// -- same shape/reasoning as Bypass403.tsx's TargetScanState.
import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'

type TargetScanState = TrackedScan<PwResetResponse>

type ExtraFieldRow = { name: string; value: string }

// PwReset is Aperture's "forgot password" scanner (see internal/pwreset):
// submits a request-reset endpoint's own request (baseline), then runs a
// battery of checks against it -- Host-header/proxy-header poisoning
// (password-reset link poisoning), a reset token/link leaking directly in
// the endpoint's own response, missing rate limiting, user enumeration
// (when a known-good identifier is supplied), and -- when a separate form
// page URL is given -- missing CSRF protection or weak cookie/caching
// attributes on that form. Runs against every endpoint the user selects or
// types at once, same batch pattern as Probe/Bypass403.
export function PwReset({
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
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()

  const [method, setMethod] = useState<'POST' | 'GET'>('POST')
  const [contentType, setContentType] = useState<'form' | 'json'>('form')
  const [identifierField, setIdentifierField] = useState('email')
  const [knownIdentifier, setKnownIdentifier] = useState('')

  const [showAdvanced, setShowAdvanced] = useState(false)
  const [unknownIdentifier, setUnknownIdentifier] = useState('')
  const [formUrl, setFormUrl] = useState('')
  const [extraFieldRows, setExtraFieldRows] = useState<ExtraFieldRow[]>([])

  const hasScans = Object.keys(scans).length > 0
  const [formOpen, setFormOpen] = useCollapsible('pwreset.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)
  const [view, setView] = useState<'scan' | 'history'>('scan')

  // Restores this case's most recent password-reset run per target on
  // mount/reload -- see saveCaseScan in internal/api/handlers_pwreset.go.
  // Every past run is also browsable via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<PwResetResponse>(caseId, 'pwreset').then((list) => {
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

  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])

  const running = Object.values(scans).some((s) => s.status === 'running')
  // stopScan stops one target's running scan. Its card settles itself once the
  // server's terminal event arrives.
  const stopScan = (t: string) => stopTrackedScan(scans[t])
  const speed = useScanSpeed()
  const canRun = runTargets.length > 0 && !running && speed.rps !== null

  const addExtraFieldRow = () => setExtraFieldRows((rows) => [...rows, { name: '', value: '' }])
  const updateExtraFieldRow = (i: number, patch: Partial<ExtraFieldRow>) =>
    setExtraFieldRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const removeExtraFieldRow = (i: number) => setExtraFieldRows((rows) => rows.filter((_, idx) => idx !== i))

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
  const runOneScan = (targetValue: string, signal?: AbortSignal) => {
    // Extra form fields are only sent when a row has a name, so a half-filled
    // row doesn't submit an empty field name.
    const extraFields = Object.fromEntries(extraFieldRows.filter((r) => r.name.trim()).map((r) => [r.name.trim(), r.value]))
    return runTrackedScan<PwResetResponse>(
      () => api.pwReset({ requestsPerSecond: speed.rps ?? undefined,
        // A target picked from the case list (or typed bare) has no scheme
        // -- pwreset.Run rejects that outright, same normalization as
        // Bypass403.tsx/SecretScan.tsx.
        url: toAbsoluteUrl(targetValue),
        method,
        contentType,
        identifierField: identifierField.trim() || undefined,
        knownIdentifier: knownIdentifier.trim() || undefined,
        unknownIdentifier: unknownIdentifier.trim() || undefined,
        extraFields: Object.keys(extraFields).length ? extraFields : undefined,
        formUrl: formUrl.trim() || undefined,
        credentialId,
        caseId,
      }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
      signal,
    )
  }

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
        title="Password Reset"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Password Reset</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Submits a "forgot password" endpoint's own request-reset form, then checks it for Host-header reset-link
            poisoning, a reset token/link leaked straight into the response, missing rate limiting, and -- when a known
            registered identifier is given -- user enumeration. Never guesses a live token or completes a reset.
            Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Request-reset endpoints in this case</span>
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
            placeholder="https://target.htb/api/forgot-password"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <div className="flex flex-wrap items-end gap-2">
          <label className="flex items-center gap-1 text-xs text-neutral-400">
            Method
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as 'POST' | 'GET')}
              className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
            >
              <option value="POST">POST</option>
              <option value="GET">GET</option>
            </select>
          </label>
          <label className="flex items-center gap-1 text-xs text-neutral-400">
            Body
            <select
              value={contentType}
              onChange={(e) => setContentType(e.target.value as 'form' | 'json')}
              className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-xs text-neutral-200 outline-none focus:border-sky-500"
            >
              <option value="form">form-encoded</option>
              <option value="json">JSON</option>
            </select>
          </label>
          <label className="flex flex-1 items-center gap-1 text-xs text-neutral-400" style={{ minWidth: '10rem' }}>
            Identifier field
            <input
              value={identifierField}
              onChange={(e) => setIdentifierField(e.target.value)}
              placeholder="email"
              className={`${inputBase} flex-1 py-0.5`}
            />
          </label>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Known registered identifier</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            An email/username you know is a real account on the target -- unlocks the user-enumeration check and makes the
            leaked-token check use its response. Leave blank to skip enumeration.
          </span>
          <input
            value={knownIdentifier}
            onChange={(e) => setKnownIdentifier(e.target.value)}
            placeholder="known-user@target.htb"
            className={`mt-1 ${inputBase}`}
          />
        </label>


        {speed.control}


        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          className="rounded border border-neutral-800 px-2 py-0.5 text-xs text-neutral-500 hover:text-neutral-300"
        >
          {showAdvanced ? 'Hide advanced ▾' : 'Advanced ▸'}
        </button>

        {showAdvanced && (
          <div className="space-y-3 rounded border border-neutral-800 bg-neutral-950/40 p-3">
            <label className="block">
              <span className="text-xs font-medium text-neutral-300">Unknown identifier</span>
              <span className="mt-0.5 block text-[11px] text-neutral-600">
                What the baseline/rate-limit/host-header requests submit as a non-existent account. Auto-generated when blank.
              </span>
              <input
                value={unknownIdentifier}
                onChange={(e) => setUnknownIdentifier(e.target.value)}
                placeholder="auto-generated"
                className={`mt-1 ${inputBase}`}
              />
            </label>

            <label className="block">
              <span className="text-xs font-medium text-neutral-300">Form page URL</span>
              <span className="mt-0.5 block text-[11px] text-neutral-600">
                The page that renders the reset-request form itself (not the submission endpoint above) -- unlocks the CSRF
                and cookie/caching checks. Leave blank to skip them.
              </span>
              <input
                value={formUrl}
                onChange={(e) => setFormUrl(e.target.value)}
                placeholder="https://target.htb/forgot-password"
                className={`mt-1 ${inputBase}`}
              />
            </label>

            <div>
              <span className="text-xs font-medium text-neutral-300">Extra fields</span>
              <span className="mt-0.5 block text-[11px] text-neutral-600">
                Additional static fields every request sends -- a CSRF token pulled from the form page, a required "action"
                field, and the like.
              </span>
              <div className="mt-1 space-y-1.5">
                {extraFieldRows.map((row, i) => (
                  <div key={i} className="flex gap-1.5">
                    <input
                      value={row.name}
                      onChange={(e) => updateExtraFieldRow(i, { name: e.target.value })}
                      placeholder="Field name"
                      className={`${inputBase} flex-1`}
                    />
                    <input
                      value={row.value}
                      onChange={(e) => updateExtraFieldRow(i, { value: e.target.value })}
                      placeholder="Value"
                      className={`${inputBase} flex-1`}
                    />
                    <button
                      onClick={() => removeExtraFieldRow(i)}
                      className="rounded border border-neutral-700 px-2 text-sm text-neutral-400 hover:border-red-500 hover:text-red-400"
                      title="Remove field"
                    >
                      ×
                    </button>
                  </div>
                ))}
                <button onClick={addExtraFieldRow} className="text-xs text-sky-400 hover:text-sky-300">
                  + Add field
                </button>
              </div>
            </div>
          </div>
        )}

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
            tool="pwreset"
            toState={(data: PwResetResponse) => ({ status: 'done' as const, result: data })}
            getSummary={pwResetSummary}
            renderCard={(t, scan) => <TargetScanCard target={t} scan={scan} />}
          />
        ) : (
          <>
            {!hasScans && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Select or type one or more request-reset endpoints, then run.
              </div>
            )}

            {hasScans && (
              <BatchResultsPanel
                entries={Object.entries(scans)}
                getSummary={pwResetSummary}
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

// pwResetSummary is one target's one-line compact-view badge once a batch
// covers more than BatchResultsPanel's threshold -- mirrors Probe.tsx's
// probeScanSummary.
function pwResetSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
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
  cancelled: { label: 'Stopped', cls: 'border-neutral-700 bg-neutral-900 text-neutral-400' },
}

function ScanStatusBadge({ status }: { status: TargetScanState['status'] }) {
  const meta = SCAN_STATUS_STYLES[status]
  return <span className={`rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${meta.cls}`}>{meta.label}</span>
}

// TargetScanCard is one endpoint's whole run lifecycle in a batch -- same
// role as Bypass403.tsx's TargetScanCard / Probe.tsx's TargetScanCard.
function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const result = scan.result

  const severityCounts = useMemo(() => {
    const c: Record<ProbeSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const m of result?.modules ?? []) c[m.severity] += m.findings.length
    return c
  }, [result])

  const totalFindings = (result?.modules ?? []).reduce((n, m) => n + m.findings.length, 0)

  // Once at least one module found something, only list the categories that
  // actually hit -- same reasoning as Probe.tsx's sortedModules: with every
  // check registered, a "nothing found" card per category just pushes the
  // real findings off-screen.
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

      {scan.status === 'done' && result && (
        <>
          <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
            <div className="flex flex-wrap gap-x-6 gap-y-1">
              <span>
                Baseline → <span className="font-mono text-neutral-300">{result.baseline.method}</span>{' '}
                <span className="font-mono text-neutral-200">{result.baseline.statusCode}</span> · {result.baseline.contentLength}b
              </span>
            </div>
          </div>

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

function SeverityTile({ severity, value }: { severity: ProbeSeverity; value: number }) {
  const meta = SEVERITY_META[severity]
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-center">
      <p className={`text-2xl font-semibold ${meta.text}`}>{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-neutral-500">{meta.label}</p>
    </div>
  )
}

function ModuleCard({ module }: { module: PwResetModuleResult }) {
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

// FindingRow mirrors Probe.tsx's FindingRow: an always-visible label/detail
// line, plus a toggleable "how it was found" panel for evidence/method/
// status when the backend sent any.
function FindingRow({ finding }: { finding: PwResetFinding }) {
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
