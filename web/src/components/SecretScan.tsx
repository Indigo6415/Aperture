import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { SecretScanRequest as HandoffRequest } from '../secretScanHandoff'
import type { Credential, SecretMatch, SecretScanResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { BatchResultsPanel, stoppedSummary, type BatchResultSummary } from './BatchResultsPanel'
import { ScanHistoryPanel } from './ScanHistoryPanel'
import { ScanWindowTabs } from './ScanWindowTabs'
import { latestByTarget, loadCaseScans } from '../scanHistory'
import { CopyButton } from './CopyButton'
import { SendToTesterButton } from './SendToTesterButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { emptyProgress, runTrackedScan, type TrackedScan, runBatch, stopTrackedScan, useScanBatch, stopAllScans } from '../scanProgress'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToTester } from '../testerHandoff'

// TargetScanState is one target's place in a (possibly multi-target)
// secret-scan run -- same shape/reasoning as Probe.tsx's TargetScanState,
// minus a per-module progress map since a secret scan has no equivalent
// (the backend runs it as one synchronous crawl, not streamed checks).
import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'

type TargetScanState = TrackedScan<SecretScanResponse>

// SecretScan is Aperture's Go/tsx port of Snitch (see internal/secretscan):
// crawl a URL (and, if a recursion depth is set, same-origin pages it links
// to), regex/entropy-scan every page and same-origin script it fetches, and
// list whatever recognizable API keys/tokens/credentials turn up. Runs
// against every target the user selects or types at once, same batch
// pattern as Probe.tsx.
export function SecretScan({
  caseId,
  targets,
  credentials,
  prefill,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  prefill?: HandoffRequest
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [manualTarget, setManualTarget] = useState('')
  const [recursionDepth, setRecursionDepth] = useState(0)
  const [entropy, setEntropy] = useState(false)
  const [secretFinderEngine, setSecretFinderEngine] = useState(false)
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const batch = useScanBatch()
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [view, setView] = useState<'scan' | 'history'>('scan')

  const hasScans = Object.keys(scans).length > 0
  // Form starts open and collapses itself the first time a scan result
  // arrives, so the findings column gets the width -- see
  // JwtScan.tsx/Probe.tsx's identical pattern.
  const [formOpen, setFormOpen] = useCollapsible('secretscan.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

  // Restores this case's most recent secret scan per target on mount/reload
  // -- see saveCaseScan in internal/api/handlers_secrets.go. Every past run
  // is also browsable via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    loadCaseScans<SecretScanResponse>(caseId, 'secrets').then((list) => {
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

  // Applies a "Send to Secret Scanner" handoff (see secretScanHandoff.ts)
  // even though this component stays mounted the whole time the case is
  // open -- keyed on prefill.seq so sending the same URL twice in a row
  // still re-applies it.
  useEffect(() => {
    if (prefill) setManualTarget(prefill.url)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.seq])

  // manualTargets splits the free-text field on commas/newlines, matching
  // Probe.tsx's/the Targets tab's "paste a list" convention.
  const manualTargets = useMemo(() => manualTarget.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean), [manualTarget])
  const runTargets = useMemo(() => [...new Set([...selected, ...manualTargets])], [selected, manualTargets])

  const running = Object.values(scans).some((s) => s.status === 'running')
  // stopScan stops one target's running scan. Its card settles itself once the
  // server's terminal event arrives.
  const stopScan = (t: string) => stopTrackedScan(scans[t])
  const speed = useScanSpeed()
  const canRun = runTargets.length > 0 && !running && speed.rps !== null

  // runScan kicks off one independent crawl per target in runTargets --
  // each resolves on its own schedule, so a slow/unresponsive target
  // doesn't hold up the others' results from appearing.
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
  const runOneScan = (targetValue: string, signal?: AbortSignal) =>
    runTrackedScan<SecretScanResponse>(
      () => api.secretScan({ requestsPerSecond: speed.rps ?? undefined, url: toAbsoluteUrl(targetValue), recursionDepth, entropy, secretFinderEngine, credentialId, caseId }),
      (update) => setScans((prev) => (prev[targetValue] ? { ...prev, [targetValue]: update(prev[targetValue]) } : prev)),
      signal,
    )

  // stopAll ends the whole batch: targets not yet started are skipped, and
  // every running target is cancelled.
  const stopAll = () => {
    batch.stop()
    setScans((prev) => stopAllScans(prev))
  }

  const runLabel = runTargets.length > 1 ? `Scan (${runTargets.length})` : 'Scan'

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-6">
      <CollapsibleFormPanel
        title="Secrets"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={runTargets.length > 0 ? `${runTargets.length} target${runTargets.length === 1 ? '' : 's'} queued` : 'No targets selected'}
        onRun={runScan}
        canRun={canRun}
        loading={running}
        runLabel={runLabel}
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Secrets</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Crawls a URL for exposed API keys, tokens, and credentials -- regex-matches a library of known key/token formats
            (AWS, GCP, GitHub, Slack, Stripe, private key blocks, database connection strings, and more) against the page and
            its same-origin scripts, optionally following same-origin links and flagging unlabeled high-entropy strings. Can
            also run a second, broader pattern library ported from the SecretFinder tool for extra coverage. Runs against as
            many targets at once as you select. Authorized testing only.
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
            One-off URLs not saved to the case -- comma- or newline-separated for a batch.
          </span>
          <textarea
            value={manualTarget}
            onChange={(e) => setManualTarget(e.target.value)}
            placeholder="https://target.htb/"
            rows={2}
            className={`mt-1 ${inputBase}`}
          />
        </label>

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">Follow links</span>
            <select
              value={recursionDepth}
              onChange={(e) => setRecursionDepth(Number(e.target.value))}
              className={`mt-1 ${inputBase}`}
            >
              <option value={0}>Just this page (+ its scripts)</option>
              <option value={1}>1 hop of same-origin links</option>
              <option value={2}>2 hops</option>
              <option value={3}>3 hops</option>
            </select>
          </label>
          <label className="mt-5 flex items-center gap-1.5 text-xs text-neutral-400" title="Also flags unlabeled high-entropy strings as possible secrets -- noisier, off by default.">
            <input type="checkbox" checked={entropy} onChange={(e) => setEntropy(e.target.checked)} className="accent-sky-500" />
            Also flag high-entropy strings
          </label>
        </div>

        <label
          className="flex items-center gap-1.5 text-xs text-neutral-400"
          title="Also matches against a second, broader pattern library ported from the SecretFinder tool -- more false positives, but a higher chance of catching something the core patterns miss. Off by default."
        >
          <input
            type="checkbox"
            checked={secretFinderEngine}
            onChange={(e) => setSecretFinderEngine(e.target.checked)}
            className="accent-sky-500"
          />
          Also run SecretFinder engine (broader, noisier)
        </label>


        {speed.control}


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

        {view === 'history' ? (
          <ScanHistoryPanel
            caseId={caseId}
            tool="secrets"
            toState={(data: SecretScanResponse) => ({ status: 'done' as const, result: data })}
            getSummary={secretScanSummary}
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
            getSummary={secretScanSummary}
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

// secretScanSummary is one target's one-line compact-view badge once a
// batch covers more than BatchResultsPanel's threshold -- any match at all
// is worth a look (tone: danger), same as Probe.tsx's summary but without a
// severity split, since every secret match is equally worth surfacing.
function secretScanSummary(scan: TargetScanState): BatchResultSummary {
  if (scan.status === 'cancelled') return stoppedSummary
  if (scan.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (scan.status === 'error') return { label: 'Error', tone: 'danger', failed: true }
  const n = scan.result?.matches.length ?? 0
  return n === 0 ? { label: 'Clean', tone: 'clean' } : { label: `${n} match${n === 1 ? '' : 'es'}`, tone: 'danger' }
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

// TargetScanCard is one target's whole scan lifecycle in a batch run --
// same role as Probe.tsx's TargetScanCard.
function TargetScanCard({ target, scan }: { target: string; scan: TargetScanState }) {
  const grouped = useMemo(() => {
    const byType = new Map<string, SecretMatch[]>()
    for (const m of scan.result?.matches ?? []) {
      const list = byType.get(m.type) ?? []
      list.push(m)
      byType.set(m.type, list)
    }
    return [...byType.entries()].sort((a, b) => b[1].length - a[1].length)
  }, [scan.result])

  const result = scan.result

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
                Pages scanned → <span className="text-neutral-200">{result.pagesScanned.length}</span>
              </span>
              <span>
                Scripts scanned → <span className="text-neutral-200">{result.scriptsScanned.length}</span>
              </span>
              <span>
                Matches → <span className={result.matches.length ? 'font-semibold text-red-400' : 'text-neutral-200'}>{result.matches.length}</span>
              </span>
            </div>
          </div>

          {result.matches.length === 0 ? (
            <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
              No secrets found across {result.pagesScanned.length} page{result.pagesScanned.length === 1 ? '' : 's'} and{' '}
              {result.scriptsScanned.length} script{result.scriptsScanned.length === 1 ? '' : 's'}.
            </div>
          ) : (
            <div className="space-y-3">
              {grouped.map(([type, matches]) => (
                <SecretTypeGroup key={type} type={type} matches={matches} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function SecretTypeGroup({ type, matches }: { type: string; matches: SecretMatch[] }) {
  const [expanded, setExpanded] = useState(true)
  return (
    <div className="rounded-lg border border-neutral-800 border-l-4 border-l-red-500 bg-neutral-900">
      <button onClick={() => setExpanded((v) => !v)} className="flex w-full items-center gap-3 p-4 text-left">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-neutral-100">{type}</p>
        </div>
        <span className="shrink-0 text-xs text-neutral-500">
          {matches.length} match{matches.length === 1 ? '' : 'es'}
        </span>
        <span className="shrink-0 text-xs text-neutral-600">{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded && (
        <div className="border-t border-neutral-800 px-4 py-2">
          <ul className="divide-y divide-neutral-900">
            {matches.map((m, i) => (
              <SecretMatchRow key={i} match={m} />
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function SecretMatchRow({ match }: { match: SecretMatch }) {
  const { openMenu } = useContextMenu()
  return (
    <li
      onContextMenu={(e) => {
        e.stopPropagation()
        openMenu(e, [
          { label: 'Copy value', onSelect: () => copyToClipboard(match.value, 'Copied secret') },
          { label: 'Copy location', onSelect: () => copyToClipboard(match.location, 'Copied URL') },
          { label: 'Open location in new tab', onSelect: () => window.open(match.location, '_blank', 'noopener,noreferrer') },
          { label: 'Send to Tester', onSelect: () => sendToTester(match.location, 'GET', match.headers) },
        ])
      }}
      className="flex items-start gap-2 py-2 text-xs"
    >
      <div className="min-w-0 flex-1">
        <p className="break-all font-mono text-neutral-200">{match.value}</p>
        <p className="mt-0.5 truncate text-neutral-600" title={match.location}>
          {match.method === 'entropy' ? 'entropy' : 'regex'}
          {match.engine === 'secretfinder' && (
            <span className="mx-1 rounded border border-amber-800 bg-amber-950/40 px-1 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-400">
              SecretFinder
            </span>
          )}
          {' · '}
          {match.location}
        </p>
      </div>
      <CopyButton text={match.value} />
      {/* The secret was found in the response at match.location, so that's the request to replay. */}
      <SendToTesterButton url={match.location} headers={match.headers} />
    </li>
  )
}
