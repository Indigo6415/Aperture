import { useEffect, useMemo, useState } from 'react'
import { api, ApiError } from '../api'
import type { SecretScanRequest as HandoffRequest } from '../secretScanHandoff'
import type { Credential, SecretMatch, SecretScanResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetPicker } from './TargetPicker'
import { CredentialPicker } from './CredentialPicker'
import { CopyButton } from './CopyButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToRepeater } from '../repeaterHandoff'

// TargetScanState is one target's place in a (possibly multi-target)
// secret-scan run -- same shape/reasoning as Probe.tsx's TargetScanState,
// minus a per-module progress map since a secret scan has no equivalent
// (the backend runs it as one synchronous crawl, not streamed checks).
interface TargetScanState {
  status: 'running' | 'done' | 'error'
  result?: SecretScanResponse
  error?: string
}

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
  const [scans, setScans] = useState<Record<string, TargetScanState>>({})
  const [credentialId, setCredentialId] = useState<string | undefined>()

  const hasScans = Object.keys(scans).length > 0
  // Form starts open and collapses itself the first time a scan result
  // arrives, so the findings column gets the width -- see
  // JwtScan.tsx/Probe.tsx's identical pattern.
  const [formOpen, setFormOpen] = useCollapsible('secretscan.form', true)
  useAutoCollapseOnce(hasScans, setFormOpen)

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
  const canRun = runTargets.length > 0 && !running

  // runScan kicks off one independent crawl per target in runTargets --
  // each resolves on its own schedule, so a slow/unresponsive target
  // doesn't hold up the others' results from appearing.
  const runScan = () => {
    if (!canRun) return
    const list = runTargets
    setScans(Object.fromEntries(list.map((t) => [t, { status: 'running' as const }])))
    for (const t of list) runOneScan(t)
  }

  const runOneScan = async (targetValue: string) => {
    try {
      // A target picked from the case list (or typed bare, e.g.
      // "target.htb") has no scheme -- secretscan.Run rejects that outright
      // ("invalid URL"), unlike Probe's target field, whose backend fills
      // in a default scheme itself. Normalize here, keyed display-side by
      // the original raw value the user actually picked/typed.
      const resp = await api.secretScan({ url: toAbsoluteUrl(targetValue), recursionDepth, entropy, credentialId, caseId })
      // Defensive: normalize away any null array (the backend always sends
      // [] now, but a null here previously crashed this whole tab on
      // .length -- never let that class of bug black-screen the app again).
      const result: SecretScanResponse = { pagesScanned: resp.pagesScanned ?? [], scriptsScanned: resp.scriptsScanned ?? [], matches: resp.matches ?? [] }
      setScans((prev) => ({ ...prev, [targetValue]: { status: 'done', result } }))
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
      setScans((prev) => ({ ...prev, [targetValue]: { status: 'error', error: message } }))
    }
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
            its same-origin scripts, optionally following same-origin links and flagging unlabeled high-entropy strings. Runs
            against as many targets at once as you select. Authorized testing only.
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
          <TargetScanCard key={t} target={t} scan={scan} />
        ))}
      </div>
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

      {scan.status === 'error' && (
        <div className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-xs text-red-300">{scan.error}</div>
      )}

      {scan.status === 'running' && (
        <div className="flex h-24 items-center justify-center rounded-lg border border-neutral-800 bg-neutral-900 text-xs text-neutral-500">
          Crawling and scanning…
        </div>
      )}

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
          { label: 'Send to Repeater', onSelect: () => sendToRepeater(match.location) },
        ])
      }}
      className="flex items-start gap-2 py-2 text-xs"
    >
      <div className="min-w-0 flex-1">
        <p className="break-all font-mono text-neutral-200">{match.value}</p>
        <p className="mt-0.5 truncate text-neutral-600" title={match.location}>
          {match.method === 'entropy' ? 'entropy' : 'regex'} · {match.location}
        </p>
      </div>
      <CopyButton text={match.value} />
    </li>
  )
}
