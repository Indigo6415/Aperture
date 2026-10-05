import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { JwtScannerRequest } from '../jwtHandoff'
import type { CallbackSelection, CaseScan, Credential, JwtAttempt, JwtScanResponse, JwtTestResult, JwtTestStatus, Target, WordlistInfo } from '../types'
import { CopyButton } from './CopyButton'
import { StatusBadge } from './FindingBadges'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetButtons } from './TargetButtons'
import { CredentialPicker } from './CredentialPicker'
import { CallbackPicker } from './CallbackPicker'
import { ScanWindowTabs } from './ScanWindowTabs'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { sendToTester } from '../testerHandoff'
import { emptyProgress, runTrackedScan, stopTrackedScan, type TrackedScan } from '../scanProgress'
import { indicatorOfScans, useReportScanIndicator } from '../scanIndicator'
import { ScanTargetCard } from './ScanTargetCard'
import { stoppedSummary, type BatchResultSummary } from './BatchResultsPanel'
import { ScanErrorNotice } from './ScanErrorNotice'
import { useScanSpeed } from './scanSpeed'

// b64urlDecode decodes one base64url JWT segment (header or payload) into
// its UTF-8 text, tolerating the missing padding JWTs conventionally omit.
function b64urlDecode(segment: string): string {
  let s = segment.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const binary = atob(s)
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

// decodeToken is a purely client-side preview of a pasted token's header
// and payload -- lets the user sanity-check what they pasted before it ever
// leaves the browser to run an actual scan.
function decodeToken(token: string): { header?: unknown; payload?: unknown; error?: string } {
  const parts = token.trim().split('.')
  if (parts.length !== 3) {
    return token.trim() === '' ? {} : { error: `Expected 3 dot-separated parts, got ${parts.length}` }
  }
  try {
    return { header: JSON.parse(b64urlDecode(parts[0])), payload: JSON.parse(b64urlDecode(parts[1])) }
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) }
  }
}

type HeaderRow = { name: string; value: string }

const TEST_ORDER_HINT: Record<string, string> = {
  alg_none: '1',
  empty_sig: '2',
  weak_secret: '3',
  jwk_injection: '4',
  kid_injection: '5',
  claim_tampering: '6',
  rs256_hs256_confusion: '7',
  kid_ssrf: '8',
  jku_injection: '9',
  x5u_injection: '10',
}

export function JwtScan({
  caseId,
  targets,
  credentials,
  prefill,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  prefill?: JwtScannerRequest
}) {
  const [url, setUrl] = useState('')
  const [credentialId, setCredentialId] = useState<string | undefined>()
  const [token, setToken] = useState('')
  const [method, setMethod] = useState('GET')
  const [authMode, setAuthMode] = useState<'header' | 'cookie'>('header')
  const [cookieName, setCookieName] = useState('')
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([{ name: '', value: '' }])
  const [pubKeyPem, setPubKeyPem] = useState('')
  const [wordlists, setWordlists] = useState<WordlistInfo[]>([])
  const [wordlistName, setWordlistName] = useState('')
  const [extraSecrets, setExtraSecrets] = useState('')
  const [callback, setCallback] = useState<CallbackSelection | null>(null)

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<JwtScanResponse | null>(null)
  // live is the run's streamed progress, shown as one card above its results.
  const [live, setLive] = useState<TrackedScan<JwtScanResponse> | null>(null)
  // Publishes the live run's state to the case nav's border. JWT test results
  // carry no severity, so a finished run shows the clean green.
  useReportScanIndicator('jwtscan', indicatorOfScans(live ? { live } : {}, () => []))
  const [view, setView] = useState<'scan' | 'history'>('scan')

  // Restores this case's most recent JWT scan on mount/reload -- see
  // saveCaseScan in internal/api/handlers_jwt.go. Unlike the batch tools
  // (Probe, SecretScan, …) this tab only ever shows one scan at a time, so
  // the latest run is what comes back; every past run is still browsable
  // via the "Scan history" tab below.
  useEffect(() => {
    let cancelled = false
    api.listCaseScans(caseId, 'jwt').then(async (list) => {
      if (cancelled || list.length === 0) return
      try {
        const full = await api.getCaseScan(list[0].id)
        if (cancelled || !full.data) return
        setResult(JSON.parse(full.data) as JwtScanResponse)
        setUrl(list[0].target)
      } catch {
        // best-effort restore -- leave the tab empty if it fails
      }
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  // Form starts open (there's nothing else to look at yet) and collapses
  // itself the first time a scan result arrives, so the results column
  // below gets the full width -- see collapsible.ts. A user who re-expands
  // it afterward (e.g. to tweak a header and re-run) is never overridden
  // again this session, and their choice persists across reloads.
  const [formOpen, setFormOpen] = useCollapsible('jwtscan.form', true)
  useAutoCollapseOnce(result !== null, setFormOpen)

  useEffect(() => {
    api.listWordlists().then(setWordlists).catch(() => {})
  }, [])

  // Applies a "Send to JWT Scanner" handoff (see jwtHandoff.ts) even though
  // this component stays mounted the whole time the case is open -- keyed
  // on prefill.seq (not prefill.url) so sending the same URL twice in a row
  // still re-applies it instead of being a no-op dependency change.
  useEffect(() => {
    if (prefill) setUrl(prefill.url)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.seq])

  const decoded = useMemo(() => decodeToken(token), [token])

  const addHeaderRow = () => setHeaderRows((rows) => [...rows, { name: '', value: '' }])
  const updateHeaderRow = (i: number, patch: Partial<HeaderRow>) =>
    setHeaderRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const removeHeaderRow = (i: number) => setHeaderRows((rows) => (rows.length === 1 ? rows : rows.filter((_, idx) => idx !== i)))

  const speed = useScanSpeed()

  const canRun = url.trim() !== '' && token.trim() !== '' && !loading && speed.rps !== null

  const runScan = async () => {
    if (!canRun) return
    setLoading(true)
    setError('')
    setResult(null)
    setLive({ status: 'running', progress: emptyProgress() })
    const headers: Record<string, string> = {}
    for (const row of headerRows) {
      if (row.name.trim()) headers[row.name.trim()] = row.value
    }
    const outcome = await runTrackedScan<JwtScanResponse>(
      () =>
        api.jwtScan({
          requestsPerSecond: speed.rps ?? undefined,
          url: url.trim(),
          token: token.trim(),
          method: method.trim() || 'GET',
          cookie: authMode === 'cookie' ? cookieName.trim() : undefined,
          headers: Object.keys(headers).length ? headers : undefined,
          pubKeyPem: pubKeyPem.trim() || undefined,
          wordlist: wordlistName || undefined,
          extraSecrets: extraSecrets.trim() || undefined,
          credentialId,
          caseId,
          callback: callback ?? undefined,
        }),
      (update) => setLive((prev) => update(prev ?? { status: 'running', progress: emptyProgress() })),
    )
    // A stopped scan has neither a result nor an error, so it leaves no error behind.
    if (outcome.result) setResult(outcome.result)
    else if (outcome.error) setError(outcome.error)
    setLoading(false)
  }

  const counts = useMemo(() => {
    const c = { vulnerable: 0, safe: 0, skipped: 0 }
    for (const r of result?.results ?? []) c[r.status]++
    return c
  }, [result])

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto p-6 lg:flex-row lg:overflow-hidden">
      <div className="lg:min-h-0 lg:w-[26rem] lg:shrink-0 lg:overflow-y-auto lg:pr-1">
      <CollapsibleFormPanel
        title="JWT"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={url.trim() ? `${method} ${url}` : 'No target set'}
        onRun={runScan}
        canRun={canRun}
        loading={loading}
        runLabel="Run Scan"
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">JWT</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Probes a protected endpoint with a battery of forged tokens (alg:none, weak HMAC secrets, JWK/kid injection, claim
            tampering, RS256→HS256 confusion) to find JWT verification misconfigurations. Authorized testing only.
          </p>
        </div>

        <div>
          <span className="text-xs font-medium text-neutral-300">Out-of-band callback</span>
          <span className="mt-0.5 block text-[11px] text-neutral-600">
            Off by default: the kid-SSRF, jku, and x5u header-injection tests are reported as skipped without one. Pick a
            shared server to enable them -- jku/x5u additionally need an Aperture-hosted server (not webhook.site), since the
            target has to fetch back a JWKS document/certificate this process actually serves.
          </span>
          <div className="mt-1">
            <CallbackPicker value={callback} onChange={setCallback} />
          </div>
        </div>

        <Field label="Protected route to probe" hint="The URL your valid token currently grants access to.">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://target.htb/api/me"
            className={inputBase}
          />
          <TargetButtons targets={targets} onPick={(v) => setUrl(toAbsoluteUrl(v))} className="mt-1.5" />
        </Field>

        <Field label="JWT token">
          <textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIs..."
            rows={4}
            className={`${inputBase} font-mono text-[11px] leading-snug`}
            spellCheck={false}
          />
          {decoded.error && token.trim() !== '' && <p className="mt-1 text-xs text-red-400">{decoded.error}</p>}
          {!decoded.error && (decoded.header !== undefined || decoded.payload !== undefined) && (
            <div className="mt-2 space-y-2">
              <DecodedBlock title="Header" value={decoded.header} />
              <DecodedBlock title="Payload" value={decoded.payload} />
            </div>
          )}
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="HTTP method">
            <input value={method} onChange={(e) => setMethod(e.target.value)} list="jwt-methods" className={inputBase} />
            <datalist id="jwt-methods">
              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
          </Field>
          <Field label="Send token via">
            <select value={authMode} onChange={(e) => setAuthMode(e.target.value as 'header' | 'cookie')} className={inputBase}>
              <option value="header">Authorization: Bearer</option>
              <option value="cookie">Cookie</option>
            </select>
          </Field>
        </div>

        {authMode === 'cookie' && (
          <Field label="Cookie name">
            <input value={cookieName} onChange={(e) => setCookieName(e.target.value)} placeholder="session" className={inputBase} />
          </Field>
        )}

        <Field label="Extra HTTP headers" hint="Sent on every probe request, e.g. a required API key or Host override.">
          <div className="space-y-1.5">
            {headerRows.map((row, i) => (
              <div key={i} className="flex gap-1.5">
                <input
                  value={row.name}
                  onChange={(e) => updateHeaderRow(i, { name: e.target.value })}
                  placeholder="Name"
                  className={`${inputBase} flex-1`}
                />
                <input
                  value={row.value}
                  onChange={(e) => updateHeaderRow(i, { value: e.target.value })}
                  placeholder="Value"
                  className={`${inputBase} flex-1`}
                />
                <button
                  onClick={() => removeHeaderRow(i)}
                  className="rounded border border-neutral-700 px-2 text-sm text-neutral-400 hover:border-red-500 hover:text-red-400"
                  title="Remove header"
                >
                  ×
                </button>
              </div>
            ))}
            <button onClick={addHeaderRow} className="text-xs text-sky-400 hover:text-sky-300">
              + Add header
            </button>

            {speed.control}

            <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />
          </div>
        </Field>

        <Field
          label="RS256 public key (PEM)"
          hint="Optional -- left blank, the scan auto-discovers it from the token's jku/x5u header, OIDC discovery, or common well-known paths on the target."
        >
          <textarea
            value={pubKeyPem}
            onChange={(e) => setPubKeyPem(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----... (leave blank to auto-discover)"
            rows={3}
            className={`${inputBase} font-mono text-[11px]`}
            spellCheck={false}
          />
        </Field>

        <Field label="Extra secrets for the brute-force" hint="Both sources are merged with the built-in weak-secret list.">
          <div className="space-y-1.5">
            <select value={wordlistName} onChange={(e) => setWordlistName(e.target.value)} className={inputBase}>
              <option value="">No project wordlist</option>
              {wordlists.map((w) => (
                <option key={w.name} value={w.name}>
                  {w.name} ({w.lines} lines)
                </option>
              ))}
            </select>
            <textarea
              value={extraSecrets}
              onChange={(e) => setExtraSecrets(e.target.value)}
              placeholder={'Paste extra secrets, one per line…'}
              rows={2}
              className={`${inputBase} font-mono text-[11px]`}
              spellCheck={false}
            />
          </div>
        </Field>

        <button
          onClick={runScan}
          disabled={!canRun}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? 'Scanning…' : 'Run Scan'}
        </button>
      </CollapsibleFormPanel>
      </div>

      <div className="min-w-0 flex-1 space-y-4 lg:min-h-0 lg:overflow-y-auto lg:pr-1">
        <ScanWindowTabs view={view} onChange={setView} />

        {view === 'history' ? (
          <JwtHistoryTab caseId={caseId} />
        ) : (
          <>
            {error && <ScanErrorNotice label="Scan could not run" message={error} />}

            {!error && !result && !loading && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
                Results will appear here once you run a scan.
              </div>
            )}

            {loading && (
              <div className="flex h-64 items-center justify-center rounded-lg border border-neutral-800 text-sm text-neutral-500">
                Probing target — this can take a while with a large secret wordlist…
              </div>
            )}

            {live && (
              <div className="max-w-md">
                <ScanTargetCard
                  target={url.trim() || 'JWT scan'}
                  summary={jwtSummary(live)}
                  progress={live.progress}
                  selected={false}
                  onSelect={() => {}}
                  onStop={() => stopTrackedScan(live)}
                />
              </div>
            )}

            {result && (
              <JwtResultView
                result={result}
                counts={counts}
                request={{ url: url.trim(), method: method.trim() || 'GET', cookie: authMode === 'cookie' ? cookieName.trim() : undefined }}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

// JwtResultView is the whole scored-results section for one JwtScanResponse
// -- factored out of JwtScan's own render so the exact same layout can show
// either the live run or a past run opened from JwtHistoryTab below.
// JwtTestRequest is the endpoint/method/cookie-name a JwtScanResponse's
// tests were all run against -- known for a live, just-finished run (the
// form's own state), but not reconstructable for a past run opened from
// history (JwtScanResponse itself doesn't carry it), so "Send to Tester"
// only appears when this is passed.
interface JwtTestRequest {
  url: string
  method: string
  cookie?: string
}

function JwtResultView({
  result,
  counts,
  request,
}: {
  result: JwtScanResponse
  counts: { vulnerable: number; safe: number; skipped: number }
  request?: JwtTestRequest
}) {
  return (
    <>
      <div className="grid grid-cols-3 gap-3">
        <SummaryTile label="Vulnerable" value={counts.vulnerable} color="text-red-400" />
        <SummaryTile label="Safe" value={counts.safe} color="text-emerald-400" />
        <SummaryTile label="Skipped" value={counts.skipped} color="text-neutral-400" />
      </div>

      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
        <div className="flex flex-wrap gap-x-6 gap-y-1">
          <span>
            Valid token → <span className="text-neutral-200">{result.baseline.validStatus}</span> ({result.baseline.validLength} B)
          </span>
          <span>
            Invalid token → <span className="text-neutral-200">{result.baseline.invalidStatus}</span> ({result.baseline.invalidLength} B)
          </span>
          <span>
            Secrets tried: <span className="text-neutral-200">{result.secretsTried}</span>
          </span>
        </div>
        {result.baseline.identical && (
          <p className="mt-2 text-amber-400">
            Valid and invalid tokens yield identical responses — every result below rests on a content-length heuristic. Review findings
            manually.
          </p>
        )}
        {result.crackedSecret !== undefined && result.crackedSecret !== '' && (
          <div className="mt-2 flex items-center gap-2 text-emerald-400">
            <span>
              Cracked HMAC secret: <code className="rounded bg-neutral-950 px-1.5 py-0.5">{result.crackedSecret}</code>
            </span>
            <CopyButton text={result.crackedSecret} />
          </div>
        )}
      </div>

      <div className="space-y-3">
        {result.results.map((r) => (
          <TestCard key={r.id} result={r} request={request} />
        ))}
      </div>
    </>
  )
}

function jwtCounts(result: JwtScanResponse) {
  const c = { vulnerable: 0, safe: 0, skipped: 0 }
  for (const r of result.results) c[r.status]++
  return c
}

// JwtHistoryTab is the "Scan history" view for this tool tab: every JWT
// scan persisted for this case (see store.SaveCaseScan), most recent first
// -- pick one to load its full result below via JwtResultView, same as
// opening the live scan.
function JwtHistoryTab({ caseId }: { caseId: string }) {
  const [loading, setLoading] = useState(true)
  const [scans, setScans] = useState<CaseScan[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selected, setSelected] = useState<JwtScanResponse | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  useEffect(() => {
    let cancelled = false
    api.listCaseScans(caseId, 'jwt').then((list) => {
      if (cancelled) return
      setScans(list)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  const open = async (id: string) => {
    setSelectedId(id)
    setSelected(null)
    setLoadingDetail(true)
    try {
      const full = await api.getCaseScan(id)
      setSelected(full.data ? (JSON.parse(full.data) as JwtScanResponse) : null)
    } finally {
      setLoadingDetail(false)
    }
  }

  if (loading) return <div className="flex h-64 items-center justify-center text-sm text-neutral-600">Loading scan history…</div>
  if (scans.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
        No saved scans yet -- runs launched with this case selected will show up here.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="divide-y divide-neutral-900 rounded-lg border border-neutral-800 bg-neutral-950/40">
        {scans.map((s) => (
          <button
            key={s.id}
            type="button"
            onClick={() => open(s.id)}
            className={`flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-neutral-900/60 ${selectedId === s.id ? 'bg-neutral-900/60' : ''}`}
          >
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-neutral-200">{s.target}</span>
            <span className="shrink-0 text-[11px] text-neutral-500">{s.summary}</span>
            <span className="shrink-0 text-[11px] text-neutral-600">{new Date(s.createdAt).toLocaleString()}</span>
          </button>
        ))}
      </div>
      {loadingDetail && <p className="text-xs text-neutral-600">Loading…</p>}
      {selected && <JwtResultView result={selected} counts={jwtCounts(selected)} />}
    </div>
  )
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-neutral-300">{label}</span>
      {hint && <span className="mt-0.5 block text-[11px] text-neutral-600">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  )
}

function DecodedBlock({ title, value }: { title: string; value: unknown }) {
  if (value === undefined) return null
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-neutral-500">{title}</p>
      <pre className="mt-1.5 max-h-56 overflow-auto whitespace-pre-wrap break-all font-mono text-[12.5px] leading-relaxed text-neutral-300">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  )
}

function SummaryTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-center">
      <p className={`text-2xl font-semibold ${color}`}>{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-neutral-500">{label}</p>
    </div>
  )
}

function statusStyles(status: JwtTestStatus): { border: string; badge: string; label: string } {
  switch (status) {
    case 'vulnerable':
      return { border: 'border-l-red-500', badge: 'border-red-700 bg-red-950/60 text-red-300', label: 'Vulnerable' }
    case 'safe':
      return { border: 'border-l-emerald-500', badge: 'border-emerald-700 bg-emerald-950/60 text-emerald-300', label: 'Safe' }
    case 'skipped':
      return { border: 'border-l-neutral-700', badge: 'border-neutral-700 bg-neutral-800/60 text-neutral-400', label: 'Skipped' }
  }
}

function TestCard({ result, request }: { result: JwtTestResult; request?: JwtTestRequest }) {
  const [expanded, setExpanded] = useState(result.status === 'vulnerable')
  const styles = statusStyles(result.status)
  const order = TEST_ORDER_HINT[result.id]

  return (
    <div className={`rounded-lg border border-neutral-800 border-l-4 bg-neutral-900 p-4 ${styles.border}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-neutral-100">
            {order && <span className="text-neutral-600">{order} · </span>}
            {result.name}
          </p>
          <p className="mt-1 text-xs text-neutral-400">{result.summary}</p>
        </div>
        <span className={`shrink-0 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${styles.badge}`}>
          {styles.label}
        </span>
      </div>

      {result.token && (
        <div className="mt-3 flex items-start gap-2 rounded border border-neutral-800 bg-neutral-950 p-2">
          <code className="min-w-0 flex-1 break-all text-[10px] text-neutral-400">{result.token}</code>
          <CopyButton text={result.token} />
          {request?.url && (
            <button
              onClick={() =>
                sendToTester(
                  request.url,
                  request.method,
                  request.cookie ? { Cookie: `${request.cookie}=${result.token}` } : { Authorization: `Bearer ${result.token}` },
                )
              }
              className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
            >
              Send to Tester
            </button>
          )}
        </div>
      )}

      {result.attempts && result.attempts.length > 0 && (
        <div className="mt-3">
          <button onClick={() => setExpanded((v) => !v)} className="text-[11px] text-sky-400 hover:text-sky-300">
            {expanded ? 'Hide' : 'Show'} {result.attempts.length} attempt{result.attempts.length === 1 ? '' : 's'}
          </button>
          {expanded && (
            <ul className="mt-2 space-y-1">
              {result.attempts.map((a, i) => (
                <AttemptRow key={i} attempt={a} />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

function AttemptRow({ attempt }: { attempt: JwtAttempt }) {
  return (
    <li className="flex items-center gap-2 rounded border border-neutral-800/60 px-2 py-1 text-[11px]">
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${attempt.hit ? 'bg-red-500' : attempt.error ? 'bg-neutral-600' : 'bg-emerald-600'}`} />
      <span className="min-w-0 flex-1 truncate text-neutral-400">{attempt.label}</span>
      {attempt.error ? (
        <span className="shrink-0 text-neutral-600">error</span>
      ) : (
        <StatusBadge code={attempt.httpStatus} />
      )}
    </li>
  )
}


// jwtSummary is the live card's status pill: running while the tests run,
// then how many of them found the token forgeable once the run lands.
function jwtSummary(run: TrackedScan<JwtScanResponse>): BatchResultSummary {
  if (run.status === 'running') return { label: 'Running…', tone: 'neutral', running: true }
  if (run.status === 'cancelled') return stoppedSummary
  if (run.status === 'error') return { label: 'Failed', tone: 'danger' }
  const vulnerable = (run.result?.results ?? []).filter((r) => r.status === 'vulnerable').length
  return vulnerable === 0 ? { label: 'Clean', tone: 'clean' } : { label: `${vulnerable} vulnerable`, tone: 'danger' }
}
