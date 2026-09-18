import { useEffect, useMemo, useState } from 'react'
import { api, ApiError } from '../api'
import { showToast } from '../toast'
import type { JwtScannerRequest } from '../jwtHandoff'
import type { JwtAttempt, JwtScanResponse, JwtTestResult, JwtTestStatus, WordlistInfo } from '../types'

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

// inputBase matches the input styling Settings.tsx's KeyCard already uses,
// so the two API-key inputs and this whole form read as the same design
// language rather than introducing a second input style.
const inputBase = 'w-full rounded border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500'

const TEST_ORDER_HINT: Record<string, string> = {
  alg_none: '1',
  empty_sig: '2',
  weak_secret: '3',
  jwk_injection: '4',
  kid_injection: '5',
  claim_tampering: '6',
  rs256_hs256_confusion: '7',
}

export function JwtScan({ prefill }: { prefill?: JwtScannerRequest }) {
  const [url, setUrl] = useState('')
  const [token, setToken] = useState('')
  const [method, setMethod] = useState('GET')
  const [authMode, setAuthMode] = useState<'header' | 'cookie'>('header')
  const [cookieName, setCookieName] = useState('')
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([{ name: '', value: '' }])
  const [pubKeyPem, setPubKeyPem] = useState('')
  const [wordlists, setWordlists] = useState<WordlistInfo[]>([])
  const [wordlistName, setWordlistName] = useState('')
  const [extraSecrets, setExtraSecrets] = useState('')
  const [showHints, setShowHints] = useState(false)

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<JwtScanResponse | null>(null)

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

  const canRun = url.trim() !== '' && token.trim() !== '' && !loading

  const runScan = async () => {
    if (!canRun) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const headers: Record<string, string> = {}
      for (const row of headerRows) {
        if (row.name.trim()) headers[row.name.trim()] = row.value
      }
      const resp = await api.jwtScan({
        url: url.trim(),
        token: token.trim(),
        method: method.trim() || 'GET',
        cookie: authMode === 'cookie' ? cookieName.trim() : undefined,
        headers: Object.keys(headers).length ? headers : undefined,
        pubKeyPem: pubKeyPem.trim() || undefined,
        wordlist: wordlistName || undefined,
        extraSecrets: extraSecrets.trim() || undefined,
      })
      setResult(resp)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  const counts = useMemo(() => {
    const c = { vulnerable: 0, safe: 0, skipped: 0 }
    for (const r of result?.results ?? []) c[r.status]++
    return c
  }, [result])

  return (
    <div className="mx-auto grid max-w-6xl grid-cols-1 gap-6 p-6 lg:grid-cols-[26rem_1fr]">
      <div className="space-y-4">
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">JWT Scanner</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Probes a protected endpoint with a battery of forged tokens (alg:none, weak HMAC secrets, JWK/kid injection, claim
            tampering, RS256→HS256 confusion) to find JWT verification misconfigurations. Authorized testing only.
          </p>
        </div>

        <Field label="Protected route to probe" hint="The URL your valid token currently grants access to.">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://target.htb/api/me"
            className={inputBase}
          />
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

        <ManualHints show={showHints} onToggle={() => setShowHints((v) => !v)} />
      </div>

      <div className="min-w-0 space-y-4">
        {error && (
          <div className="rounded-lg border border-red-800 bg-red-950/40 p-4 text-sm text-red-300">
            <p className="font-medium">Scan could not run</p>
            <p className="mt-1 text-xs text-red-400">{error}</p>
          </div>
        )}

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

        {result && (
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
                  Valid and invalid tokens yield identical responses — every result below rests on a content-length heuristic. Review
                  findings manually.
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
                <TestCard key={r.id} result={r} />
              ))}
            </div>
          </>
        )}
      </div>
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

function TestCard({ result }: { result: JwtTestResult }) {
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
        <span className="shrink-0 text-neutral-500">{attempt.httpStatus}</span>
      )}
    </li>
  )
}

function CopyButton({ text }: { text: string }) {
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          showToast('Copied to clipboard', 'success')
        } catch {
          showToast('Could not copy to clipboard', 'error')
        }
      }}
      className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
    >
      Copy
    </button>
  )
}

function ManualHints({ show, onToggle }: { show: boolean; onToggle: () => void }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <button onClick={onToggle} className="text-xs font-medium text-neutral-300 hover:text-neutral-100">
        {show ? '▾' : '▸'} Manual / out-of-band tests
      </button>
      {show && (
        <div className="mt-2 space-y-2 text-[11px] text-neutral-500">
          <p>These need an external callback server (Burp Collaborator, interactsh, etc.) and aren't run automatically:</p>
          <div>
            <p className="font-medium text-neutral-400">jku injection</p>
            <p>
              Set the header's <code>jku</code> to a URL you control serving a JWKS document, then forge a token with your own
              RSA key pair (<code>alg: RS256</code>).
            </p>
          </div>
          <div>
            <p className="font-medium text-neutral-400">x5u injection</p>
            <p>Same idea as jku, using the <code>x5u</code> header for an X.509 certificate chain URL.</p>
          </div>
          <div>
            <p className="font-medium text-neutral-400">kid SSRF</p>
            <p>
              If <code>kid</code> looks like it resolves a URL server-side, try setting it to a URL you control, e.g.{' '}
              <code>https://your.server/key</code>.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
