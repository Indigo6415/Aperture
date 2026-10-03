import { useEffect, useState } from 'react'
import { api, ApiError } from '../api'
import type { TesterHandoffRequest } from '../testerHandoff'
import type { CookieVaultEntry, Credential, Target, TesterResponse } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetButtons } from './TargetButtons'
import { CredentialPicker } from './CredentialPicker'
import { CopyButton } from './CopyButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'
import { loadCaseScans, type RestoredScan } from '../scanHistory'
import { buildCurl } from '../curl'

type HeaderRow = { name: string; value: string }

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

// TesterScanRecord mirrors internal/api's testerScan -- the request
// alongside the response, exactly what's persisted to a case's scan
// history for one Tester send (see handleTesterSend).
interface TesterScanRecord {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  response: TesterResponse
}

function statusTextClass(code: number): string {
  if (code === 0) return 'text-neutral-500'
  if (code >= 200 && code < 300) return 'text-emerald-400'
  if (code >= 300 && code < 400) return 'text-sky-400'
  if (code >= 400 && code < 500) return 'text-amber-400'
  return 'text-red-400'
}

// formHeaderMap collects the header rows the user filled in, skipping rows
// with no name -- the same map a send submits.
function formHeaderMap(rows: HeaderRow[]): Record<string, string> {
  const headers: Record<string, string> = {}
  for (const row of rows) {
    if (row.name.trim()) headers[row.name.trim()] = row.value
  }
  return headers
}

// hostnameOf returns the lowercase host the server keys cookie-vault entries
// by (see hostFromTarget in handlers_cookievault.go), or '' when the URL
// doesn't parse. An unparseable URL can't be sent anyway.
function hostnameOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname.replace(/^\[|\]$/g, '').toLowerCase()
  } catch {
    return ''
  }
}

// requestHeaders returns every header a send actually goes out with. The
// form only shows what the user typed, but the server (see
// handleTesterSend) also merges in the selected credential's headers and
// cookie, then fills in the case's cookie-vault cookie for the target domain
// when no Cookie header is set. This repeats that merge in the same order,
// so the curl preview replays the real request, not just the visible form.
function requestHeaders(
  formHeaders: Record<string, string>,
  credential: Credential | undefined,
  cookieVault: CookieVaultEntry[],
  caseId: string,
  rawUrl: string,
): { headers: Record<string, string>; fromCredential: boolean; fromCookieVault: boolean } {
  // Credential headers form the base and the form's own headers overwrite
  // them, so an explicit header always beats the saved credential.
  const headers: Record<string, string> = { ...(credential?.headers ?? {}) }
  if (credential?.cookie) headers['Cookie'] = credential.cookie
  Object.assign(headers, formHeaders)
  const fromCredential = credential !== undefined && (Object.keys(credential.headers ?? {}).length > 0 || !!credential.cookie)

  // The cookie vault only fills in a Cookie header when nothing else set one.
  // The check ignores case, the same as applyDomainCookie on the server.
  let fromCookieVault = false
  const hasCookie = Object.keys(headers).some((k) => k.toLowerCase() === 'cookie')
  if (caseId && !hasCookie) {
    const host = hostnameOf(rawUrl)
    const entry = cookieVault.find((e) => e.domain.toLowerCase() === host)
    if (host && entry?.cookie) {
      headers['Cookie'] = entry.cookie
      fromCookieVault = true
    }
  }
  return { headers, fromCredential, fromCookieVault }
}

// CurlPanel shows the request as a curl command that updates with every edit,
// so it can be copied and replayed outside Aperture. notes names any values
// the send adds on its own (from a credential or the cookie vault), since the
// form doesn't show those.
function CurlPanel({ command, notes }: { command: string; notes: string[] }) {
  return (
    <div className="rounded-lg border border-neutral-800">
      <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">cURL</p>
        {command && <CopyButton text={command} />}
      </div>
      {command ? (
        <>
          <pre className="max-h-[24rem] overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11.5px] leading-relaxed text-neutral-300">
            {command}
          </pre>
          {notes.length > 0 && (
            <p className="border-t border-neutral-800 px-3 py-2 text-xs text-neutral-500">
              Includes {notes.join(' and ')}. The form doesn't show these, but the send uses them.
            </p>
          )}
        </>
      ) : (
        <p className="px-3 py-4 text-xs text-neutral-600">Enter a URL to see the equivalent curl command.</p>
      )}
    </div>
  )
}

// Tester is Aperture's manual request tester: every scanner's findings can
// be sent here (see testerHandoff.ts) to load the exact request that
// triggered the finding, then replay it as-is, edit method/headers/body,
// resend, and view the raw response inline -- a single explicit action per
// click, not a running job, so it's a synchronous form+result like
// JwtScan/Probe/SecretScan rather than anything engine/job-backed.
export function Tester({
  caseId,
  targets,
  credentials,
  cookieVault,
  prefill,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  cookieVault: CookieVaultEntry[]
  prefill?: TesterHandoffRequest
}) {
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([{ name: '', value: '' }])
  const [body, setBody] = useState('')
  const [followRedirects, setFollowRedirects] = useState(false)
  const [credentialId, setCredentialId] = useState<string | undefined>()

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<TesterResponse | null>(null)

  // history is this case's past sends, persisted like any other scan tool's
  // history (see store.CaseScan, tool "tester") -- fetched fresh whenever
  // the case changes, and re-fetched after every send so a just-sent
  // request shows up without a manual refresh.
  const [history, setHistory] = useState<RestoredScan<TesterScanRecord>[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)

  const refreshHistory = () => {
    if (!caseId) return
    loadCaseScans<TesterScanRecord>(caseId, 'tester').then(setHistory).catch(() => {})
  }
  useEffect(refreshHistory, [caseId])

  // loadEntry replays a past request's method/URL/headers/body into the
  // form without sending it -- an explicit second click (Send) still
  // decides when the request actually goes out.
  const loadEntry = (e: TesterScanRecord) => {
    setMethod(e.method || 'GET')
    setUrl(e.url)
    const rows = Object.entries(e.headers ?? {}).map(([name, value]) => ({ name, value }))
    setHeaderRows(rows.length > 0 ? rows : [{ name: '', value: '' }])
    setBody(e.body ?? '')
    setFormOpen(true)
  }

  // Form starts open and collapses itself the first time a response
  // arrives, so the response gets the width -- same pattern as
  // JwtScan.tsx/Probe.tsx/SecretScan.tsx.
  const [formOpen, setFormOpen] = useCollapsible('tester.form', true)
  useAutoCollapseOnce(result !== null, setFormOpen)

  // Applies a "Send to Tester" handoff (see testerHandoff.ts) even though
  // this component stays mounted the whole time the case is open -- keyed
  // on prefill.seq so sending the same request twice in a row still
  // re-applies it. This is how every scanner's findings hand their exact
  // captured request (method/url/headers/body) off to be replayed here.
  useEffect(() => {
    if (prefill) {
      setMethod(prefill.method || 'GET')
      setUrl(prefill.url)
      const rows = Object.entries(prefill.headers ?? {}).map(([name, value]) => ({ name, value }))
      setHeaderRows(rows.length > 0 ? rows : [{ name: '', value: '' }])
      setBody(prefill.body ?? '')
      setFormOpen(true)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.seq])

  const addHeaderRow = () => setHeaderRows((rows) => [...rows, { name: '', value: '' }])
  const updateHeaderRow = (i: number, patch: Partial<HeaderRow>) =>
    setHeaderRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const removeHeaderRow = (i: number) => setHeaderRows((rows) => (rows.length === 1 ? rows : rows.filter((_, idx) => idx !== i)))

  const canRun = url.trim() !== '' && !loading

  // Recomputed on every render, so the curl panel follows each keystroke in
  // the form, the credential picker, and the cookie vault.
  const selectedCredential = credentials.find((c) => c.id === credentialId)
  const sent = requestHeaders(formHeaderMap(headerRows), selectedCredential, cookieVault, caseId, url.trim())
  const curlCommand = url.trim()
    ? buildCurl({ method, url: url.trim(), headers: sent.headers, body: body || undefined, followRedirects })
    : ''
  const curlNotes: string[] = []
  if (sent.fromCredential && selectedCredential) {
    // Name only what the credential actually contributes, so the note doesn't
    // claim a cookie when the credential has none.
    const contributes = [
      Object.keys(selectedCredential.headers ?? {}).length > 0 ? 'headers' : '',
      selectedCredential.cookie ? 'cookie' : '',
    ].filter(Boolean).join(' and ')
    curlNotes.push(`the ${contributes} of credential "${selectedCredential.name}"`)
  }
  if (sent.fromCookieVault) curlNotes.push(`the cookie-vault cookie for ${hostnameOf(url.trim())}`)

  const send = async () => {
    if (!canRun) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const headers = formHeaderMap(headerRows)
      const resp = await api.testerSend({
        method,
        url: url.trim(),
        headers: Object.keys(headers).length ? headers : undefined,
        body: body || undefined,
        followRedirects,
        credentialId,
        caseId,
      })
      setResult(resp)
      refreshHistory()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto p-6 lg:flex-row lg:overflow-hidden">
      <div className="lg:min-h-0 lg:w-[26rem] lg:shrink-0 lg:overflow-y-auto lg:pr-1">
      <CollapsibleFormPanel
        title="Tester"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={url.trim() ? `${method} ${url}${credentialId ? ' · ' + (credentials.find((c) => c.id === credentialId)?.name ?? '') : ''}` : 'No request set'}
        onRun={send}
        canRun={canRun}
        loading={loading}
        runLabel="Send"
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Tester</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Builds and sends one manual HTTP request -- edit the method, URL, headers, and body, then send it and inspect the
            raw response. Any finding from any scanner can be sent here (right-click it → "Send to Tester") to load the exact
            request that triggered it. A single one-off request, not a running job.
          </p>
        </div>

        {/* Width utilities live on these wrapper divs, not stacked onto the
            same element as inputBase's own `w-full` -- two width classes on
            one element race in Tailwind's generated stylesheet order (not
            class-attribute order), and `w-full` was winning, collapsing the
            URL input to ~0 width with the method select stretched to fill
            the row. */}
        <div className="flex gap-2">
          <div className="w-28 shrink-0">
            <select value={method} onChange={(e) => setMethod(e.target.value)} className={inputBase}>
              {METHODS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>
          <div className="min-w-0 flex-1">
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') send()
              }}
              placeholder="https://target.htb/api/resource"
              className={inputBase}
            />
          </div>
        </div>
        <TargetButtons targets={targets} onPick={(v) => setUrl(toAbsoluteUrl(v))} />

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Headers</span>
          <div className="mt-1 space-y-1.5">
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
        </label>
        <CredentialPicker credentials={credentials} selected={credentialId} onSelect={setCredentialId} />

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Body</span>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={6}
            placeholder={'{"example": "value"}'}
            spellCheck={false}
            className={`mt-1 ${inputBase} font-mono text-[11px] leading-snug`}
          />
        </label>

        <label className="flex items-center gap-1.5 text-xs text-neutral-400">
          <input type="checkbox" checked={followRedirects} onChange={(e) => setFollowRedirects(e.target.checked)} className="accent-sky-500" />
          Follow redirects
        </label>

        <button
          onClick={send}
          disabled={!canRun}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? 'Sending…' : 'Send'}
        </button>
      </CollapsibleFormPanel>

      {caseId && (
        <div className="mt-4 rounded-lg border border-neutral-800">
          <button
            onClick={() => setHistoryOpen((v) => !v)}
            className="flex w-full items-center justify-between px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-neutral-500 hover:text-neutral-300"
          >
            <span>History ({history.length})</span>
            <span>{historyOpen ? '−' : '+'}</span>
          </button>
          {historyOpen && (
            <div className="max-h-72 divide-y divide-neutral-900 overflow-y-auto border-t border-neutral-800">
              {history.length === 0 && <p className="px-3 py-4 text-center text-xs text-neutral-600">No requests sent yet this case.</p>}
              {history.map((r) => (
                <button
                  key={r.scan.id}
                  onClick={() => loadEntry(r.data)}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-neutral-900/60"
                  title={r.data.url}
                >
                  <span className={`shrink-0 font-mono font-semibold ${statusTextClass(r.data.response.statusCode)}`}>{r.data.method}</span>
                  <span className="min-w-0 flex-1 truncate text-neutral-400">{r.data.url}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
      </div>

      <div className="min-w-0 flex-1 space-y-4 lg:min-h-0 lg:overflow-y-auto lg:pr-1">
        {/* Above the response and outside the collapsible form, so the curl
            command stays visible after a send collapses the form. */}
        <CurlPanel command={curlCommand} notes={curlNotes} />

        {error && (
          <div className="rounded-lg border border-red-800 bg-red-950/40 p-4 text-sm text-red-300">
            <p className="font-medium">Request could not be sent</p>
            <p className="mt-1 text-xs text-red-400">{error}</p>
          </div>
        )}

        {!error && !result && (
          <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
            The response will appear here once you send a request.
          </div>
        )}

        {result && <ResponseView response={result} />}
      </div>
    </div>
  )
}

function ResponseView({ response }: { response: TesterResponse }) {
  if (response.error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/40 p-4 text-sm text-red-300">
        <p className="font-medium">Request failed</p>
        <p className="mt-1 text-xs text-red-400">{response.error}</p>
        {response.durationMs > 0 && <p className="mt-1 text-xs text-neutral-500">after {response.durationMs}ms</p>}
      </div>
    )
  }

  const headerEntries = Object.entries(response.headers ?? {})

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs text-neutral-400">
        <div className="flex flex-wrap gap-x-6 gap-y-1">
          <span>
            Status → <span className={`font-mono font-semibold ${statusTextClass(response.statusCode)}`}>{response.status || response.statusCode}</span>
          </span>
          <span>
            Size → <span className="text-neutral-200">{response.contentLength} bytes</span>
          </span>
          <span>
            Time → <span className="text-neutral-200">{response.durationMs}ms</span>
          </span>
          {response.bodyEncoding === 'base64' && <span className="text-amber-400">binary body (base64-encoded)</span>}
        </div>
      </div>

      {headerEntries.length > 0 && (
        <div className="rounded-lg border border-neutral-800">
          <p className="border-b border-neutral-800 px-3 py-2 text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Response headers</p>
          <div className="divide-y divide-neutral-900 font-mono text-xs">
            {headerEntries.map(([name, value]) => (
              <div key={name} className="flex gap-2 px-3 py-1.5">
                <span className="w-40 shrink-0 text-neutral-500">{name}</span>
                <span className="min-w-0 flex-1 break-all text-neutral-300">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-lg border border-neutral-800">
        <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Raw response</p>
          <CopyButton text={response.raw} />
        </div>
        <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11.5px] leading-relaxed text-neutral-300">
          {response.raw}
        </pre>
      </div>
    </div>
  )
}
