import { useEffect, useState } from 'react'
import { api, ApiError } from '../api'
import type { RepeaterHandoffRequest } from '../repeaterHandoff'
import type { Credential, RepeaterHistoryEntry, RepeaterResponse, Target } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetButtons } from './TargetButtons'
import { CredentialPicker } from './CredentialPicker'
import { CopyButton } from './CopyButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'

type HeaderRow = { name: string; value: string }

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

function statusTextClass(code: number): string {
  if (code === 0) return 'text-neutral-500'
  if (code >= 200 && code < 300) return 'text-emerald-400'
  if (code >= 300 && code < 400) return 'text-sky-400'
  if (code >= 400 && code < 500) return 'text-amber-400'
  return 'text-red-400'
}

// Repeater is the manual request repeater: pick any Finding (or target),
// edit method/headers/body, resend, and view the raw response inline. A
// single explicit action per click -- one request sent, one response shown
// -- not a running job, so it's a synchronous form+result like
// JwtScan/Probe/SecretScan rather than anything engine/job-backed.
export function Repeater({
  caseId,
  targets,
  credentials,
  prefill,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  prefill?: RepeaterHandoffRequest
}) {
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([{ name: '', value: '' }])
  const [body, setBody] = useState('')
  const [followRedirects, setFollowRedirects] = useState(false)
  const [credentialId, setCredentialId] = useState<string | undefined>()

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<RepeaterResponse | null>(null)

  // history is this case's past sends (see store.RepeaterEntry) -- fetched
  // fresh whenever the case changes, and re-fetched after every send so a
  // just-sent request shows up without a manual refresh.
  const [history, setHistory] = useState<RepeaterHistoryEntry[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)

  const refreshHistory = () => {
    if (!caseId) return
    api.listRepeaterHistory(caseId).then(setHistory).catch(() => {})
  }
  useEffect(refreshHistory, [caseId])

  // loadEntry replays a past request's method/URL/headers/body into the
  // form without sending it -- an explicit second click (Send) still
  // decides when the request actually goes out.
  const loadEntry = (e: RepeaterHistoryEntry) => {
    setMethod(e.method || 'GET')
    setUrl(e.url)
    const rows = Object.entries(e.requestHeaders ?? {}).map(([name, value]) => ({ name, value }))
    setHeaderRows(rows.length > 0 ? rows : [{ name: '', value: '' }])
    setBody(e.requestBody ?? '')
    setFormOpen(true)
  }

  const deleteEntry = async (id: string) => {
    setHistory((prev) => prev.filter((e) => e.id !== id))
    try {
      await api.deleteRepeaterHistoryEntry(id)
    } catch {
      refreshHistory()
    }
  }

  // Form starts open and collapses itself the first time a response
  // arrives, so the response gets the width -- same pattern as
  // JwtScan.tsx/Probe.tsx/SecretScan.tsx.
  const [formOpen, setFormOpen] = useCollapsible('repeater.form', true)
  useAutoCollapseOnce(result !== null, setFormOpen)

  // Applies a "Send to Repeater" handoff (see repeaterHandoff.ts) even
  // though this component stays mounted the whole time the case is open --
  // keyed on prefill.seq so sending the same request twice in a row still
  // re-applies it.
  useEffect(() => {
    if (prefill) {
      setMethod(prefill.method || 'GET')
      setUrl(prefill.url)
      const rows = Object.entries(prefill.headers ?? {}).map(([name, value]) => ({ name, value }))
      setHeaderRows(rows.length > 0 ? rows : [{ name: '', value: '' }])
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefill?.seq])

  const addHeaderRow = () => setHeaderRows((rows) => [...rows, { name: '', value: '' }])
  const updateHeaderRow = (i: number, patch: Partial<HeaderRow>) =>
    setHeaderRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const removeHeaderRow = (i: number) => setHeaderRows((rows) => (rows.length === 1 ? rows : rows.filter((_, idx) => idx !== i)))

  const canRun = url.trim() !== '' && !loading

  const send = async () => {
    if (!canRun) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const headers: Record<string, string> = {}
      for (const row of headerRows) {
        if (row.name.trim()) headers[row.name.trim()] = row.value
      }
      const resp = await api.repeaterSend({
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
        title="Repeater"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={url.trim() ? `${method} ${url}${credentialId ? ' · ' + (credentials.find((c) => c.id === credentialId)?.name ?? '') : ''}` : 'No request set'}
        onRun={send}
        canRun={canRun}
        loading={loading}
        runLabel="Send"
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Repeater</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Builds and sends one manual HTTP request -- edit the method, URL, headers, and body, then send it and inspect the
            raw response. A single one-off request, not a running job.
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
              {history.map((e) => (
                <div key={e.id} className="flex items-center gap-2 px-3 py-1.5 text-xs">
                  <button onClick={() => loadEntry(e)} className="min-w-0 flex-1 truncate text-left hover:text-sky-300" title={e.url}>
                    <span className={`font-mono font-semibold ${statusTextClass(e.response.statusCode)}`}>{e.method}</span>{' '}
                    <span className="text-neutral-400">{e.url}</span>
                  </button>
                  <button
                    onClick={() => deleteEntry(e.id)}
                    className="shrink-0 text-neutral-600 hover:text-red-400"
                    title="Delete from history"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      </div>

      <div className="min-w-0 flex-1 space-y-4 lg:min-h-0 lg:overflow-y-auto lg:pr-1">
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

function ResponseView({ response }: { response: RepeaterResponse }) {
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
