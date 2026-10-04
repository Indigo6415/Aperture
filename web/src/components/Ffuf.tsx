import { useEffect, useState } from 'react'
import { api } from '../api'
import type { Credential, Finding, FfufOptions, Job, JobOptions, NodeStatus, RunStatus, Target, WordlistInfo } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { TargetButtons } from './TargetButtons'
import { TargetProgressPanel, type TargetProgress } from './TargetProgressPanel'
import { ResultsTable } from './ResultsTable'
import { JobHistory } from './JobHistory'
import { JobTemplatePicker } from './JobTemplatePicker'
import { CredentialPicker } from './CredentialPicker'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { estimateEtaSeconds } from '../eta'
import { inputBase } from '../formStyles'
import { toAbsoluteUrl } from '../url'

type HeaderRow = { name: string; value: string }

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

// splitArgs turns the free-text "extra ffuf flags" field into the []string
// exec.CommandContext wants. Whitespace-separated only -- no quoting support
// -- since this field is an escape hatch for whatever flag isn't already a
// dedicated field below (e.g. -sf, -ignore-body), not a full shell parser.
function splitArgs(raw: string): string[] | undefined {
  const parts = raw.trim().split(/\s+/).filter(Boolean)
  return parts.length > 0 ? parts : undefined
}

// splitCommaList turns a comma-separated field (extensions) into a trimmed
// []string, dropping empty entries a trailing/leading/doubled comma would
// otherwise leave behind.
function splitCommaList(raw: string): string[] | undefined {
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean)
  return parts.length > 0 ? parts : undefined
}

// Ffuf is the general-purpose FFuF launcher: unlike the Subdomain/VHost
// Scanner tabs (which only ever fuzz a subdomain label or a vhost Host
// header), this tab exposes ffuf's own parameters directly -- method,
// headers, POST body, extensions, match/filter rules, timing, proxy -- so
// FUZZ can go anywhere in the request (a path segment, a query string
// value, a header, a form field) and the job still runs through the same
// case/job/results infrastructure (progress, cancellation, the results
// table) every other tool tab uses.
export function FfufTab({
  caseId,
  targets,
  credentials,
  jobs,
  findings,
  statusOf,
  nodeStatus,
  jobProgress,
  nodeStartedAtRef,
  onStart,
  onCancel,
  onPromote,
}: {
  caseId: string
  targets: Target[]
  credentials: Credential[]
  jobs: Job[]
  findings: Finding[]
  statusOf: (job: Job) => RunStatus
  nodeStatus: Record<string, NodeStatus>
  jobProgress: Record<string, { done: number; total: number }>
  nodeStartedAtRef: React.MutableRefObject<Record<string, number>>
  onStart: (job: Job) => void
  onCancel: (job: Job) => void
  onPromote: (values: string[]) => void
}) {
  const [url, setUrl] = useState('')
  const [method, setMethod] = useState('GET')
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([{ name: '', value: '' }])
  const [body, setBody] = useState('')
  const [extensions, setExtensions] = useState('')
  const [wordlist, setWordlist] = useState('')
  const [wordlists, setWordlists] = useState<WordlistInfo[]>([])

  const [matchCodes, setMatchCodes] = useState('')
  const [filterCodes, setFilterCodes] = useState('')
  const [matchSize, setMatchSize] = useState('')
  const [filterSize, setFilterSize] = useState('')

  const [threads, setThreads] = useState('')
  const [timeoutSeconds, setTimeoutSeconds] = useState('')
  const [rateLimit, setRateLimit] = useState('')
  const [delay, setDelay] = useState('')
  const [proxy, setProxy] = useState('')
  const [autoCalibrate, setAutoCalibrate] = useState(false)
  const [followRedirects, setFollowRedirects] = useState(false)
  const [extraArgs, setExtraArgs] = useState('')

  const [showAdvanced, setShowAdvanced] = useState(false)
  const [starting, setStarting] = useState(false)
  const [message, setMessage] = useState('')
  const [credentialId, setCredentialId] = useState<string | undefined>()

  // Same "collapse the launcher once there's something to look at" pattern
  // every tool tab in CaseView uses.
  const [launcherOpen, setLauncherOpen] = useCollapsible('launcher.ffuf-custom', true)
  useAutoCollapseOnce(jobs.length > 0, setLauncherOpen)

  useEffect(() => {
    api.listWordlists().then(setWordlists).catch(() => {})
  }, [])

  const addHeaderRow = () => setHeaderRows((rows) => [...rows, { name: '', value: '' }])
  const updateHeaderRow = (i: number, patch: Partial<HeaderRow>) =>
    setHeaderRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const removeHeaderRow = (i: number) => setHeaderRows((rows) => (rows.length === 1 ? rows : rows.filter((_, idx) => idx !== i)))

  const hasFuzzSomewhere = url.includes('FUZZ') || headerRows.some((r) => r.value.includes('FUZZ')) || body.includes('FUZZ')
  const canRun = !starting && url.trim() !== '' && hasFuzzSomewhere

  const start = async () => {
    if (!canRun) return
    setStarting(true)
    setMessage('')
    try {
      const headers: Record<string, string> = {}
      for (const row of headerRows) {
        if (row.name.trim()) headers[row.name.trim()] = row.value
      }
      const ffuf: FfufOptions = {
        method,
        headers: Object.keys(headers).length ? headers : undefined,
        body: body || undefined,
        extensions: splitCommaList(extensions),
        matchCodes: matchCodes.trim() || undefined,
        filterCodes: filterCodes.trim() || undefined,
        matchSize: matchSize.trim() || undefined,
        filterSize: filterSize.trim() || undefined,
        autoCalibrate,
        followRedirects,
        delay: delay.trim() || undefined,
        proxy: proxy.trim() || undefined,
        extraArgs: splitArgs(extraArgs),
      }
      const options: JobOptions = {
        threads: threads ? Number(threads) : undefined,
        timeoutSeconds: timeoutSeconds ? Number(timeoutSeconds) : undefined,
        rateLimit: rateLimit ? Number(rateLimit) : undefined,
        wordlist: wordlist.trim() || undefined,
        ffuf,
        credentialId,
      }
      const res = await api.startJob(caseId, 'ffuf-custom', [url.trim()], options)
      if (res.jobId) {
        const job = await api.getJob(res.jobId)
        onStart(job)
        setMessage('Started — see results below')
      }
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  const targetProgress = (): TargetProgress[] => {
    const rows: TargetProgress[] = []
    for (const job of jobs) {
      const jStatus = statusOf(job)
      job.targets.forEach((target, i) => {
        const nodeId = `ffuf-${i}`
        const key = `${job.id}:${nodeId}`
        const status: NodeStatus = nodeStatus[key] ?? (jobProgress[key] ? 'running' : jStatus === 'running' ? 'pending' : jStatus)
        const p = jobProgress[key]
        const done = p?.done ?? 0
        const total = p?.total ?? 0
        const startedAt = nodeStartedAtRef.current[key] ?? null
        const detail = job.nodes?.find((n) => n.nodeId === nodeId)
        rows.push({
          key, target, status, done, total, etaSeconds: estimateEtaSeconds(done, total, startedAt),
          wordlist: detail?.wordlist, extensions: detail?.extensions, candidates: detail?.candidates,
          threads: detail?.threads, timeoutSeconds: detail?.timeoutSeconds, rateLimit: detail?.rateLimit,
          runId: job.runId, nodeId,
        })
      })
    }
    return rows
  }

  const launcherSummary = url.trim() ? `${method} ${url}` : 'No request set'

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="shrink-0 overflow-y-auto border-b border-neutral-800 p-3">
        <CollapsibleFormPanel
          title="Configure"
          open={launcherOpen}
          onToggle={() => setLauncherOpen(!launcherOpen)}
          summary={launcherSummary}
          onRun={start}
          canRun={canRun}
          loading={starting}
          runLabel="Run"
        >
          <p className="text-xs text-neutral-500">
            Fuzz any part of a request -- put the <code className="text-neutral-300">FUZZ</code> keyword in the URL (a path
            segment or query value), a header value, or the body, then pick a wordlist to fuzz it with.
          </p>

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
                placeholder="https://target.htb/FUZZ or https://target.htb/api?id=FUZZ"
                spellCheck={false}
                className={`${inputBase} font-mono`}
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
                    placeholder="Value (may contain FUZZ)"
                    spellCheck={false}
                    className={`${inputBase} flex-1 font-mono`}
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
            <span className="text-xs font-medium text-neutral-300">Body (POST/PUT data, may contain FUZZ)</span>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={3}
              placeholder="username=admin&password=FUZZ"
              spellCheck={false}
              className={`mt-1 ${inputBase} font-mono text-[11px] leading-snug`}
            />
          </label>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Wordlist file</span>
              <select value={wordlist} onChange={(e) => setWordlist(e.target.value)} className={inputBase}>
                <option value="">Directories category default</option>
                {wordlists.map((w) => (
                  <option key={w.name} value={w.name}>
                    {w.name} ({w.lines.toLocaleString()} lines)
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Extensions</span>
              <input value={extensions} onChange={(e) => setExtensions(e.target.value)} placeholder=".php,.bak,.old" className={inputBase} />
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Match codes (-mc)</span>
              <input value={matchCodes} onChange={(e) => setMatchCodes(e.target.value)} placeholder="all" className={inputBase} />
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-1.5 text-xs text-neutral-400" title="Probe with a random, guaranteed-bogus word first and filter out any response that matches it -- catches a catch-all/wildcard response that would otherwise flood every result as a false positive.">
              <input type="checkbox" checked={autoCalibrate} onChange={(e) => setAutoCalibrate(e.target.checked)} className="accent-sky-500" />
              Auto-calibrate
            </label>
            <label className="flex items-center gap-1.5 text-xs text-neutral-400">
              <input type="checkbox" checked={followRedirects} onChange={(e) => setFollowRedirects(e.target.checked)} className="accent-sky-500" />
              Follow redirects
            </label>
            <button
              type="button"
              onClick={() => setShowAdvanced((v) => !v)}
              className="rounded border border-neutral-800 px-2 py-0.5 text-xs text-neutral-500 hover:text-neutral-300"
            >
              {showAdvanced ? 'Hide advanced ▾' : 'Advanced (filters, timing, proxy) ▸'}
            </button>
            <button
              onClick={start}
              disabled={!canRun}
              className="ml-auto rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {starting ? 'Starting…' : 'Run'}
            </button>
          </div>

          {showAdvanced && (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Filter codes (-fc)</span>
                <input value={filterCodes} onChange={(e) => setFilterCodes(e.target.value)} placeholder="none" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Match size (-ms)</span>
                <input value={matchSize} onChange={(e) => setMatchSize(e.target.value)} placeholder="none" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Filter size (-fs)</span>
                <input value={filterSize} onChange={(e) => setFilterSize(e.target.value)} placeholder="none" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Threads</span>
                <input value={threads} onChange={(e) => setThreads(e.target.value)} placeholder="default" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Timeout (s)</span>
                <input value={timeoutSeconds} onChange={(e) => setTimeoutSeconds(e.target.value)} placeholder="default" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Rate limit (req/s)</span>
                <input value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} placeholder="unlimited" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Delay (-p)</span>
                <input value={delay} onChange={(e) => setDelay(e.target.value)} placeholder="0.1-0.5" className={inputBase} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Proxy (-x)</span>
                <input value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="http://127.0.0.1:8080" className={inputBase} />
              </label>
              <label className="col-span-2 flex flex-col gap-0.5 sm:col-span-4">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Extra ffuf flags</span>
                <input value={extraArgs} onChange={(e) => setExtraArgs(e.target.value)} placeholder="-sf -ignore-body" className={`${inputBase} font-mono`} />
              </label>
            </div>
          )}

          {!hasFuzzSomewhere && url.trim() !== '' && (
            <p className="text-xs text-amber-400">FUZZ must appear in the URL, a header value, or the body.</p>
          )}
          {message && <p className="text-xs text-neutral-500">{message}</p>}

          <JobTemplatePicker
            tool="ffuf-custom"
            current={{
              threads: threads ? Number(threads) : undefined,
              timeoutSeconds: timeoutSeconds ? Number(timeoutSeconds) : undefined,
              rateLimit: rateLimit ? Number(rateLimit) : undefined,
              wordlist: wordlist.trim() || undefined,
              ffuf: {
                method,
                headers: Object.fromEntries(headerRows.filter((r) => r.name.trim()).map((r) => [r.name.trim(), r.value])),
                body: body || undefined,
                extensions: splitCommaList(extensions),
                matchCodes: matchCodes.trim() || undefined,
                filterCodes: filterCodes.trim() || undefined,
                matchSize: matchSize.trim() || undefined,
                filterSize: filterSize.trim() || undefined,
                autoCalibrate,
                followRedirects,
                delay: delay.trim() || undefined,
                proxy: proxy.trim() || undefined,
                extraArgs: splitArgs(extraArgs),
              },
            }}
            onApply={(options) => {
              setThreads(options.threads ? String(options.threads) : '')
              setTimeoutSeconds(options.timeoutSeconds ? String(options.timeoutSeconds) : '')
              setRateLimit(options.rateLimit ? String(options.rateLimit) : '')
              setWordlist(options.wordlist ?? '')
              const f = options.ffuf
              setMethod(f?.method || 'GET')
              const rows = Object.entries(f?.headers ?? {}).map(([name, value]) => ({ name, value }))
              setHeaderRows(rows.length > 0 ? rows : [{ name: '', value: '' }])
              setBody(f?.body ?? '')
              setExtensions((f?.extensions ?? []).join(','))
              setMatchCodes(f?.matchCodes ?? '')
              setFilterCodes(f?.filterCodes ?? '')
              setMatchSize(f?.matchSize ?? '')
              setFilterSize(f?.filterSize ?? '')
              setAutoCalibrate(f?.autoCalibrate ?? false)
              setFollowRedirects(f?.followRedirects ?? false)
              setDelay(f?.delay ?? '')
              setProxy(f?.proxy ?? '')
              setExtraArgs((f?.extraArgs ?? []).join(' '))
            }}
          />
        </CollapsibleFormPanel>
      </div>

      {jobs.length > 0 && <JobHistory jobs={jobs} statusOf={statusOf} onCancel={onCancel} panelKey="ffuf-custom" />}

      <div className="flex flex-1 overflow-hidden">
        <TargetProgressPanel targets={targetProgress()} tabKey="ffuf-custom" />
        <div className="flex-1 overflow-hidden">
          <ResultsTable findings={findings} caseId={caseId} facetPlacement="right" selectable onPromote={onPromote} />
        </div>
      </div>
    </div>
  )
}
