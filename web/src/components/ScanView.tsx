import { useEffect, useRef, useState } from 'react'
import { api, watchRun, watchScan } from '../api'
import type { Check, CheckKind, Finding, Run, Scan } from '../types'
import { ResultsTable } from './ResultsTable'

const CHECK_LABELS: Record<CheckKind, string> = {
  dns: 'DNS',
  tls: 'TLS',
  http: 'HTTP',
  subdomains: 'Subdomains',
  whois: 'WHOIS',
}

const STATUS_DOT: Record<Check['status'] | 'pending', string> = {
  pending: '#6b7280',
  running: '#facc15',
  done: '#34d399',
  error: '#f87171',
}

function keyFor(domain: string, kind: CheckKind): string {
  return `${domain}::${kind}`
}

// ScanView is the domain-scan dashboard: recon check cards for the apex
// domain, a subdomain table with its own per-row mini-status, and the
// existing ResultsTable/watchRun machinery reused unchanged for the
// auto-generated ffuf/feroxbuster flow's live findings.
export function ScanView({ scanId, onBack, onOpenFlow }: { scanId: string; onBack: () => void; onOpenFlow: (flowId: string) => void }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [checks, setChecks] = useState<Record<string, Check>>({})
  const [flowId, setFlowId] = useState<string | undefined>()
  const [, setRunId] = useState<string | undefined>()
  const [run, setRun] = useState<Run | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const stopScanWatch = useRef<() => void>(() => {})
  const stopRunWatch = useRef<() => void>(() => {})

  const watchTheRun = (id: string) => {
    stopRunWatch.current()
    api.getRun(id).then(setRun)
    api.listFindings(id).then(setFindings)
    stopRunWatch.current = watchRun(id, (ev) => {
      if (ev.type === 'finding' && ev.finding) {
        const finding = ev.finding
        setFindings((prev) => [...prev, finding])
      } else if (ev.type === 'done') {
        setRun((r) => (r ? { ...r, status: ev.status === 'failed' ? 'failed' : 'succeeded' } : r))
      }
    })
  }

  useEffect(() => {
    let cancelled = false
    setScan(null)
    setChecks({})
    setFlowId(undefined)
    setRunId(undefined)
    setRun(null)
    setFindings([])

    api.getScan(scanId).then((s) => {
      if (cancelled) return
      setScan(s)
      const byKey: Record<string, Check> = {}
      for (const c of s.checks ?? []) byKey[keyFor(c.domain, c.kind)] = c
      setChecks(byKey)
      if (s.flowId && s.runId) {
        setFlowId(s.flowId)
        setRunId(s.runId)
        watchTheRun(s.runId)
      }
    })

    stopScanWatch.current()
    stopScanWatch.current = watchScan(scanId, (ev) => {
      if (ev.type === 'check' && ev.check) {
        const check = ev.check
        setChecks((prev) => ({ ...prev, [keyFor(check.domain, check.kind)]: check }))
      } else if (ev.type === 'flow' && ev.flowId && ev.runId) {
        setFlowId(ev.flowId)
        setRunId(ev.runId)
        watchTheRun(ev.runId)
      }
    })

    return () => {
      cancelled = true
      stopScanWatch.current()
      stopRunWatch.current()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  if (!scan) {
    return <div className="p-8 text-neutral-500">Loading…</div>
  }

  const apexChecks: CheckKind[] = ['dns', 'tls', 'http', 'whois']
  const subdomainsCheck = checks[keyFor(scan.domain, 'subdomains')]
  const subdomains = (subdomainsCheck?.data?.subdomains as string[] | undefined) ?? []

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <header className="flex items-center gap-3 border-b border-neutral-800 bg-neutral-950 px-4 py-2">
        <button onClick={onBack} className="text-sm text-neutral-400 hover:text-neutral-200">
          ← Dashboard
        </button>
        <h1 className="font-mono text-sm font-medium text-neutral-100">{scan.domain}</h1>
        <span className="text-xs text-neutral-500">{new Date(scan.createdAt).toLocaleString()}</span>
        {flowId && (
          <button onClick={() => onOpenFlow(flowId)} className="ml-auto text-xs text-sky-400 hover:text-sky-300">
            Open in Flow Editor →
          </button>
        )}
      </header>

      <div className="mx-auto w-full max-w-5xl flex-1 space-y-6 px-4 py-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {apexChecks.map((kind) => (
            <CheckCard key={kind} kind={kind} check={checks[keyFor(scan.domain, kind)]} />
          ))}
        </div>

        <section>
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">
            Subdomains {subdomainsCheck?.status === 'done' && `(${subdomains.length})`}
          </h2>
          <SubdomainsTable subdomainsCheck={subdomainsCheck} subdomains={subdomains} checks={checks} />
        </section>

        <section>
          <div className="mb-2 flex items-center gap-2">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">Content discovery (ffuf + feroxbuster)</h2>
            {run && <RunBadge status={run.status} />}
          </div>
          <div className="h-96 overflow-hidden rounded-lg border border-neutral-800">
            <ResultsTable findings={findings} />
          </div>
        </section>
      </div>
    </div>
  )
}

function RunBadge({ status }: { status: Run['status'] }) {
  const color = status === 'running' ? 'text-amber-400' : status === 'failed' ? 'text-red-400' : 'text-emerald-400'
  return <span className={`text-xs font-medium ${color}`}>{status}</span>
}

function CheckCard({ kind, check }: { kind: CheckKind; check?: Check }) {
  const status = check?.status ?? 'pending'
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: STATUS_DOT[status] }} />
        <span className="text-xs font-semibold uppercase tracking-wide text-neutral-400">{CHECK_LABELS[kind]}</span>
      </div>
      {status === 'pending' && <p className="text-xs text-neutral-600">Queued…</p>}
      {status === 'running' && <p className="text-xs text-neutral-500">Checking…</p>}
      {status === 'error' && <p className="text-xs text-red-400">{check?.error || 'failed'}</p>}
      {status === 'done' && check?.data && <CheckSummary kind={kind} data={check.data} />}
    </div>
  )
}

function CheckSummary({ kind, data }: { kind: CheckKind; data: Record<string, unknown> }) {
  switch (kind) {
    case 'dns': {
      const a = (data.a as string[]) ?? []
      const ns = (data.ns as string[]) ?? []
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate font-mono">{a.length ? a.join(', ') : 'no A records'}</p>
          <p className="text-neutral-500">{ns.length} nameserver{ns.length === 1 ? '' : 's'}</p>
        </div>
      )
    }
    case 'tls': {
      const days = data.daysRemaining as number | undefined
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate">{(data.issuer as string) || 'unknown issuer'}</p>
          <p className={days !== undefined && days < 14 ? 'text-amber-400' : 'text-neutral-500'}>
            {days !== undefined ? `${days} days remaining` : ''}
          </p>
        </div>
      )
    }
    case 'http': {
      const code = data.statusCode as number | undefined
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p>
            <span className="font-mono">{code}</span> · {(data.scheme as string)?.toUpperCase()}
          </p>
          <p className="truncate text-neutral-500">{(data.title as string) || (data.server as string) || ''}</p>
        </div>
      )
    }
    case 'whois': {
      return (
        <div className="space-y-0.5 text-xs text-neutral-300">
          <p className="truncate">{(data.registrar as string) || 'unknown registrar'}</p>
          <p className="text-neutral-500">{(data.expiresAt as string)?.slice(0, 10) || ''}</p>
        </div>
      )
    }
    default:
      return null
  }
}

function SubdomainsTable({
  subdomainsCheck,
  subdomains,
  checks,
}: {
  subdomainsCheck?: Check
  subdomains: string[]
  checks: Record<string, Check>
}) {
  if (!subdomainsCheck) {
    return <p className="rounded-lg border border-neutral-800 px-4 py-6 text-center text-xs text-neutral-600">Queued…</p>
  }
  if (subdomainsCheck.status === 'error') {
    return <p className="rounded-lg border border-neutral-800 px-4 py-6 text-center text-xs text-red-400">{subdomainsCheck.error}</p>
  }
  if (subdomainsCheck.status === 'done' && subdomains.length === 0) {
    return <p className="rounded-lg border border-neutral-800 px-4 py-6 text-center text-xs text-neutral-600">None found via certificate transparency</p>
  }
  return (
    <div className="max-h-64 overflow-y-auto rounded-lg border border-neutral-800">
      <table className="w-full text-left text-sm">
        <tbody>
          {subdomains.map((sub) => {
            const dns = checks[keyFor(sub, 'dns')]
            const tls = checks[keyFor(sub, 'tls')]
            const http = checks[keyFor(sub, 'http')]
            const httpData = http?.data
            return (
              <tr key={sub} className="border-b border-neutral-900 last:border-0 hover:bg-neutral-900/60">
                <td className="px-3 py-1.5 font-mono text-neutral-200">{sub}</td>
                <MiniStatus label="DNS" check={dns} />
                <MiniStatus label="TLS" check={tls} />
                <td className="px-3 py-1.5 text-xs text-neutral-500">
                  {http?.status === 'done' && httpData ? `${httpData.statusCode} ${(httpData.title as string) || ''}` : http?.status === 'error' ? '—' : ''}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function MiniStatus({ label, check }: { label: string; check?: Check }) {
  const status = check?.status ?? 'pending'
  return (
    <td className="px-3 py-1.5">
      <span className="inline-flex items-center gap-1 text-xs text-neutral-500">
        <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: STATUS_DOT[status] }} />
        {label}
      </span>
    </td>
  )
}
