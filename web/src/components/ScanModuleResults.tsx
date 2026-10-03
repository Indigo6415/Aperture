import { useMemo, useState } from 'react'
import type { CapturedRequest, ProbeSeverity } from '../types'
import { CopyButton } from './CopyButton'
import { SEVERITY_META, SEVERITY_ORDER } from '../severityColor'
import { sendToTester } from '../testerHandoff'

// GenericFinding/GenericModuleResult cover the check-module shape every one
// of the four scanners added alongside this file (corsscan/openredirect/
// ssrf/csrf) already share field-for-field with internal/pwreset's own
// Finding/ModuleResult (see that package's doc comment for why each Go
// scanner keeps its own copy of the type rather than a shared one). Unlike
// the Go side, the frontend render logic for "a severity-colored module
// card full of label/detail/evidence findings" really is identical across
// all four, so -- rather than re-copying PwReset.tsx's ModuleCard/
// FindingRow/SeverityTile a fourth, fifth, sixth and seventh time -- those
// pieces live here once. CsrfFinding (which carries no method/statusCode)
// still satisfies this shape structurally, since both fields are optional.
export interface GenericFinding {
  label: string
  detail?: string
  evidence?: string
  method?: string
  statusCode?: number
  request?: CapturedRequest
}

export interface GenericModuleResult {
  id: string
  name: string
  severity: ProbeSeverity
  findings: GenericFinding[]
}

export function totalFindingsOf(modules: GenericModuleResult[]): number {
  return modules.reduce((n, m) => n + m.findings.length, 0)
}

export function hasSevereFindings(modules: GenericModuleResult[]): boolean {
  return modules.some((m) => m.findings.length > 0 && (m.severity === 'critical' || m.severity === 'high'))
}

// SeverityTiles is the 5-tile critical/high/medium/low/info count row every
// scan result card opens with.
export function SeverityTiles({ modules }: { modules: GenericModuleResult[] }) {
  const counts = useMemo(() => {
    const c: Record<ProbeSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const m of modules) c[m.severity] += m.findings.length
    return c
  }, [modules])

  return (
    <div className="grid grid-cols-5 gap-2">
      {SEVERITY_ORDER.map((sev) => {
        const meta = SEVERITY_META[sev]
        return (
          <div key={sev} className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-center">
            <p className={`text-2xl font-semibold ${meta.text}`}>{counts[sev]}</p>
            <p className="text-[11px] uppercase tracking-wide text-neutral-500">{meta.label}</p>
          </div>
        )
      })}
    </div>
  )
}

// ModuleResultsList renders every module as a collapsible card, sorted by
// severity -- once anything's been found, only the modules that actually
// found something are shown (same reasoning as PwReset.tsx's
// sortedModules: with every check always registered, a wall of "nothing
// found" cards just pushes the real findings off-screen).
export function ModuleResultsList({ modules }: { modules: GenericModuleResult[] }) {
  const total = totalFindingsOf(modules)
  const sorted = useMemo(() => {
    const rank: Record<ProbeSeverity, number> = Object.fromEntries(SEVERITY_ORDER.map((s, i) => [s, i])) as Record<ProbeSeverity, number>
    const relevant = total > 0 ? modules.filter((m) => m.findings.length > 0) : modules
    return [...relevant].sort((a, b) => rank[a.severity] - rank[b.severity] || a.name.localeCompare(b.name))
  }, [modules, total])

  if (total === 0) {
    return (
      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 text-center text-sm text-neutral-500">
        No issues found across {modules.length} check{modules.length === 1 ? '' : 's'}.
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {sorted.map((m) => (
        <ModuleCard key={m.id} module={m} />
      ))}
    </div>
  )
}

function ModuleCard({ module }: { module: GenericModuleResult }) {
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

function FindingRow({ finding }: { finding: GenericFinding }) {
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
