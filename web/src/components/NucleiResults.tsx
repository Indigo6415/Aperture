import { useMemo, useState } from 'react'
import type { Finding } from '../types'
import { hostnameOf } from '../url'
import { SEVERITY_META } from '../severityColor'
import { CopyButton } from './CopyButton'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToTester } from '../testerHandoff'
import { BatchResultsPanel, type BatchResultSummary } from './BatchResultsPanel'

// NUCLEI_SEVERITY_ORDER ranks nuclei's own -severity values worst-first,
// plus 'unknown' for a template that ships with none -- nuclei's info.
// severity field is a free string, not validated against ProbeSeverity's
// five values, so anything else it ever sends still gets a slot instead of
// silently sorting as if it were "info".
const NUCLEI_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const
type NucleiSeverity = (typeof NUCLEI_SEVERITY_ORDER)[number]
const SEVERITY_RANK: Record<NucleiSeverity, number> = Object.fromEntries(NUCLEI_SEVERITY_ORDER.map((s, i) => [s, i])) as Record<NucleiSeverity, number>

const UNKNOWN_META = { label: 'Unknown', text: 'text-neutral-400', badge: 'border-neutral-700 bg-neutral-900 text-neutral-400', border: 'border-l-neutral-600' }

function severityMetaOf(s: NucleiSeverity) {
  return s === 'unknown' ? UNKNOWN_META : SEVERITY_META[s]
}

// severityOf reads a nuclei Finding's severity out of its tags -- see
// adapters.NucleiAdapter.Run, which always emits Tags: [severity,
// templateID] in that order.
function severityOf(f: Finding): NucleiSeverity {
  const raw = (f.tags?.[0] ?? '').toLowerCase()
  return (NUCLEI_SEVERITY_ORDER as readonly string[]).includes(raw) ? (raw as NucleiSeverity) : 'unknown'
}

function templateIdOf(f: Finding): string | undefined {
  return f.tags?.[1]
}

interface HostGroup {
  host: string
  findings: Finding[]
  worst: NucleiSeverity
}

// groupByHost buckets nuclei's flat finding list by the hostname it hit --
// nuclei runs one node per originally-selected target (see
// handlers_jobs.go's ToolNuclei case), but grouping by the finding's own
// matched-at hostname (rather than threading job/node IDs through) works
// just as well and doesn't need this view to know anything about jobs.
function groupByHost(findings: Finding[]): HostGroup[] {
  const byHost = new Map<string, Finding[]>()
  for (const f of findings) {
    const host = hostnameOf(f.url) ?? f.url
    const list = byHost.get(host) ?? []
    list.push(f)
    byHost.set(host, list)
  }
  return [...byHost.entries()].map(([host, list]) => {
    const sorted = [...list].sort((a, b) => SEVERITY_RANK[severityOf(a)] - SEVERITY_RANK[severityOf(b)])
    return { host, findings: sorted, worst: severityOf(sorted[0]) }
  })
}

// NucleiResults is the nuclei tab's results view in place of the generic
// ResultsTable: nuclei findings carry a severity and a template name that
// matter far more than the status-code/size columns ResultsTable is built
// around (nuclei doesn't even set those), and previously the only way to
// see either was to expand every row one at a time in one long flat list --
// unworkable once a batch covers 100+ targets. This groups findings by the
// host they hit, shows severity counts up front, and hands the per-host
// grouping off to BatchResultsPanel so a large batch compacts into a
// sortable/filterable table instead of a wall of cards.
export function NucleiResults({ findings }: { findings: Finding[] }) {
  const groups = useMemo(() => groupByHost(findings), [findings])

  const severityCounts = useMemo(() => {
    const c: Record<NucleiSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }
    for (const f of findings) c[severityOf(f)]++
    return c
  }, [findings])

  if (findings.length === 0) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-sm text-neutral-600">
        No findings yet -- run nuclei against a target to see results here.
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col gap-3 overflow-y-auto p-3">
      <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
        {NUCLEI_SEVERITY_ORDER.map((sev) => (
          <div key={sev} className="rounded-lg border border-neutral-800 bg-neutral-900 p-2.5 text-center">
            <p className={`text-xl font-semibold ${severityMetaOf(sev).text}`}>{severityCounts[sev]}</p>
            <p className="text-[10px] uppercase tracking-wide text-neutral-500">{severityMetaOf(sev).label}</p>
          </div>
        ))}
      </div>

      <BatchResultsPanel
        entries={groups.map((g): [string, HostGroup] => [g.host, g])}
        getSummary={hostGroupSummary}
        renderCard={(_host, group) => <HostFindingsCard group={group} />}
      />
    </div>
  )
}

// hostGroupSummary is one host's compact-view badge -- every group here
// already has at least one finding (a clean host never appears at all,
// same reasoning as BreachCheck's crawl summary), so the only question is
// how bad the worst one is.
function hostGroupSummary(group: HostGroup): BatchResultSummary {
  const n = group.findings.length
  const label = `${n} · ${severityMetaOf(group.worst).label}`
  // Every group has at least one finding, so each one counts as an issue for
  // the "Issues only" toggle -- including info-only hosts, which keep a
  // neutral tone and would otherwise be read as clean.
  if (group.worst === 'critical' || group.worst === 'high') return { label, tone: 'danger', hasIssues: true }
  if (group.worst === 'medium' || group.worst === 'low') return { label, tone: 'warn', hasIssues: true }
  return { label, tone: 'neutral', hasIssues: true }
}

function HostFindingsCard({ group }: { group: HostGroup }) {
  return (
    <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="flex items-center gap-2">
        <span className="break-all font-mono text-sm text-neutral-200">{group.host}</span>
        <span className="shrink-0 text-xs text-neutral-500">
          {group.findings.length} finding{group.findings.length === 1 ? '' : 's'}
        </span>
      </div>
      <ul className="divide-y divide-neutral-900">
        {group.findings.map((f) => (
          <NucleiFindingRow key={`${f.sourceNodeId}:${f.id}`} finding={f} />
        ))}
      </ul>
    </div>
  )
}

function NucleiFindingRow({ finding: f }: { finding: Finding }) {
  const { openMenu } = useContextMenu()
  const [expanded, setExpanded] = useState(false)
  const severity = severityOf(f)
  const meta = severityMetaOf(severity)
  const templateId = templateIdOf(f)

  return (
    <li
      onContextMenu={(e) => {
        e.stopPropagation()
        openMenu(e, [
          { label: 'Copy URL', onSelect: () => copyToClipboard(f.url, 'Copied URL') },
          { label: 'Open in new tab', onSelect: () => window.open(f.url, '_blank', 'noopener,noreferrer') },
          { label: 'Send to Tester', onSelect: () => sendToTester(f.url, f.method || 'GET', f.headers) },
        ])
      }}
      className={`border-l-4 py-2 pl-2.5 text-xs ${meta.border}`}
    >
      <div onClick={() => setExpanded((v) => !v)} className="flex cursor-pointer items-start gap-2">
        <span className="mt-0.5 shrink-0 text-neutral-600">{expanded ? '▾' : '▸'}</span>
        <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${meta.badge}`}>{meta.label}</span>
        <div className="min-w-0 flex-1">
          <p className="text-neutral-200">{f.contentType || templateId || 'Unnamed template'}</p>
          {!expanded && (
            <p className="mt-0.5 truncate text-neutral-600" title={f.url}>
              {f.url}
            </p>
          )}
        </div>
      </div>
      {expanded && (
        <div className="ml-4 mt-1.5 space-y-1.5 rounded border border-neutral-800 bg-neutral-950 p-2">
          <div className="flex items-start gap-2">
            <span className="mt-0.5 shrink-0 text-[10px] uppercase tracking-wide text-neutral-600">URL</span>
            <span className="min-w-0 flex-1 break-all text-[11px] text-neutral-300">{f.url}</span>
            <span onClick={(e) => e.stopPropagation()}>
              <CopyButton text={f.url} />
            </span>
          </div>
          {templateId && (
            <p className="text-[11px] text-neutral-500">
              <span className="text-neutral-600">Template — </span>
              <span className="font-mono">{templateId}</span>
            </p>
          )}
        </div>
      )}
    </li>
  )
}
