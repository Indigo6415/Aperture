import { useMemo } from 'react'
import type { CaseScan, Check, Job, Target } from '../types'
import { buildRiskSummary } from '../riskSummary'
import { SEVERITY_META, SEVERITY_ORDER } from '../severityColor'
import { CopyButton } from './CopyButton'

const SCAN_TOOL_LABEL: Record<CaseScan['tool'], string> = { probe: 'Probe', jwt: 'JWT Scanner', secrets: 'Secret Scanner' }

// RiskPanel is a case's at-a-glance risk posture: CVE severities already
// surfaced by Identify's technology fingerprinting (KEV/EPSS-aware, see
// riskSummary.ts), dangling-CNAME takeover flags, and any Probe/JWT
// Scanner/Secret Scanner runs that were launched with this case selected --
// rolled up into one view instead of being scattered across each target's
// own check cards / tool tab. `checks` updates live as an Identify job
// streams in; `caseScans` is a plain fetch (see CaseView), since a scan run
// is a one-shot action, not a live stream.
export function RiskPanel({
  checks,
  targets,
  jobs,
  caseScans,
}: {
  checks: Record<string, Check>
  targets: Target[]
  jobs: Job[]
  caseScans: CaseScan[]
}) {
  const summary = useMemo(() => buildRiskSummary(checks, caseScans), [checks, caseScans])
  const totalFindings = SEVERITY_ORDER.reduce((n, s) => n + summary.findingCounts[s], 0)

  return (
    <div className="mx-auto h-full max-w-4xl space-y-6 overflow-y-auto px-4 py-6">
      <div>
        <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Risk posture</h1>
        <p className="mt-1 text-xs text-neutral-500">
          A rollup of CVE severities, takeover flags, and scan findings this case has surfaced so far. Updates live as Identify
          checks stream in; Probe/JWT/Secret Scanner runs are included once launched with this case selected.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-3 text-center text-xs text-neutral-400 sm:grid-cols-6">
        <StatTile label="Targets" value={targets.length} />
        <StatTile label="Jobs run" value={jobs.length} />
        <StatTile label="Findings" value={totalFindings} />
        <StatTile label="Actively exploited" value={summary.kevCount} accent={summary.kevCount > 0 ? 'text-red-400' : undefined} />
        <StatTile label="Takeover flags" value={summary.takeovers.length} accent={summary.takeovers.length > 0 ? 'text-red-400' : undefined} />
        <StatTile label="Scans run" value={caseScans.length} />
      </div>

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">Findings by severity</h2>
        <div className="grid grid-cols-5 gap-2">
          {SEVERITY_ORDER.map((sev) => (
            <div key={sev} className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-center">
              <p className={`text-2xl font-semibold ${SEVERITY_META[sev].text}`}>{summary.findingCounts[sev]}</p>
              <p className="text-[11px] uppercase tracking-wide text-neutral-500">{SEVERITY_META[sev].label}</p>
            </div>
          ))}
        </div>
      </div>

      {summary.takeovers.length > 0 && (
        <div>
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-red-400">Possible subdomain takeovers</h2>
          <div className="space-y-1.5">
            {summary.takeovers.map((t) => (
              <div key={t.domain} className="flex items-center gap-2 rounded-lg border border-red-800 bg-red-950/30 px-3 py-2 text-xs">
                <span className="min-w-0 flex-1 truncate font-mono text-red-200">{t.domain}</span>
                <span className="shrink-0 text-red-400">dangling CNAME → {t.provider}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">Top CVEs</h2>
        {summary.topCves.length === 0 ? (
          <div className="flex h-24 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
            No CVEs found yet -- run Identify against a target to fingerprint its technology stack.
          </div>
        ) : (
          <div className="space-y-1.5">
            {summary.topCves.map((cve) => (
              <div key={cve.id + cve.tech} className={`rounded-lg border border-neutral-800 border-l-4 bg-neutral-900 p-3 text-xs ${SEVERITY_META[cveSeverityKey(cve.severity)].border}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-medium text-neutral-200">{cve.id}</span>
                  <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${SEVERITY_META[cveSeverityKey(cve.severity)].badge}`}>
                    {cve.severity} · {cve.score}
                  </span>
                  {cve.kev && (
                    <span className="rounded border border-red-700 bg-red-950/60 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-300">
                      Actively exploited (KEV)
                    </span>
                  )}
                  {!cve.kev && cve.epss !== undefined && cve.epss > 0.1 && (
                    <span className="text-[10px] text-neutral-500">EPSS {(cve.epss * 100).toFixed(1)}%</span>
                  )}
                  <span className="text-neutral-500">{cve.tech}</span>
                  <span className="ml-auto shrink-0">
                    <CopyButton text={cve.id} />
                  </span>
                </div>
                {cve.description && <p className="mt-1 line-clamp-2 text-neutral-400">{cve.description}</p>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">Recent scans</h2>
        {summary.recentScans.length === 0 ? (
          <div className="flex h-16 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
            No Probe/JWT/Secret Scanner runs recorded yet -- launch one with this case selected to see it here.
          </div>
        ) : (
          <div className="space-y-1.5">
            {summary.recentScans.map((scan) => (
              <div
                key={scan.id}
                className={`flex items-center gap-2 rounded-lg border border-neutral-800 border-l-4 bg-neutral-900 px-3 py-2 text-xs ${SEVERITY_META[scan.severity].border}`}
              >
                <span className="shrink-0 rounded border border-neutral-700 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-neutral-400">
                  {SCAN_TOOL_LABEL[scan.tool]}
                </span>
                <span className="min-w-0 flex-1 truncate font-mono text-neutral-300">{scan.target}</span>
                <span className={`shrink-0 ${SEVERITY_META[scan.severity].text}`}>{scan.summary}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function cveSeverityKey(severity: string): keyof typeof SEVERITY_META {
  const s = severity.toLowerCase()
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s
  return 'info'
}

function StatTile({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <p className={`text-2xl font-semibold ${accent ?? 'text-neutral-200'}`}>{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-neutral-500">{label}</p>
    </div>
  )
}
