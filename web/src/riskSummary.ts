import type { CaseScan, CVE, Check, ProbeSeverity, TechDetection } from './types'

// RiskSummary is what RiskPanel.tsx renders -- a client-side rollup of the
// severity signals a case has surfaced so far: CVEs against fingerprinted
// technology versions (bumped by CISA KEV/FIRST.org EPSS exploit-likelihood
// signals, see internal/cve.EnrichExploitSignals), dangling-CNAME takeover
// flags, and -- once a case has any -- persisted Probe/JWT/Secret Scanner
// runs (see CaseScan). findingCounts folds CVE severities and case scan
// severities into one scale so the severity tiles read as "everything this
// case has found," not just the CVE half of it.
export interface RiskSummary {
  findingCounts: Record<ProbeSeverity, number>
  topCves: (CVE & { tech: string })[]
  kevCount: number
  takeovers: { domain: string; provider: string }[]
  recentScans: CaseScan[]
}

// cveSeverityToProbe maps NVD's CVSS severity vocabulary (CRITICAL/HIGH/
// MEDIUM/LOW, see internal/cve.CVE) onto the same five-bucket ProbeSeverity
// scale the rest of the UI already uses, so RiskPanel can reuse
// SEVERITY_META/SEVERITY_ORDER as-is instead of inventing its own palette.
function cveSeverityToProbe(severity: string): ProbeSeverity {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'high'
    case 'MEDIUM':
      return 'medium'
    case 'LOW':
      return 'low'
    default:
      return 'info'
  }
}

// topCvesCount caps how many CVEs RiskPanel lists individually -- there can
// be dozens across a case's fingerprinted technologies, most of which
// aren't worth showing inline once the severity tiles already summarize
// the whole picture.
const topCvesCount = 8
// recentScansCount caps how many persisted scans RiskPanel lists -- a long
// engagement can accumulate dozens of Probe/JWT/Secret runs, most of which
// found nothing worth calling out individually.
const recentScansCount = 8

export function buildRiskSummary(checks: Record<string, Check>, caseScans: CaseScan[] = []): RiskSummary {
  const findingCounts: Record<ProbeSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  const allCves: (CVE & { tech: string })[] = []
  const takeovers: { domain: string; provider: string }[] = []

  for (const check of Object.values(checks)) {
    if (check.kind === 'technologies' && check.status === 'done') {
      const technologies = (check.data?.technologies as TechDetection[] | undefined) ?? []
      for (const tech of technologies) {
        for (const cve of tech.cves ?? []) {
          findingCounts[cveSeverityToProbe(cve.severity)]++
          allCves.push({ ...cve, tech: tech.version ? `${tech.name} ${tech.version}` : tech.name })
        }
      }
    }
    if (check.kind === 'takeover' && check.status === 'done') {
      const domain = check.domain
      const provider = (check.data?.provider as string | undefined) ?? 'unknown provider'
      takeovers.push({ domain, provider })
    }
  }

  for (const scan of caseScans) {
    findingCounts[scan.severity]++
  }

  // KEV-confirmed CVEs first (an actually-exploited CVE outranks a merely
  // higher CVSS score), then by score within each group.
  const topCves = [...allCves].sort((a, b) => Number(b.kev) - Number(a.kev) || b.score - a.score).slice(0, topCvesCount)
  const kevCount = allCves.filter((c) => c.kev).length
  const recentScans = caseScans.slice(0, recentScansCount)

  return { findingCounts, topCves, kevCount, takeovers, recentScans }
}
