import type { Check, TechDetection } from '../types'

// SEVERITY_ORDER/SEVERITY_COLOR mirror NVD's own CVSS severity vocabulary
// (critical/high/medium/low/unknown) -- same palette VulnTable.tsx uses for
// nuclei's severity vocabulary, kept as its own copy here since the two
// tables render unrelated data shapes.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'unknown']
const SEVERITY_COLOR: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#facc15',
  low: '#38bdf8',
  unknown: '#9ca3af',
}

interface TechRow {
  key: string
  host: string
  name: string
  category: string
  version: string
  cves: TechDetection['cves']
}

// buildTechRows flattens every host's "technologies" check (see
// internal/api's lookupTechCVEs, which replaces the old nmap -sV "service
// profile" feature) into one row per detected technology per host.
function buildTechRows(checks: Record<string, Check>): TechRow[] {
  const rows: TechRow[] = []
  for (const key in checks) {
    const check = checks[key]
    if (check.kind !== 'technologies' || check.status !== 'done') continue
    const technologies = (check.data?.technologies as TechDetection[] | undefined) ?? []
    for (const t of technologies) {
      rows.push({ key: `${check.domain}:${t.name}`, host: check.domain, name: t.name, category: t.category, version: t.version ?? '', cves: t.cves })
    }
  }
  return rows.sort((a, b) => a.host.localeCompare(b.host) || a.name.localeCompare(b.name))
}

export function TechTable({ checks }: { checks: Record<string, Check> }) {
  const rows = buildTechRows(checks)

  return (
    <div className="flex-1 overflow-auto">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-neutral-950">
          <tr>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Host</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Technology</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Category</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Version</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">CVEs</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const cves = [...(r.cves ?? [])].sort(
              (a, b) => SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) - SEVERITY_ORDER.indexOf(b.severity.toLowerCase()),
            )
            return (
              <tr key={r.key} className="border-b border-neutral-900 hover:bg-neutral-900/60">
                <td className="px-3 py-1.5 font-mono text-neutral-500">{r.host}</td>
                <td className="px-3 py-1.5 text-neutral-200">{r.name}</td>
                <td className="px-3 py-1.5 text-xs text-neutral-500">{r.category}</td>
                <td className="px-3 py-1.5 font-mono text-neutral-300">{r.version || '—'}</td>
                <td className="px-3 py-1.5">
                  {cves.length === 0 ? (
                    <span className="text-xs text-neutral-600">—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {cves.map((c) => {
                        const severity = c.severity.toLowerCase()
                        const color = SEVERITY_COLOR[severity] ?? SEVERITY_COLOR.unknown
                        return (
                          <a
                            key={c.id}
                            href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                            target="_blank"
                            rel="noreferrer"
                            title={c.description}
                            className="rounded border px-1.5 py-0.5 font-mono text-xs font-semibold"
                            style={{ color, borderColor: color }}
                          >
                            {c.id}
                          </a>
                        )
                      })}
                    </div>
                  )}
                </td>
              </tr>
            )
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan={5} className="px-3 py-8 text-center text-neutral-600">
                No technologies fingerprinted yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
