import type { Finding } from '../types'

// SEVERITY_ORDER/SEVERITY_COLOR mirror nuclei's own severity vocabulary
// (critical/high/medium/low/info) plus "unknown" for a template that didn't
// set one.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const SEVERITY_COLOR: Record<string, string> = {
  critical: '#f87171',
  high: '#fb923c',
  medium: '#facc15',
  low: '#38bdf8',
  info: '#9ca3af',
  unknown: '#9ca3af',
}

// parseVulnFinding mirrors internal/adapters/nuclei.go's encoding: URL is
// the matched URL, ContentType is the template's human-readable name, and
// Tags is [severity, templateId].
function parseVulnFinding(f: Finding) {
  const [severity, templateID] = f.tags ?? []
  return {
    key: `${f.sourceNodeId}:${f.id}`,
    url: f.url,
    name: f.contentType || templateID || 'unknown finding',
    templateID: templateID ?? '',
    severity: (severity || 'unknown').toLowerCase(),
  }
}

export function VulnTable({ findings }: { findings: Finding[] }) {
  const rows = findings
    .map(parseVulnFinding)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))

  return (
    <div className="flex-1 overflow-auto">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-neutral-950">
          <tr>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Severity</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Finding</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Template</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">URL</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className={`border-b border-neutral-900 hover:bg-neutral-900/60 ${r.severity === 'critical' || r.severity === 'high' ? 'bg-red-950/20' : ''}`}>
              <td className="px-3 py-1.5">
                <span
                  className="rounded border px-1.5 py-0.5 font-mono text-xs font-semibold uppercase"
                  style={{ color: SEVERITY_COLOR[r.severity], borderColor: SEVERITY_COLOR[r.severity] }}
                >
                  {r.severity}
                </span>
              </td>
              <td className="px-3 py-1.5 text-neutral-200">{r.name}</td>
              <td className="px-3 py-1.5 font-mono text-xs text-neutral-500">{r.templateID}</td>
              <td className="max-w-[420px] truncate px-3 py-1.5 font-mono text-xs text-neutral-400" title={r.url}>
                {r.url}
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={4} className="px-3 py-8 text-center text-neutral-600">
                No vulnerabilities flagged yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
