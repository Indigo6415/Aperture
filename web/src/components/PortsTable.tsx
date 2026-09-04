import type { Finding } from '../types'

// PortsTable renders nmap's results. Port scanning has no natural fit in
// the Finding shape ResultsTable is built for (status/size/words/lines are
// all meaningless for a port) -- see internal/adapters/nmap.go's doc
// comment for how a port ends up encoded as a Finding: URL is a
// "<proto>://<host>:<port>/" pseudo-URL, ContentType carries the detected
// service name, and Tags is [state, proto].
function parsePortFinding(f: Finding) {
  let host = ''
  let port = ''
  try {
    const u = new URL(f.url)
    host = u.hostname
    port = u.port
  } catch {
    // leave host/port blank -- rendered as an empty cell below
  }
  const [state, proto] = f.tags ?? []
  return { key: `${f.sourceNodeId}:${f.id}`, host, port, proto: proto ?? '', state: state ?? 'open', service: f.contentType ?? 'unknown' }
}

export function PortsTable({ findings }: { findings: Finding[] }) {
  const rows = findings.map(parsePortFinding).sort((a, b) => Number(a.port) - Number(b.port))

  return (
    <div className="flex-1 overflow-auto">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-neutral-950">
          <tr>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Port</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Protocol</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Service</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">State</th>
            <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Host</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className="border-b border-neutral-900 hover:bg-neutral-900/60">
              <td className="px-3 py-1.5 font-mono text-neutral-200">{r.port}</td>
              <td className="px-3 py-1.5 text-neutral-400">{r.proto}</td>
              <td className="px-3 py-1.5 font-mono text-sky-400">{r.service}</td>
              <td className="px-3 py-1.5 text-emerald-400">{r.state}</td>
              <td className="px-3 py-1.5 font-mono text-neutral-500">{r.host}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={5} className="px-3 py-8 text-center text-neutral-600">
                No open ports found yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
