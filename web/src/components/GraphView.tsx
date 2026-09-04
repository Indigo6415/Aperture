import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { useScanGraph, type GraphNode, type GraphNodeType } from '../useScanGraph'
import { statusHexColor } from '../statusColor'
import { isDangerousExtension } from '../extensions'
import { FacetFilterBar, type FacetDimension } from './FacetFilterBar'
import { GraphCanvas } from './GraphCanvas'
import { ProgressBar } from './ProgressBar'

// See ResultsTable's NO_EXTENSION comment: "no extension" is a real,
// common, filterable category for page nodes, not a value that should
// always pass through the extension filter.
const NO_EXTENSION = '(none)'

const PAGE_DIMENSIONS: FacetDimension<GraphNode>[] = [
  { key: 'statusCode', label: 'Status', getValue: (n) => n.statusCode, colorFor: (v) => statusHexColor(Number(v)) },
  { key: 'extension', label: 'Extension', getValue: (n) => n.extension ?? NO_EXTENSION, warningFor: (v) => isDangerousExtension(String(v)) },
]

// GraphView is one scan's node/edge graph -- one website node for the apex
// domain, one subdomain node per hostname discovered, and one page node per
// content-discovery finding. Scoped to a single scanId (rather than every
// scan in the app) so it reads as "this website's map," matching the way
// the rest of the app (ScanView, its tabs) is scoped per scan.
export function GraphView({ scanId }: { scanId: string }) {
  const [domain, setDomain] = useState('')

  useEffect(() => {
    let cancelled = false
    api.getScan(scanId).then((s) => {
      if (!cancelled) setDomain(s.domain)
    })
    return () => {
      cancelled = true
    }
  }, [scanId])

  const { nodes: allNodes, edges: allEdges, progress } = useScanGraph(scanId, domain)

  const [typeVisible, setTypeVisible] = useState<Record<GraphNodeType, boolean>>({ website: true, subdomain: true, page: true })
  const [search, setSearch] = useState('')
  const [keptPages, setKeptPages] = useState<GraphNode[]>([])

  const pageNodes = useMemo(() => allNodes.filter((n) => n.type === 'page'), [allNodes])
  const keptPageIds = useMemo(() => new Set(keptPages.map((n) => n.id)), [keptPages])
  const searchNeedle = search.trim().toLowerCase()

  const visibleNodes = useMemo(
    () =>
      allNodes.filter((n) => {
        if (!typeVisible[n.type]) return false
        if (n.type === 'page' && !keptPageIds.has(n.id)) return false
        if (searchNeedle && !n.label.toLowerCase().includes(searchNeedle)) return false
        return true
      }),
    [allNodes, typeVisible, keptPageIds, searchNeedle],
  )
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes])
  const visibleEdges = useMemo(
    () =>
      allEdges.filter((e) => {
        const sourceId = typeof e.source === 'object' ? e.source.id : e.source
        const targetId = typeof e.target === 'object' ? e.target.id : e.target
        return visibleIds.has(String(sourceId)) && visibleIds.has(String(targetId))
      }),
    [allEdges, visibleIds],
  )

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-start gap-x-6 gap-y-2 border-b border-neutral-800 px-3 py-2">
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Show</span>
          <div className="flex gap-1">
            {(['website', 'subdomain', 'page'] as GraphNodeType[]).map((t) => (
              <button
                key={t}
                onClick={() => setTypeVisible((prev) => ({ ...prev, [t]: !prev[t] }))}
                className={`rounded border px-1.5 py-0.5 text-xs capitalize transition-colors ${
                  typeVisible[t] ? 'border-neutral-600 bg-neutral-800 text-neutral-100' : 'border-neutral-800 bg-transparent text-neutral-600 line-through'
                }`}
              >
                {t}s
              </button>
            ))}
          </div>
        </div>

        <FacetFilterBar items={pageNodes} dimensions={PAGE_DIMENSIONS} onChange={setKeptPages} />

        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search hostname/path…"
          className="ml-auto w-56 rounded border border-neutral-700 bg-neutral-800 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
        />
        <span className="self-center text-xs text-neutral-500">
          {visibleNodes.length} of {allNodes.length} nodes
        </span>
        {progress && <ProgressBar done={progress.done} total={progress.total} />}
      </div>

      <div className="flex-1">
        {allNodes.length === 0 ? (
          <p className="px-3 py-6 text-center text-xs text-neutral-600">Nothing found yet — the scan is still running.</p>
        ) : (
          <GraphCanvas nodes={visibleNodes} edges={visibleEdges} scanId={scanId} />
        )}
      </div>
    </div>
  )
}
