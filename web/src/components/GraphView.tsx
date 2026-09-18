import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { useScanGraph, type GraphNode, type GraphNodeType } from '../useScanGraph'
import { buildEstateModel } from '../useEstateModel'
import { statusHexColor } from '../statusColor'
import { isDangerousExtension } from '../extensions'
import { FacetFilterBar, type FacetDimension } from './FacetFilterBar'
import { GraphCanvas } from './GraphCanvas'
import { HierarchyView } from './HierarchyView'
import { ProgressBar } from './ProgressBar'

// See ResultsTable's NO_EXTENSION comment: "no extension" is a real,
// common, filterable category for page nodes, not a value that should
// always pass through the extension filter.
const NO_EXTENSION = '(none)'

const PAGE_DIMENSIONS: FacetDimension<GraphNode>[] = [
  { key: 'statusCode', label: 'Status', getValue: (n) => n.statusCode, colorFor: (v) => statusHexColor(Number(v)) },
  { key: 'extension', label: 'Extension', getValue: (n) => n.extension ?? NO_EXTENSION, warningFor: (v) => isDangerousExtension(String(v)) },
]

const TYPE_LABELS: Record<GraphNodeType, string> = { case: 'Case', target: 'Targets', page: 'Pages', technology: 'Technologies' }

type Mode = 'hierarchy' | 'graph'

// GraphView is one case's node/edge graph -- one case node at the root, one
// target node per case Target, and one page node per feroxbuster finding.
// Scoped to a single caseId (rather than every case in the app) so it reads
// as "this case's map," matching the way the rest of the app (CaseView, its
// tabs) is scoped per case.
//
// Two modes share the one useScanGraph subscription opened below: the
// default `hierarchy` tier view (HierarchyView, see
// design_handoff_estate_hierarchy/README.md) and the original force-graph
// `graph` mode (GraphCanvas) kept around for anyone who prefers the
// free-form map. Neither mode opens a socket of its own.
export function GraphView({ caseId }: { caseId: string }) {
  const [caseName, setCaseName] = useState('')
  const [mode, setMode] = useState<Mode>('hierarchy')

  useEffect(() => {
    let cancelled = false
    api.getCase(caseId).then((c) => {
      if (!cancelled) setCaseName(c.name)
    })
    return () => {
      cancelled = true
    }
  }, [caseId])

  const { nodes: allNodes, edges: allEdges, progress, pageGroupsByHost } = useScanGraph(caseId, caseName)
  const estateModel = useMemo(() => buildEstateModel(allNodes, allEdges, caseName), [allNodes, allEdges, caseName])

  const [typeVisible, setTypeVisible] = useState<Record<GraphNodeType, boolean>>({ case: true, target: true, page: true, technology: true })
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
      <div className="flex items-center gap-2 border-b border-neutral-800 bg-neutral-950 px-3 py-1.5">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">View</span>
        <div className="flex gap-1">
          {(['hierarchy', 'graph'] as Mode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`rounded border px-2 py-0.5 text-xs capitalize transition-colors ${
                mode === m ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-transparent text-neutral-400 hover:border-neutral-500'
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {mode === 'hierarchy' ? (
        <div className="flex-1 overflow-hidden">
          {caseName && (
            <HierarchyView
              caseId={caseId}
              apex={estateModel.apex}
              clusters={estateModel.clusters}
              pageGroupsByHost={pageGroupsByHost}
              progress={progress}
            />
          )}
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-start gap-x-6 gap-y-2 border-b border-neutral-800 px-3 py-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Show</span>
              <div className="flex gap-1">
                {(['case', 'target', 'page', 'technology'] as GraphNodeType[]).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeVisible((prev) => ({ ...prev, [t]: !prev[t] }))}
                    className={`rounded border px-1.5 py-0.5 text-xs transition-colors ${
                      typeVisible[t] ? 'border-neutral-600 bg-neutral-800 text-neutral-100' : 'border-neutral-800 bg-transparent text-neutral-600 line-through'
                    }`}
                  >
                    {TYPE_LABELS[t]}
                  </button>
                ))}
              </div>
            </div>

            <FacetFilterBar items={pageNodes} dimensions={PAGE_DIMENSIONS} onChange={setKeptPages} restrictStatusByDefault />

            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search target/path…"
              className="ml-auto w-56 rounded border border-neutral-700 bg-neutral-800 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
            />
            <span className="self-center text-xs text-neutral-500">
              {visibleNodes.length} of {allNodes.length} nodes
            </span>
            {progress && <ProgressBar done={progress.done} total={progress.total} />}
          </div>

          <div className="flex-1">
            {allNodes.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-neutral-600">Nothing found yet — add targets and run a job.</p>
            ) : (
              <GraphCanvas nodes={visibleNodes} edges={visibleEdges} caseId={caseId} />
            )}
          </div>
        </>
      )}
    </div>
  )
}
