import { useMemo } from 'react'
import { useScanGraph, type GraphEdge, type GraphNode, type PageGroup } from './useScanGraph'
import { clusterOf, riskOf, type ClusterId, type EstateHost } from './estate'
import type { TechDetection } from './types'

// Rotated across clusters in risk order -- violet/sky/amber/steel/emerald/red,
// the six-color set the Estate Hierarchy design spec ties to cluster boxes
// and their apex→cluster link stroke.
const CLUSTER_COLORS = ['#a78bfa', '#38bdf8', '#fbbf24', '#5980a6', '#34d399', '#f87171']

// Preference order for picking a cluster's label out of its shared
// technology signature -- a CMS or framework name reads as "what this
// cluster is" far better than the web server underneath it. Values match
// internal/techfp/signatures.go's Category constants ("web-server",
// "js-framework", "cdn-proxy", ...), not the design mock's simplified
// server/framework/cdn names.
const CATEGORY_PRIORITY = ['cms', 'js-framework', 'language', 'web-server', 'cdn-proxy']

export interface EstateHostModel {
  hostname: string
  clusterId: ClusterId
  statusCode?: number
  pageCount: number
  technologies: TechDetection[]
  exposedFiles: number
  risk: number
}

export interface EstateCluster {
  id: ClusterId
  label: string
  color: string
  hosts: EstateHostModel[]
  pageCount: number
  exposedFiles: number
  techCount: number
}

export interface EstateModel {
  apex: { hostname: string; hostCount: number; pageCount: number; technologies: TechDetection[] }
  clusters: EstateCluster[]
}

// clusterLabel is the dominant CMS/framework shared by a cluster's hosts --
// the reason clusterOf grouped them in the first place -- or, for a
// prefix-fallback cluster (mail/infra hosts with no fingerprint), the
// prefix itself.
function clusterLabel(id: ClusterId, hosts: EstateHostModel[]): string {
  if (id.startsWith('prefix:')) return id.slice('prefix:'.length)
  const categoryOf = new Map<string, string>()
  for (const h of hosts) for (const t of h.technologies) categoryOf.set(t.name, t.category)
  for (const category of CATEGORY_PRIORITY) {
    const match = [...categoryOf.entries()].find(([, c]) => c === category)
    if (match) return match[0]
  }
  return [...categoryOf.keys()][0] ?? id
}

// buildEstateModel reshapes useScanGraph's node/edge graph into the Estate
// Hierarchy view's five tiers (apex → cluster → host → technology → page
// group). A plain function (not a hook) so GraphView can build it from the
// one useScanGraph subscription it already holds for the retained `graph`
// mode, instead of HierarchyView opening a second, redundant socket to the
// same scan.
export function buildEstateModel(nodes: GraphNode[], edges: GraphEdge[], rootLabel: string): EstateModel {
  const nodeById = new Map(nodes.map((n) => [n.id, n]))

  const techByHost = new Map<string, TechDetection[]>()
  for (const n of nodes) {
    if (n.type !== 'technology' || !n.host) continue
    const list = techByHost.get(n.host) ?? []
    list.push({ name: n.label, category: n.category ?? 'web-server', cves: n.cves })
    techByHost.set(n.host, list)
  }

  // Page counts and exposed-file counts per host come from walking the
  // host→page edges rather than pageGroupsByHost, since that memo's rows
  // are capped at 9 and would undercount any host with more buckets than
  // that.
  const pageCountByHost = new Map<string, number>()
  const exposedFilesByHost = new Map<string, number>()
  for (const e of edges) {
    const targetId = typeof e.target === 'object' ? e.target.id : String(e.target)
    const target = nodeById.get(targetId)
    if (!target || target.type !== 'page') continue
    const sourceId = typeof e.source === 'object' ? e.source.id : String(e.source)
    const source = nodeById.get(sourceId)
    if (!source) continue
    pageCountByHost.set(source.label, (pageCountByHost.get(source.label) ?? 0) + 1)
    // Mirrors ScanView's "Critical files" rule (dangerous extension + 200)
    // so the two counts never disagree.
    if (target.dangerous && target.statusCode === 200) {
      exposedFilesByHost.set(source.label, (exposedFilesByHost.get(source.label) ?? 0) + 1)
    }
  }

  const byCluster = new Map<ClusterId, EstateHostModel[]>()
  for (const n of nodes) {
    if (n.type !== 'target') continue
    const technologies = techByHost.get(n.label) ?? []
    const exposedFiles = exposedFilesByHost.get(n.label) ?? 0
    const host: EstateHost = { hostname: n.label, technologies, exposedFiles }
    const model: EstateHostModel = {
      hostname: n.label,
      clusterId: clusterOf(host),
      statusCode: n.statusCode,
      pageCount: pageCountByHost.get(n.label) ?? 0,
      technologies,
      exposedFiles,
      risk: riskOf(host),
    }
    const list = byCluster.get(model.clusterId) ?? []
    list.push(model)
    byCluster.set(model.clusterId, list)
  }

  const built: EstateCluster[] = [...byCluster.entries()].map(([id, hosts]) => {
    hosts.sort((a, b) => b.risk - a.risk || a.hostname.localeCompare(b.hostname))
    const techNames = new Set<string>()
    let pageCount = 0
    let exposedFiles = 0
    for (const h of hosts) {
      for (const t of h.technologies) techNames.add(t.name)
      pageCount += h.pageCount
      exposedFiles += h.exposedFiles
    }
    return { id, label: clusterLabel(id, hosts), color: '', hosts, pageCount, exposedFiles, techCount: techNames.size }
  })

  // Riskiest clusters first (summed host risk), so the tier rail reads
  // top-to-bottom as "worry about this first."
  built.sort((a, b) => {
    const riskA = a.hosts.reduce((s, h) => s + h.risk, 0)
    const riskB = b.hosts.reduce((s, h) => s + h.risk, 0)
    return riskB - riskA || b.hosts.length - a.hosts.length || a.label.localeCompare(b.label)
  })
  built.forEach((c, i) => {
    c.color = CLUSTER_COLORS[i % CLUSTER_COLORS.length]
  })

  const clusterPages = built.reduce((s, c) => s + c.pageCount, 0)
  const apexPageCount = (pageCountByHost.get(rootLabel) ?? 0) + clusterPages
  const apexHostCount = built.reduce((s, c) => s + c.hosts.length, 0)

  return {
    clusters: built,
    apex: { hostname: rootLabel, hostCount: apexHostCount, pageCount: apexPageCount, technologies: techByHost.get(rootLabel) ?? [] },
  }
}

// useEstateModel is the standalone convenience form of buildEstateModel --
// opens its own useScanGraph subscription and memoizes the tiers on top of
// it. GraphView doesn't use this (it shares one useScanGraph call across
// both its modes via buildEstateModel directly); kept for any future
// consumer that wants the hierarchy model on its own.
export function useEstateModel(caseId: string, caseLabel: string): EstateModel & { pageGroupsByHost: Map<string, PageGroup[]>; progress: { done: number; total: number } | null } {
  const { nodes, edges, progress, pageGroupsByHost } = useScanGraph(caseId, caseLabel)
  const model = useMemo(() => buildEstateModel(nodes, edges, caseLabel), [nodes, edges, caseLabel])
  return { ...model, pageGroupsByHost, progress }
}
