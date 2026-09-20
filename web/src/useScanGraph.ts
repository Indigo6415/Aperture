import { useEffect, useMemo, useRef, useState } from 'react'
import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force'
import { api, watchJob } from './api'
import type { Check, CVE, Finding, Job, RunStatus, TechDetection } from './types'
import { hostnameOf, extensionOf } from './url'
import { isDangerousExtension } from './extensions'

export type GraphNodeType = 'case' | 'target' | 'page' | 'technology'

export interface GraphNode extends SimulationNodeDatum {
  id: string
  type: GraphNodeType
  label: string
  statusCode?: number
  extension?: string
  dangerous?: boolean
  // Set only on 'technology' nodes -- category/cves back the Estate
  // Hierarchy view's technology panel, and host lets it (and any future
  // consumer) find the owning host without walking edges.
  host?: string
  category?: string
  cves?: CVE[]
  // Set only on 'target' nodes once an 'asn' check completes for that
  // host (see internal/recon/asn.go) -- the hosting network Team Cymru's
  // DNS-based lookup resolved, backing the Estate Hierarchy view's
  // network/ASN clustering mode (see estate.ts's clusterOfNetwork).
  asn?: string
  asnOrg?: string
}

export type GraphEdge = SimulationLinkDatum<GraphNode> & { id: string }

// PageGroup is one bucketed row of the Estate Hierarchy view's page-group
// panel: either a path pattern (e.g. "/wp-content/*") with how many pages
// matched it, or -- for dangerous?:true rows -- one specific exposed file,
// kept unmerged so it renders in the warning treatment instead of vanishing
// into a bucket.
export interface PageGroup {
  key: string
  label: string
  count: number
  statusCode: number
  dangerous: boolean
}

const MAX_PAGE_GROUPS = 9

const caseNodeId = (caseId: string) => `case:${caseId}`
const targetNodeId = (caseId: string, value: string) => `target:${caseId}:${value}`
const techNodeId = (caseId: string, value: string, techName: string) => `tech:${caseId}:${value}:${techName}`

// pathPatternOf collapses a URL path down to its first segment, the same
// granularity a directory-bruteforce result is actually shaped by (e.g.
// every "/wp-content/uploads/2024/03/x.jpg" hit is one WordPress uploads
// tree, not 40 distinct pages worth a row each).
function pathPatternOf(pathname: string): string {
  const segments = pathname.split('/').filter(Boolean)
  if (segments.length === 0) return '/ (root)'
  if (segments.length === 1) return '/' + segments[0]
  return '/' + segments[0] + '/*'
}

// bucketPageGroups turns one target's raw feroxbuster findings into the
// page-group panel's rows: dangerous-extension 200 hits stay one row each
// (never merged into a pattern bucket, since each is individually worth
// looking at), everything else buckets by pathPatternOf. Capped at
// MAX_PAGE_GROUPS total, largest first -- see estate hierarchy README's
// "Layout" section for why (3,000 pages on one host would otherwise blow
// the panel out).
function bucketPageGroups(findings: Finding[]): PageGroup[] {
  const dangerous: PageGroup[] = []
  const patterns = new Map<string, { count: number; statusCodes: Map<number, number> }>()

  for (const f of findings) {
    let pathname = '/'
    try {
      pathname = new URL(f.url).pathname
    } catch {
      // fall back to '/' -- an unparseable URL still needs a bucket
    }
    if (f.statusCode === 200 && isDangerousExtension(extensionOf(f.url))) {
      dangerous.push({ key: `d:${f.url}`, label: pathname, count: 1, statusCode: 200, dangerous: true })
      continue
    }
    const pattern = pathPatternOf(pathname)
    const entry = patterns.get(pattern) ?? { count: 0, statusCodes: new Map<number, number>() }
    entry.count++
    entry.statusCodes.set(f.statusCode, (entry.statusCodes.get(f.statusCode) ?? 0) + 1)
    patterns.set(pattern, entry)
  }

  const patternRows: PageGroup[] = [...patterns.entries()].map(([pattern, { count, statusCodes }]) => {
    // The row's status code is whichever one most of the bucket's findings
    // actually had -- a bucket is rarely 100% one status, but this is the
    // one number the row has room to show.
    let statusCode = 200
    let bestCount = -1
    for (const [code, n] of statusCodes) {
      if (n > bestCount) {
        bestCount = n
        statusCode = code
      }
    }
    return { key: `p:${pattern}`, label: pattern, count, statusCode, dangerous: false }
  })

  // Dangerous rows are guaranteed a slot (up to the cap itself) since
  // they're the reason this panel has a warning treatment at all; pattern
  // buckets fill whatever room is left, largest first.
  const dangerousRows = dangerous.slice(0, MAX_PAGE_GROUPS)
  const topPatterns = patternRows.sort((a, b) => b.count - a.count).slice(0, MAX_PAGE_GROUPS - dangerousRows.length)
  return [...dangerousRows, ...topPatterns].sort((a, b) => b.count - a.count)
}

// POLL_MS is how often this hook re-fetches the case's target list --
// there's no live "target added" websocket event (promotion is a plain
// REST call), so a light poll is simpler than plumbing a bespoke one.
const POLL_MS = 4000

// useScanGraph builds a live node/edge graph for exactly one case -- one
// case node at the root, one target node per case Target, a technology node
// per fingerprinted technology an identify job found on a target, and a
// page node per feroxbuster finding under a target. Shared by the full-page
// GraphView and the small preview embedded in a case's Overview area, so
// both stay in sync with exactly one implementation of "what does this
// case's graph look like."
export function useScanGraph(
  caseId: string,
  caseLabel: string,
): {
  nodes: GraphNode[]
  edges: GraphEdge[]
  progress: { done: number; total: number } | null
  pageGroupsByHost: Map<string, PageGroup[]>
} {
  const nodesRef = useRef(new Map<string, GraphNode>())
  const edgesRef = useRef(new Map<string, GraphEdge>())
  // Raw feroxbuster findings per target, kept alongside nodesRef purely to
  // feed bucketPageGroups above -- the page GraphNodes themselves don't
  // carry enough (no hostname, no raw path) to re-bucket from.
  const findingsRef = useRef(new Map<string, Finding[]>())
  const stopFns = useRef(new Map<string, () => void>())
  // Progress/status per job, tracked alongside nodes/edges above so the
  // overall "how's this case doing" bar (CaseView's header, GraphView's
  // toolbar) can reuse the same watchJob sockets already open here instead
  // of opening a second set just to hear progress events.
  const jobStatusRef = useRef(new Map<string, RunStatus>())
  const jobProgressRef = useRef(new Map<string, { done: number; total: number }>())
  const bumpScheduled = useRef(false)
  const [version, setVersion] = useState(0)

  const bump = () => {
    if (bumpScheduled.current) return
    bumpScheduled.current = true
    requestAnimationFrame(() => {
      bumpScheduled.current = false
      setVersion((v) => v + 1)
    })
  }

  useEffect(() => {
    if (!caseId) return
    let cancelled = false
    nodesRef.current = new Map()
    edgesRef.current = new Map()
    findingsRef.current = new Map()
    jobStatusRef.current = new Map()
    jobProgressRef.current = new Map()
    setVersion((v) => v + 1)

    const rootId = caseNodeId(caseId)
    const ensureTargetNode = (value: string): string => {
      const id = targetNodeId(caseId, value)
      if (!nodesRef.current.has(id)) {
        nodesRef.current.set(id, { id, type: 'target', label: value })
        const edgeId = `e:${rootId}->${id}`
        edgesRef.current.set(edgeId, { id: edgeId, source: rootId, target: id })
      }
      return id
    }

    const applyCheck = (check: Check) => {
      if (check.status !== 'done') return
      if (check.kind === 'http') {
        const nodeId = ensureTargetNode(check.domain)
        const node = nodesRef.current.get(nodeId)
        if (node) node.statusCode = check.data?.statusCode as number | undefined
        return
      }
      if (check.kind === 'asn') {
        const nodeId = ensureTargetNode(check.domain)
        const node = nodesRef.current.get(nodeId)
        if (node) {
          node.asn = check.data?.asn as string | undefined
          node.asnOrg = check.data?.org as string | undefined
        }
        return
      }
      if (check.kind === 'technologies') {
        const hostNodeId = ensureTargetNode(check.domain)
        const technologies = (check.data?.technologies as TechDetection[] | undefined) ?? []
        for (const t of technologies) {
          const id = techNodeId(caseId, check.domain, t.name)
          nodesRef.current.set(id, { id, type: 'technology', label: t.name, host: check.domain, category: t.category, cves: t.cves })
          const edgeId = `e:${hostNodeId}->${id}`
          edgesRef.current.set(edgeId, { id: edgeId, source: hostNodeId, target: id })
        }
        return
      }
      if (check.kind !== 'subdomains-verified') return
      const hostnames = (check.data?.subdomains as string[] | undefined) ?? []
      for (const h of hostnames) ensureTargetNode(h)
    }

    const applyFinding = (f: Finding) => {
      const hostname = hostnameOf(f.url)
      if (!hostname) return
      const hostNodeId = ensureTargetNode(hostname)

      // Keyed by URL (not finding.id, which is a fresh random id every time
      // a finding is emitted) so re-discovering the same page across a
      // second job against the same target updates one node instead of
      // piling up a duplicate for every observation.
      const pageId = `page:${caseId}:${f.url}`
      if (nodesRef.current.has(pageId)) return
      let label = f.url
      try {
        const u = new URL(f.url)
        label = u.pathname + u.search || '/'
      } catch {
        // fall back to the raw URL above
      }
      const extension = extensionOf(f.url)
      nodesRef.current.set(pageId, { id: pageId, type: 'page', label, statusCode: f.statusCode, extension, dangerous: isDangerousExtension(extension) })
      const edgeId = `e:${hostNodeId}->${pageId}`
      edgesRef.current.set(edgeId, { id: edgeId, source: hostNodeId, target: pageId })

      const list = findingsRef.current.get(hostname) ?? []
      list.push(f)
      findingsRef.current.set(hostname, list)
    }

    // watchTheJob mirrors CaseView's own per-job wiring, but only cares
    // about feroxbuster jobs' findings (page nodes) and every job's
    // status/progress (for the overall bar) -- identify jobs' checks stream
    // separately below.
    const watchTheJob = (job: Job) => {
      const key = `job:${job.id}`
      if (stopFns.current.has(key)) return
      jobStatusRef.current.set(job.id, job.status)
      if (job.tool === 'feroxbuster' && job.runId) {
        api.listFindings(job.runId).then((findings) => {
          if (cancelled) return
          for (const f of findings) applyFinding(f)
          bump()
        })
      }
      stopFns.current.set(
        key,
        watchJob(job.id, (ev) => {
          if (ev.type === 'finding' && ev.finding && job.tool === 'feroxbuster') {
            applyFinding(ev.finding)
            bump()
          } else if (ev.type === 'progress') {
            jobProgressRef.current.set(job.id, { done: ev.done ?? 0, total: ev.total ?? 0 })
            bump()
          } else if (ev.type === 'check' && ev.check) {
            applyCheck(ev.check)
            bump()
          } else if (ev.type === 'done') {
            jobStatusRef.current.set(job.id, ev.status === 'failed' ? 'failed' : ev.status === 'cancelled' ? 'cancelled' : 'succeeded')
            bump()
          }
        }),
      )
    }

    nodesRef.current.set(rootId, { id: rootId, type: 'case', label: caseLabel || caseId })
    bump()

    const refreshTargetsAndChecks = () => {
      api.listTargets(caseId).then((targets) => {
        if (cancelled) return
        for (const t of targets) ensureTargetNode(t.value)
        bump()
      })
      api.listCaseChecks(caseId).then((checks) => {
        if (cancelled) return
        for (const c of checks) applyCheck(c)
        bump()
      })
    }
    refreshTargetsAndChecks()
    const pollTimer = setInterval(refreshTargetsAndChecks, POLL_MS)

    const refreshJobs = () => {
      api.listJobs(caseId).then((jobs) => {
        if (cancelled) return
        for (const j of jobs) watchTheJob(j)
      })
    }
    refreshJobs()
    const jobPollTimer = setInterval(refreshJobs, POLL_MS)

    return () => {
      cancelled = true
      clearInterval(pollTimer)
      clearInterval(jobPollTimer)
      // stopFns is a plain mutable ref (not a DOM/component ref), so
      // reading .current here in cleanup is safe -- it holds whatever
      // watchJob subscriptions this same effect instance opened.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      for (const stop of stopFns.current.values()) stop()
      // eslint-disable-next-line react-hooks/exhaustive-deps
      stopFns.current.clear()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, caseLabel])

  // version is a plain counter bumped whenever nodesRef/edgesRef (mutable
  // refs, not state) change -- it's the trigger to re-derive these arrays,
  // not a value either memo reads directly.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const nodes = useMemo(() => Array.from(nodesRef.current.values()), [version])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const edges = useMemo(() => Array.from(edgesRef.current.values()), [version])

  // progress sums done/total across every job still marked "running" --
  // null (not just zero) once nothing is running, so callers can tell
  // "finished" apart from "0 of 0 so far." Any contributing job with an
  // unknowable total (total === 0, e.g. feroxbuster) makes the whole
  // aggregate indeterminate rather than reporting a misleadingly small
  // total.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const progress = useMemo(() => {
    const runningIds = [...jobStatusRef.current.entries()].filter(([, s]) => s === 'running').map(([id]) => id)
    if (runningIds.length === 0) return null
    let done = 0
    let total = 0
    let indeterminate = false
    for (const id of runningIds) {
      const p = jobProgressRef.current.get(id)
      if (!p) {
        indeterminate = true
        continue
      }
      done += p.done
      if (p.total === 0) indeterminate = true
      else total += p.total
    }
    return { done, total: indeterminate ? 0 : total }
  }, [version])

  // pageGroupsByHost re-buckets every target's findingsRef entry whenever
  // the graph changes -- see bucketPageGroups above. Cheap enough to
  // recompute wholesale on each bump rather than tracking per-target
  // dirtiness.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const pageGroupsByHost = useMemo(() => {
    const result = new Map<string, PageGroup[]>()
    for (const [hostname, findings] of findingsRef.current) result.set(hostname, bucketPageGroups(findings))
    return result
  }, [version])

  return { nodes, edges, progress, pageGroupsByHost }
}
