import { useEffect, useMemo, useRef, useState } from 'react'
import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force'
import { api, watchRun, watchScan } from './api'
import type { Check, Finding, RunStatus, ScanKind } from './types'
import { hostnameOf, extensionOf } from './url'
import { isDangerousExtension } from './extensions'

export type GraphNodeType = 'website' | 'subdomain' | 'page'

export interface GraphNode extends SimulationNodeDatum {
  id: string
  type: GraphNodeType
  label: string
  statusCode?: number
  extension?: string
  dangerous?: boolean
}

export type GraphEdge = SimulationLinkDatum<GraphNode> & { id: string }

const websiteId = (scanId: string) => `scan:${scanId}`
const hostId = (scanId: string, hostname: string) => `host:${scanId}:${hostname}`

// useScanGraph builds a live node/edge graph for exactly one scan --
// one website node for the apex domain, one subdomain node per hostname
// discovered (passively via crt.sh or actively via bruteforce), and one
// page node per content-discovery finding -- staying live via the same
// watchScan/watchRun WebSockets ScanView itself uses. Shared by the
// full-page GraphView and the small preview embedded in a scan's
// Overview tab, so both stay in sync with exactly one implementation of
// "what does this scan's graph look like."
export function useScanGraph(
  scanId: string,
  domain: string,
): { nodes: GraphNode[]; edges: GraphEdge[]; progress: { done: number; total: number } | null } {
  const nodesRef = useRef(new Map<string, GraphNode>())
  const edgesRef = useRef(new Map<string, GraphEdge>())
  const stopFns = useRef(new Map<string, () => void>())
  // Progress/status per run, tracked alongside nodes/edges above so the
  // overall "how's this scan doing" bar (ScanView's header, GraphView's
  // toolbar) can reuse the same watchRun sockets already open here instead
  // of opening a second set just to hear progress events.
  const runStatusRef = useRef(new Map<string, RunStatus>())
  const runProgressRef = useRef(new Map<string, { done: number; total: number }>())
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
    if (!scanId || !domain) return
    nodesRef.current = new Map()
    edgesRef.current = new Map()
    runStatusRef.current = new Map()
    runProgressRef.current = new Map()
    setVersion((v) => v + 1)

    const ensureSubdomainNode = (hostname: string): string => {
      const id = hostId(scanId, hostname)
      if (!nodesRef.current.has(id)) {
        nodesRef.current.set(id, { id, type: 'subdomain', label: hostname })
        const edgeId = `e:${websiteId(scanId)}->${id}`
        edgesRef.current.set(edgeId, { id: edgeId, source: websiteId(scanId), target: id })
      }
      return id
    }

    const applyCheck = (check: Check) => {
      if (check.kind !== 'subdomains' || check.status !== 'done') return
      const hostnames = (check.data?.subdomains as string[] | undefined) ?? []
      for (const h of hostnames) ensureSubdomainNode(h)
    }

    const applyFinding = (kind: ScanKind, f: Finding) => {
      const hostname = hostnameOf(f.url)
      if (!hostname) return
      const hostNodeId = hostname === domain ? websiteId(scanId) : ensureSubdomainNode(hostname)
      if (kind !== 'content-discovery') return

      // Keyed by URL (not finding.id, which is a fresh random id every time
      // a finding is emitted) so re-discovering the same page across a
      // restart or an additional "scan selected" run updates one node
      // instead of piling up a duplicate for every observation.
      const pageId = `page:${scanId}:${f.url}`
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
    }

    const startWatchingRun = (kind: ScanKind, runId: string) => {
      const key = `run:${runId}`
      if (stopFns.current.has(key)) return
      runStatusRef.current.set(runId, 'running')
      api.listFindings(runId).then((findings) => {
        for (const f of findings) applyFinding(kind, f)
        bump()
      })
      api.getRun(runId).then((r) => {
        runStatusRef.current.set(runId, r.status)
        bump()
      })
      stopFns.current.set(
        key,
        watchRun(runId, (ev) => {
          if (ev.type === 'finding' && ev.finding) {
            applyFinding(kind, ev.finding)
            bump()
          } else if (ev.type === 'progress') {
            runProgressRef.current.set(runId, { done: ev.done ?? 0, total: ev.total ?? 0 })
            bump()
          } else if (ev.type === 'done') {
            runStatusRef.current.set(runId, ev.status === 'failed' ? 'failed' : ev.status === 'cancelled' ? 'cancelled' : 'succeeded')
            bump()
          }
        }),
      )
    }

    nodesRef.current.set(websiteId(scanId), { id: websiteId(scanId), type: 'website', label: domain })
    bump()

    api.getScan(scanId).then((full) => {
      for (const c of full.checks ?? []) applyCheck(c)
      bump()
    })
    api.listScanRuns(scanId).then((runs) => {
      for (const r of runs) startWatchingRun(r.kind, r.runId)
    })

    stopFns.current.set(
      `scan:${scanId}`,
      watchScan(scanId, (ev) => {
        if (ev.type === 'check' && ev.check) {
          applyCheck(ev.check)
          bump()
        } else if (ev.type === 'scanRun' && ev.kind && ev.runId) {
          startWatchingRun(ev.kind, ev.runId)
        }
      }),
    )

    return () => {
      // stopFns is a plain mutable ref (not a DOM/component ref), so
      // reading .current here in cleanup is safe -- it holds whatever
      // watchScan/watchRun subscriptions this same effect instance opened.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      for (const stop of stopFns.current.values()) stop()
      // eslint-disable-next-line react-hooks/exhaustive-deps
      stopFns.current.clear()
    }
  }, [scanId, domain])

  // version is a plain counter bumped whenever nodesRef/edgesRef (mutable
  // refs, not state) change -- it's the trigger to re-derive these arrays,
  // not a value either memo reads directly.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const nodes = useMemo(() => Array.from(nodesRef.current.values()), [version])
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const edges = useMemo(() => Array.from(edgesRef.current.values()), [version])

  // progress sums done/total across every run still marked "running" --
  // null (not just zero) once nothing is running, so callers can tell
  // "finished" apart from "0 of 0 so far." Same indeterminate rule as
  // ScanView's per-kind aggregation: any contributing run with an unknowable
  // total (total === 0, e.g. feroxbuster) makes the whole aggregate
  // indeterminate rather than reporting a misleadingly small total.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const progress = useMemo(() => {
    const runningIds = [...runStatusRef.current.entries()].filter(([, s]) => s === 'running').map(([id]) => id)
    if (runningIds.length === 0) return null
    let done = 0
    let total = 0
    let indeterminate = false
    for (const id of runningIds) {
      const p = runProgressRef.current.get(id)
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

  return { nodes, edges, progress }
}
