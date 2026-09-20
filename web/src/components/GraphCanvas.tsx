import { useEffect, useRef, useState } from 'react'
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type ForceLink, type Simulation } from 'd3-force'
import type { GraphEdge, GraphNode, GraphNodeType } from '../useScanGraph'
import { statusHexColor } from '../statusColor'
import { api, screenshotPreviewEnabled } from '../api'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToJwtScanner } from '../jwtHandoff'
import { sendToProbe } from '../probeHandoff'
import { sendToSecretScan } from '../secretScanHandoff'
import { sendToRepeater } from '../repeaterHandoff'

// Interactive controls (pan/zoom/drag) can be turned off for the small
// read-only preview embedded in a scan's Overview tab -- it just needs to
// render the current layout and forward clicks to whatever the caller
// wants a click on the graph to do (open the full GraphView).
export interface GraphCanvasProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
  interactive?: boolean
  // caseId enables the hover screenshot tooltip on case/target nodes
  // (see ScreenshotTooltip below) -- omitted entirely by the read-only
  // Overview preview, which is too small for a tooltip to be worth it.
  caseId?: string
}

type Drag = { mode: 'pan'; startClientX: number; startClientY: number; origX: number; origY: number } | { mode: 'node'; node: GraphNode }

// GraphCanvas is a pure renderer: given an already-filtered node/edge set,
// it runs a d3-force simulation for layout and draws plain SVG -- no
// graph-visualization framework, since a force simulation + a handful of
// circles/lines/text is the entire feature. Panning/zooming/node-dragging
// are hand-rolled pointer-event handling rather than a library, since they
// only take a few dozen lines.
export function GraphCanvas({ nodes, edges, interactive = true, caseId }: GraphCanvasProps) {
  const { openMenu } = useContextMenu()
  const containerRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const simRef = useRef<Simulation<GraphNode, GraphEdge> | null>(null)
  const dragRef = useRef<Drag | null>(null)

  const [size, setSize] = useState({ width: 0, height: 0 })
  const [, setTick] = useState(0)
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 })
  // hovered backs the screenshot tooltip: which node the pointer is over
  // and where to float the preview -- host/website nodes only (a page
  // doesn't get its own screenshot, see api.captureScreenshot).
  const [hovered, setHovered] = useState<{ node: GraphNode; x: number; y: number } | null>(null)

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => setSize({ width: entry.contentRect.width, height: entry.contentRect.height }))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Created once: the simulation's node/link data and the center force's
  // target are updated in the effects below instead of recreating it, so
  // existing nodes keep their x/y instead of jumping every update.
  useEffect(() => {
    const sim = forceSimulation<GraphNode>()
      .force(
        'link',
        forceLink<GraphNode, GraphEdge>([])
          .id((d) => d.id)
          .distance(70)
          .strength(0.5),
      )
      .force('charge', forceManyBody().strength(-180))
      .force('center', forceCenter(0, 0))
      .force('collide', forceCollide(22))
      .on('tick', () => setTick((t) => t + 1))
    simRef.current = sim
    return () => {
      sim.stop()
    }
  }, [])

  useEffect(() => {
    simRef.current?.force('center', forceCenter(size.width / 2, size.height / 2))
  }, [size.width, size.height])

  useEffect(() => {
    const sim = simRef.current
    if (!sim) return
    sim.nodes(nodes)
    const linkForce = sim.force('link') as ForceLink<GraphNode, GraphEdge>
    linkForce.links(edges)
    sim.alpha(0.4).restart()
  }, [nodes, edges])

  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      const drag = dragRef.current
      if (!drag) return
      if (drag.mode === 'pan') {
        setTransform((t) => ({ ...t, x: drag.origX + (e.clientX - drag.startClientX), y: drag.origY + (e.clientY - drag.startClientY) }))
        return
      }
      const rect = svgRef.current?.getBoundingClientRect()
      if (!rect) return
      setTransform((t) => {
        drag.node.fx = (e.clientX - rect.left - t.x) / t.k
        drag.node.fy = (e.clientY - rect.top - t.y) / t.k
        return t
      })
      simRef.current?.alpha(0.3).restart()
    }
    const onUp = () => {
      const drag = dragRef.current
      if (drag?.mode === 'node') {
        drag.node.fx = undefined
        drag.node.fy = undefined
        simRef.current?.alpha(0.3).restart()
      }
      dragRef.current = null
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
    return () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
    }
  }, [])

  const startPan = (e: React.PointerEvent) => {
    if (!interactive) return
    dragRef.current = { mode: 'pan', startClientX: e.clientX, startClientY: e.clientY, origX: transform.x, origY: transform.y }
  }
  const startNodeDrag = (e: React.PointerEvent, node: GraphNode) => {
    if (!interactive) return
    e.stopPropagation()
    dragRef.current = { mode: 'node', node }
  }
  const onWheel = (e: React.WheelEvent) => {
    if (!interactive) return
    e.preventDefault()
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect) return
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    setTransform((t) => {
      const nextK = Math.min(4, Math.max(0.15, t.k * (1 - e.deltaY * 0.001)))
      return { k: nextK, x: mx - ((mx - t.x) / t.k) * nextK, y: my - ((my - t.y) / t.k) * nextK }
    })
  }

  return (
    <div ref={containerRef} className="h-full w-full overflow-hidden bg-neutral-950">
      <svg
        ref={svgRef}
        width={size.width}
        height={size.height}
        onPointerDown={startPan}
        onWheel={onWheel}
        className={interactive ? 'cursor-grab touch-none active:cursor-grabbing' : 'pointer-events-none'}
      >
        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
          {edges.map((e) => {
            const source = typeof e.source === 'object' ? e.source : undefined
            const target = typeof e.target === 'object' ? e.target : undefined
            if (!source || !target) return null
            return <line key={e.id} x1={source.x ?? 0} y1={source.y ?? 0} x2={target.x ?? 0} y2={target.y ?? 0} stroke="#3f3f46" strokeWidth={1} />
          })}
          {nodes.map((n) => (
            <g
              key={n.id}
              onPointerDown={(e) => startNodeDrag(e, n)}
              onPointerEnter={(e) => caseId && n.type !== 'page' && setHovered({ node: n, x: e.clientX, y: e.clientY })}
              onPointerLeave={() => setHovered(null)}
              onContextMenu={(e) => {
                if (n.type !== 'target') return
                e.stopPropagation()
                openMenu(e, [
                  { label: 'Copy value', onSelect: () => copyToClipboard(n.label, 'Copied target') },
                  { label: 'Send to JWT Scanner', onSelect: () => sendToJwtScanner(n.label) },
                  { label: 'Send to Probe', onSelect: () => sendToProbe(n.label) },
                  { label: 'Send to Secret Scanner', onSelect: () => sendToSecretScan(n.label) },
                  { label: 'Send to Repeater', onSelect: () => sendToRepeater(n.label) },
                ])
              }}
              className={interactive ? 'cursor-pointer' : undefined}
            >
              <circle
                cx={n.x ?? 0}
                cy={n.y ?? 0}
                r={radiusFor(n.type)}
                fill={colorFor(n)}
                stroke={n.dangerous ? '#ef4444' : '#0a0a0a'}
                strokeWidth={n.dangerous ? 2.5 : 1.5}
              >
                <title>{n.dangerous ? `⚠ ${n.label} (.${n.extension})` : n.label}</title>
              </circle>
              {n.type !== 'page' && (
                <text x={(n.x ?? 0) + radiusFor(n.type) + 4} y={(n.y ?? 0) + 4} className="pointer-events-none select-none fill-neutral-400 text-[10px]">
                  {n.label}
                </text>
              )}
            </g>
          ))}
        </g>
      </svg>
      {hovered && caseId && screenshotPreviewEnabled && (
        <ScreenshotTooltip key={hovered.node.label} caseId={caseId} target={hovered.node.label} x={hovered.x} y={hovered.y} />
      )}
    </div>
  )
}

// ScreenshotTooltip floats a small preview of a host's captured screenshot
// next to the pointer. A host with no screenshot yet (still capturing, or
// no headless-Chrome-compatible browser installed -- see
// adapters.CaptureScreenshot) just renders nothing once the <img> 404s,
// rather than an ugly broken-image icon.
// Keyed by hostname at the call site so switching which node is hovered
// remounts this (resetting `failed`) instead of needing an effect to do it.
function ScreenshotTooltip({ caseId, target, x, y }: { caseId: string; target: string; x: number; y: number }) {
  const [failed, setFailed] = useState(false)
  if (failed) return null
  return (
    <div
      className="pointer-events-none fixed z-50 rounded border border-neutral-700 bg-neutral-900 p-1 shadow-xl"
      style={{ left: x + 14, top: y + 14 }}
    >
      <img
        src={api.screenshotUrl(caseId, target)}
        onError={() => setFailed(true)}
        className="h-24 w-40 rounded-sm object-cover object-top"
        alt={target}
      />
      <div className="mt-0.5 max-w-[10rem] truncate text-center text-[10px] text-neutral-400">{target}</div>
    </div>
  )
}

function radiusFor(type: GraphNodeType): number {
  if (type === 'case') return 14
  if (type === 'target') return 9
  if (type === 'technology') return 6
  return 5
}

function colorFor(n: GraphNode): string {
  if (n.type === 'page') return n.statusCode ? statusHexColor(n.statusCode) : '#71717a'
  if (n.type === 'case') return '#38bdf8'
  if (n.type === 'technology') return '#fbbf24'
  return '#a78bfa'
}
