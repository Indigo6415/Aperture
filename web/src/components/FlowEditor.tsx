import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Node,
  type NodeChange,
} from 'reactflow'
import { api, watchRun } from '../api'
import { ApertureNode, type ApertureNodeData } from './ApertureNode'
import { Inspector } from './Inspector'
import { Palette } from './Palette'
import { ResultsTable } from './ResultsTable'
import type { Finding, Flow, FlowNodeData, NodeKind, NodeStatus, Run } from '../types'

const nodeTypes = { aperture: ApertureNode }

function toRFNode(n: FlowNodeData): Node<ApertureNodeData> {
  return {
    id: n.id,
    type: 'aperture',
    position: n.position ?? { x: 0, y: 0 },
    data: { kind: n.kind, label: n.label, config: n.config ?? {}, status: 'pending', liveCount: 0 },
  }
}

let seq = 0
function newNodeId(kind: NodeKind) {
  seq += 1
  return `${kind}-${Date.now().toString(36)}-${seq}`
}

export function FlowEditor({ flowId, onBack }: { flowId: string; onBack: () => void }) {
  const [flow, setFlow] = useState<Flow | null>(null)
  const [nodes, setNodes, onNodesChange] = useNodesState<ApertureNodeData>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)

  const [run, setRun] = useState<Run | null>(null)
  const [findingsByNode, setFindingsByNode] = useState<Record<string, Finding[]>>({})
  const stopWatchRef = useRef<() => void>(() => {})

  useEffect(() => {
    let cancelled = false
    api.getFlow(flowId).then((f) => {
      if (cancelled) return
      setFlow(f)
      setNodes(f.nodes.map(toRFNode))
      setEdges(f.edges.map((e) => ({ id: e.id, source: e.from, target: e.to })))
      setDirty(false)
    })
    api.listRuns(flowId).then((runs) => {
      if (cancelled || runs.length === 0) return
      const latest = runs[0]
      setRun(latest)
      api.listFindings(latest.id).then((all) => {
        if (cancelled) return
        setFindingsByNode(bucketByNode(all))
      })
    })
    return () => {
      cancelled = true
      stopWatchRef.current()
    }
  }, [flowId, setNodes, setEdges])

  const handleNodesChange = useCallback(
    (changes: NodeChange[]) => {
      onNodesChange(changes)
      setDirty(true)
    },
    [onNodesChange],
  )

  const onConnect = useCallback(
    (conn: Connection) => {
      setEdges((eds) => addEdge({ ...conn, id: `e-${conn.source}-${conn.target}-${Date.now().toString(36)}` }, eds))
      setDirty(true)
    },
    [setEdges],
  )

  const addNode = useCallback(
    (kind: NodeKind) => {
      const id = newNodeId(kind)
      const node: Node<ApertureNodeData> = {
        id,
        type: 'aperture',
        position: { x: 80 + ((nodes.length * 60) % 480), y: 80 + ((nodes.length * 90) % 420) },
        data: { kind, config: {}, status: 'pending', liveCount: 0 },
      }
      setNodes((ns) => [...ns, node])
      setSelectedId(id)
      setDirty(true)
    },
    [nodes.length, setNodes],
  )

  const selected = useMemo(() => nodes.find((n) => n.id === selectedId), [nodes, selectedId])

  const updateNodeData = useCallback(
    (id: string, patch: Partial<ApertureNodeData>) => {
      setNodes((ns) => ns.map((n) => (n.id === id ? { ...n, data: { ...n.data, ...patch } } : n)))
      setDirty(true)
    },
    [setNodes],
  )

  const deleteNode = useCallback(
    (id: string) => {
      setNodes((ns) => ns.filter((n) => n.id !== id))
      setEdges((es) => es.filter((e) => e.source !== id && e.target !== id))
      setSelectedId(null)
      setDirty(true)
    },
    [setNodes, setEdges],
  )

  const toFlow = useCallback((): Flow => {
    return {
      id: flowId,
      name: flow?.name ?? 'Untitled flow',
      nodes: nodes.map((n) => ({
        id: n.id,
        kind: n.data.kind,
        label: n.data.label,
        config: n.data.config,
        position: n.position,
      })),
      edges: edges.map((e) => ({ id: e.id, from: e.source, to: e.target })),
    }
  }, [flowId, flow, nodes, edges])

  const save = useCallback(async () => {
    setSaving(true)
    try {
      const saved = await api.updateFlow(flowId, toFlow())
      setFlow(saved)
      setDirty(false)
    } finally {
      setSaving(false)
    }
  }, [flowId, toFlow])

  const startRun = useCallback(async () => {
    if (dirty) await save()
    setNodes((ns) => ns.map((n) => ({ ...n, data: { ...n.data, status: 'pending' as NodeStatus, liveCount: 0 } })))
    setFindingsByNode({})
    const { runId } = await api.runFlow(flowId)
    setRun({ id: runId, flowId, status: 'running', startedAt: new Date().toISOString() })

    stopWatchRef.current()
    stopWatchRef.current = watchRun(runId, (ev) => {
      if (ev.type === 'finding' && ev.finding && ev.nodeId) {
        const nodeId = ev.nodeId
        const finding = ev.finding
        setFindingsByNode((prev) => ({ ...prev, [nodeId]: [...(prev[nodeId] ?? []), finding] }))
        setNodes((ns) =>
          ns.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, liveCount: n.data.liveCount + 1 } } : n)),
        )
      } else if (ev.type === 'status' && ev.nodeId && ev.status) {
        const nodeId = ev.nodeId
        const status = ev.status
        setNodes((ns) => ns.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, status } } : n)))
      } else if (ev.type === 'done') {
        setRun((r) => (r ? { ...r, status: ev.status === 'failed' ? 'failed' : 'succeeded', error: ev.message } : r))
      }
    })
  }, [dirty, save, flowId, setNodes])

  // With no node selected, show only sink nodes' output (leaves of the
  // DAG) so the same finding doesn't appear once per hop it passed
  // through — that's what "the flow's results" means to a user.
  const sinkNodeIds = useMemo(() => {
    const hasOutgoing = new Set(edges.map((e) => e.source))
    return nodes.filter((n) => !hasOutgoing.has(n.id)).map((n) => n.id)
  }, [nodes, edges])

  const displayedFindings = selectedId
    ? findingsByNode[selectedId] ?? []
    : sinkNodeIds.flatMap((id) => findingsByNode[id] ?? [])

  if (!flow) {
    return <div className="p-8 text-neutral-500">Loading…</div>
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-3 border-b border-neutral-800 bg-neutral-950 px-4 py-2">
        <button onClick={onBack} className="text-sm text-neutral-400 hover:text-neutral-200">
          ← Flows
        </button>
        <input
          className="rounded bg-transparent px-1 text-sm font-medium text-neutral-100 outline-none focus:bg-neutral-800"
          value={flow.name}
          onChange={(e) => {
            setFlow({ ...flow, name: e.target.value })
            setDirty(true)
          }}
        />
        <div className="ml-auto flex items-center gap-2">
          {run && <RunBadge run={run} />}
          <button
            onClick={save}
            disabled={saving || !dirty}
            className="rounded border border-neutral-700 px-3 py-1 text-sm text-neutral-200 hover:border-neutral-500 disabled:opacity-40"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            onClick={startRun}
            className="rounded bg-sky-600 px-3 py-1 text-sm font-medium text-white hover:bg-sky-500"
          >
            Run
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className="w-56 shrink-0 overflow-y-auto border-r border-neutral-800 bg-neutral-950">
          <Palette onAdd={addNode} />
        </aside>

        <div className="flex flex-1 flex-col">
          <div className="h-3/5 min-h-[280px]">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={handleNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onNodeClick={(_, n) => setSelectedId(n.id)}
              onPaneClick={() => setSelectedId(null)}
              nodeTypes={nodeTypes}
              fitView
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#27272a" gap={20} />
              <Controls />
              <MiniMap pannable zoomable className="!bg-neutral-900" maskColor="rgba(0,0,0,0.6)" />
            </ReactFlow>
          </div>
          <div className="flex-1 overflow-hidden border-t border-neutral-800">
            <ResultsTable findings={displayedFindings} />
          </div>
        </div>

        {selected && (
          <aside className="w-80 shrink-0 overflow-y-auto border-l border-neutral-800 bg-neutral-950">
            <Inspector
              node={{ id: selected.id, kind: selected.data.kind, label: selected.data.label, config: selected.data.config }}
              onChange={(config) => updateNodeData(selected.id, { config })}
              onLabelChange={(label) => updateNodeData(selected.id, { label })}
              onDelete={() => deleteNode(selected.id)}
            />
          </aside>
        )}
      </div>
    </div>
  )
}

function bucketByNode(findings: Finding[]): Record<string, Finding[]> {
  const out: Record<string, Finding[]> = {}
  for (const f of findings) {
    ;(out[f.sourceNodeId] ??= []).push(f)
  }
  return out
}

function RunBadge({ run }: { run: Run }) {
  const color = run.status === 'running' ? 'text-amber-400' : run.status === 'failed' ? 'text-red-400' : 'text-emerald-400'
  return <span className={`text-xs font-medium ${color}`}>Run: {run.status}</span>
}
