import { useEffect, useState } from 'react'
import { api } from '../api'
import type { FlowSummary, ToolInfo } from '../types'

export function FlowList({ onOpen }: { onOpen: (id: string) => void }) {
  const [flows, setFlows] = useState<FlowSummary[]>([])
  const [tools, setTools] = useState<ToolInfo[]>([])
  const [creating, setCreating] = useState(false)

  const refresh = () => api.listFlows().then(setFlows)

  useEffect(() => {
    refresh()
    api.listTools().then(setTools)
  }, [])

  const createFlow = async () => {
    setCreating(true)
    try {
      const flow = await api.createFlow({ name: 'New flow', nodes: [], edges: [] })
      onOpen(flow.id)
    } finally {
      setCreating(false)
    }
  }

  const remove = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (!confirm('Delete this flow and its run history?')) return
    await api.deleteFlow(id)
    refresh()
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold text-neutral-100">Aperture</h1>
        <button
          onClick={createFlow}
          disabled={creating}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          + New flow
        </button>
      </div>

      <div className="mb-6 flex gap-3">
        {tools.map((t) => (
          <span
            key={t.name}
            className={`rounded-full border px-2.5 py-0.5 text-xs ${t.available ? 'border-emerald-800 text-emerald-400' : 'border-red-900 text-red-400'}`}
          >
            {t.name} {t.available ? 'on PATH' : 'not found'}
          </span>
        ))}
      </div>

      <div className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
        {flows.map((f) => (
          <div
            key={f.id}
            onClick={() => onOpen(f.id)}
            className="flex cursor-pointer items-center justify-between px-4 py-3 hover:bg-neutral-900"
          >
            <div>
              <p className="text-sm font-medium text-neutral-100">{f.name}</p>
              <p className="text-xs text-neutral-500">Updated {new Date(f.updatedAt).toLocaleString()}</p>
            </div>
            <button onClick={(e) => remove(f.id, e)} className="text-xs text-neutral-600 hover:text-red-400">
              Delete
            </button>
          </div>
        ))}
        {flows.length === 0 && <p className="px-4 py-8 text-center text-sm text-neutral-600">No flows yet — create one to get started.</p>}
      </div>
    </div>
  )
}
