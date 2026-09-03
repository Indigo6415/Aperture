import { memo } from 'react'
import { Handle, Position, type NodeProps } from 'reactflow'
import { KIND_META, STATUS_META } from '../kindMeta'
import type { NodeKind, NodeStatus } from '../types'
import { SOURCE_KINDS } from '../types'

export interface ApertureNodeData {
  kind: NodeKind
  label?: string
  config: Record<string, unknown>
  status: NodeStatus
  liveCount: number
}

function ApertureNodeImpl({ data, selected }: NodeProps<ApertureNodeData>) {
  const meta = KIND_META[data.kind]
  const status = STATUS_META[data.status]
  const isSource = SOURCE_KINDS.has(data.kind)

  return (
    <div
      className="min-w-[220px] rounded-lg border bg-neutral-900 shadow-lg transition-colors"
      style={{
        borderColor: selected ? meta.accent : 'rgba(255,255,255,0.08)',
        boxShadow: selected ? `0 0 0 1px ${meta.accent}` : undefined,
      }}
    >
      {!isSource && <Handle type="target" position={Position.Left} className="!bg-neutral-500" />}
      <Handle type="source" position={Position.Right} className="!bg-neutral-500" />

      <div className="flex items-center gap-2 rounded-t-lg px-3 py-2" style={{ background: `${meta.accent}1a` }}>
        <span>{meta.icon}</span>
        <span className="text-sm font-medium text-neutral-100">{data.label || meta.label}</span>
        <span className="ml-auto flex items-center gap-1 text-xs text-neutral-400">
          <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ background: status.dot }} />
          {status.label}
        </span>
      </div>
      <div className="px-3 py-2">
        <p className="truncate text-xs text-neutral-400">{meta.summary(data.config)}</p>
        {data.liveCount > 0 && (
          <p className="mt-1 text-xs font-medium" style={{ color: meta.accent }}>
            {data.liveCount} finding{data.liveCount === 1 ? '' : 's'}
          </p>
        )}
      </div>
    </div>
  )
}

export const ApertureNode = memo(ApertureNodeImpl)
