import { KIND_META } from '../kindMeta'
import { NODE_KINDS, type NodeKind } from '../types'

export function Palette({ onAdd }: { onAdd: (kind: NodeKind) => void }) {
  return (
    <div className="flex flex-col gap-2 p-3">
      <h2 className="px-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Add node</h2>
      {NODE_KINDS.map((kind) => {
        const meta = KIND_META[kind]
        return (
          <button
            key={kind}
            onClick={() => onAdd(kind)}
            className="flex items-center gap-2 rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-left text-sm text-neutral-200 hover:border-neutral-600"
          >
            <span style={{ color: meta.accent }}>{meta.icon}</span>
            {meta.label}
          </button>
        )
      })}
    </div>
  )
}
