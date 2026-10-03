import { useState } from 'react'
import type { Target } from '../types'
import { TargetSelectModal } from './TargetSelectModal'

// TargetButtons is the "target already in the case" convenience the
// Directory/Subdomain/VHost Scanner tabs get from TargetPicker in
// CaseView.tsx, but for a single-value field (JWT Scanner's URL, Probe's
// target) rather than a multi-select job launcher -- a button that opens a
// modal to browse/filter the case's targets, and picking one fills the field
// and closes the modal.
export function TargetButtons({ targets, onPick, className }: { targets: Target[]; onPick: (value: string) => void; className?: string }) {
  const [open, setOpen] = useState(false)
  if (targets.length === 0) return null

  return (
    <div className={className}>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded border border-neutral-700 bg-neutral-900 px-2 py-0.5 text-xs text-neutral-400 hover:border-sky-500 hover:text-sky-300"
      >
        Select target ({targets.length})
      </button>

      {open && (
        <TargetSelectModal title="Select target" targets={targets} onClose={() => setOpen(false)}>
          {(visible) => (
            <div className="flex flex-wrap gap-1.5">
              {visible.length === 0 && <p className="text-xs text-neutral-600">No targets match.</p>}
              {visible.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => {
                    onPick(t.value)
                    setOpen(false)
                  }}
                  title={`Use ${t.value}`}
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 font-mono text-xs text-neutral-400 hover:border-sky-500 hover:text-sky-300"
                >
                  {t.value}
                </button>
              ))}
            </div>
          )}
        </TargetSelectModal>
      )}
    </div>
  )
}
