import { useState } from 'react'
import type { Target } from '../types'
import { TargetSelectModal } from './TargetSelectModal'

// TargetPicker is the shared multi-select target list used by every job
// launcher (the Directory/Subdomain/VHost Scanner tabs in CaseView.tsx) and
// by Probe's batch mode -- a button showing how many of the case's targets
// are selected, which opens a modal with the full toggleable list plus a
// "select all" shortcut, backed by a plain Set of selected values so callers
// can seed/read the selection however suits their own form state.
export function TargetPicker({ targets, selected, onChange }: { targets: Target[]; selected: Set<string>; onChange: (next: Set<string>) => void }) {
  const [open, setOpen] = useState(false)

  if (targets.length === 0) {
    return <p className="text-xs text-neutral-600">No targets in this case yet — add one on the Targets tab first.</p>
  }

  const toggle = (value: string) => {
    const next = new Set(selected)
    // Clicking an already-selected target removes it, otherwise add it.
    if (next.has(value)) next.delete(value)
    else next.add(value)
    onChange(next)
  }

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-300 hover:border-sky-600 hover:text-sky-400"
      >
        {selected.size > 0 ? `${selected.size} of ${targets.length} target${targets.length === 1 ? '' : 's'} selected` : `Select targets (${targets.length})`}
      </button>

      {open && (
        <TargetSelectModal title="Select targets" targets={targets} onClose={() => setOpen(false)}>
          {(visible, inTab) => {
            // "Select all" is scoped to the active list tab (inTab), not the whole case,
            // so it never touches selections made in other tabs.
            const allSelected = inTab.length > 0 && inTab.every((t) => selected.has(t.value))

            // Toggling on adds this tab's targets to the existing selection;
            // toggling off removes only this tab's targets and leaves the rest alone.
            const toggleAll = () => {
              const next = new Set(selected)
              for (const t of inTab) {
                if (allSelected) next.delete(t.value)
                else next.add(t.value)
              }
              onChange(next)
            }

            return (
              <div className="space-y-1.5">
                <button
                  type="button"
                  onClick={toggleAll}
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-400 hover:border-sky-600 hover:text-sky-400"
                >
                  {allSelected ? 'Deselect all' : `Select all (${inTab.length})`}
                </button>
                <div className="flex flex-wrap gap-1.5">
                  {visible.length === 0 && <p className="text-xs text-neutral-600">No targets match.</p>}
                  {visible.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => toggle(t.value)}
                      className={`rounded border px-2 py-1 font-mono text-xs ${
                        selected.has(t.value) ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-neutral-500'
                      }`}
                    >
                      {t.value}
                    </button>
                  ))}
                </div>
              </div>
            )
          }}
        </TargetSelectModal>
      )}
    </div>
  )
}
