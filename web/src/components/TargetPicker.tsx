import type { Target } from '../types'

// TargetPicker is the shared multi-select target list used by every job
// launcher (the Directory/Subdomain/VHost Scanner tabs in CaseView.tsx) and
// by Probe's batch mode -- a case's targets rendered as toggleable buttons
// plus a "select all" shortcut, backed by a plain Set of selected values so
// callers can seed/read the selection however suits their own form state.
export function TargetPicker({ targets, selected, onChange }: { targets: Target[]; selected: Set<string>; onChange: (next: Set<string>) => void }) {
  const toggle = (value: string) => {
    const next = new Set(selected)
    if (next.has(value)) next.delete(value)
    else next.add(value)
    onChange(next)
  }
  if (targets.length === 0) {
    return <p className="text-xs text-neutral-600">No targets in this case yet — add one on the Targets tab first.</p>
  }
  const allSelected = targets.every((t) => selected.has(t.value))
  const toggleAll = () => onChange(allSelected ? new Set() : new Set(targets.map((t) => t.value)))
  return (
    <div className="space-y-1.5">
      <button
        type="button"
        onClick={toggleAll}
        className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-400 hover:border-sky-600 hover:text-sky-400"
      >
        {allSelected ? 'Deselect all' : `Select all (${targets.length})`}
      </button>
      <div className="flex max-h-32 flex-wrap gap-1.5 overflow-y-auto">
        {targets.map((t) => (
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
}
