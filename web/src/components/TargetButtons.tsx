import type { Target } from '../types'

// TargetButtons renders every target already saved to this case as a small
// clickable button -- the same "target already in the case" convenience the
// Directory/Subdomain/VHost Scanner tabs get from TargetPicker in
// CaseView.tsx, but for a single-value field (JWT Scanner's URL, Probe's
// target) rather than a multi-select job launcher, so clicking one just
// fills the field instead of toggling a selection set.
export function TargetButtons({ targets, onPick, className }: { targets: Target[]; onPick: (value: string) => void; className?: string }) {
  if (targets.length === 0) return null
  return (
    <div className={`flex flex-wrap gap-1.5 ${className ?? ''}`}>
      {targets.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onPick(t.value)}
          title={`Use ${t.value}`}
          className="rounded border border-neutral-700 bg-neutral-900 px-2 py-0.5 font-mono text-xs text-neutral-400 hover:border-sky-500 hover:text-sky-300"
        >
          {t.value}
        </button>
      ))}
    </div>
  )
}
