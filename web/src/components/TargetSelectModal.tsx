import { useEffect, useMemo, useState } from 'react'
import type { Target } from '../types'

// Shared modal shell behind TargetPicker and TargetButtons -- houses the
// search box, list tabs, backdrop, and Escape-to-close wiring so both
// target selectors open the same-feeling "picker window" instead of
// duplicating a dialog each. Tabs are derived straight from the targets
// passed in (each one already carries its listId/listName from the
// backend), so callers don't need to separately fetch/pass the case's
// target lists just to get tabbed browsing.
// children receives two lists: `visible` is the active tab filtered by the search
// box (what the user sees), and `inTab` is every target in the active tab before
// filtering, so bulk actions like "select all" can scope to the tab rather than the whole case.
export function TargetSelectModal({ title, targets, onClose, children }: { title: string; targets: Target[]; onClose: () => void; children: (visible: Target[], inTab: Target[]) => React.ReactNode }) {
  const [query, setQuery] = useState('')
  const [activeListId, setActiveListId] = useState('all')

  // Close on Escape so the picker behaves like any other modal dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const lists = useMemo(() => {
    const byId = new Map<string, { id: string; name: string; count: number }>()
    for (const t of targets) {
      const existing = byId.get(t.listId)
      if (existing) existing.count += 1
      else byId.set(t.listId, { id: t.listId, name: t.listName, count: 1 })
    }
    return [...byId.values()]
  }, [targets])

  // Tabs are pointless with zero or one list -- every target would already
  // be in the single visible tab.
  const showTabs = lists.length > 1
  const withinList = showTabs && activeListId !== 'all' ? targets.filter((t) => t.listId === activeListId) : targets
  const visible = withinList.filter((t) => t.value.toLowerCase().includes(query.trim().toLowerCase()))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="flex max-h-[80vh] w-full max-w-lg flex-col rounded-lg border border-neutral-700 bg-neutral-900 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-300">{title}</h2>
          <button type="button" onClick={onClose} className="text-neutral-500 hover:text-neutral-300" title="Close">
            ✕
          </button>
        </div>
        {showTabs && (
          <div className="flex flex-wrap gap-1 border-b border-neutral-800 px-2 py-1.5">
            <button
              type="button"
              onClick={() => setActiveListId('all')}
              className={`rounded px-2 py-1 text-xs ${
                activeListId === 'all' ? 'bg-sky-950/60 text-sky-300' : 'text-neutral-400 hover:text-neutral-200'
              }`}
            >
              All ({targets.length})
            </button>
            {lists.map((l) => (
              <button
                key={l.id}
                type="button"
                onClick={() => setActiveListId(l.id)}
                className={`rounded px-2 py-1 text-xs ${
                  activeListId === l.id ? 'bg-sky-950/60 text-sky-300' : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                {l.name} ({l.count})
              </button>
            ))}
          </div>
        )}
        <div className="border-b border-neutral-800 p-2">
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter targets…"
            className="w-full rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-xs text-neutral-200 outline-none focus:border-sky-500"
          />
        </div>
        <div className="flex-1 overflow-y-auto p-2">{children(visible, withinList)}</div>
      </div>
    </div>
  )
}
