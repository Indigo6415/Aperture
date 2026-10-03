import { useState } from 'react'
import type { TargetList, TargetListKind } from '../types'
import { TARGET_LIST_KINDS, TARGET_LIST_KIND_LABELS } from '../targetListKinds'

// SaveToListModal is the "add to playlist" prompt every save flow outside
// the Targets tab goes through (promoting selected tool results, saving a
// discovered subdomain) -- unlike the Targets tab's add form, which always
// saves into whichever list tab is open, these saves happen with no list
// already in view, so the destination has to be asked for explicitly: pick
// one of the case's existing lists, or create a new one on the spot.
export function SaveToListModal({
  lists,
  itemLabel,
  onPick,
  onCreateList,
  onClose,
}: {
  lists: TargetList[]
  itemLabel: string
  onPick: (listId: string) => Promise<void> | void
  onCreateList: (name: string, kind: TargetListKind) => Promise<TargetList>
  onClose: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(lists.length === 0)
  const [name, setName] = useState('')
  const [kind, setKind] = useState<TargetListKind>('domain')

  const pick = async (listId: string) => {
    setBusy(true)
    setError('')
    try {
      await onPick(listId)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setBusy(false)
    }
  }

  const createAndPick = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = name.trim()
    if (!trimmed) return
    setBusy(true)
    setError('')
    try {
      const list = await onCreateList(trimmed, kind)
      await onPick(list.id)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="flex max-h-[80vh] w-full max-w-sm flex-col rounded-lg border border-neutral-700 bg-neutral-900 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-300">Save {itemLabel} to…</h2>
          <button type="button" onClick={onClose} className="text-neutral-500 hover:text-neutral-300" title="Close">
            ✕
          </button>
        </div>
        <div className="flex-1 space-y-1.5 overflow-y-auto p-2">
          {lists.map((l) => (
            <button
              key={l.id}
              type="button"
              disabled={busy}
              onClick={() => pick(l.id)}
              className="flex w-full items-center justify-between rounded border border-neutral-800 px-3 py-2 text-left text-sm text-neutral-200 hover:border-sky-600 hover:bg-neutral-800/60 disabled:opacity-50"
            >
              <span className="truncate">{l.name}</span>
              <span className="shrink-0 text-xs text-neutral-500">{TARGET_LIST_KIND_LABELS[l.kind]}</span>
            </button>
          ))}

          {!creating ? (
            <button
              type="button"
              onClick={() => setCreating(true)}
              className="w-full rounded border border-dashed border-neutral-700 px-3 py-2 text-left text-xs text-neutral-500 hover:border-sky-600 hover:text-sky-400"
            >
              + Create new list
            </button>
          ) : (
            <form onSubmit={createAndPick} className="space-y-1.5 rounded border border-neutral-800 p-2">
              <input
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="List name…"
                className="w-full rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-xs text-neutral-200 outline-none focus:border-sky-500"
              />
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value as TargetListKind)}
                className="w-full rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-xs text-neutral-200 outline-none focus:border-sky-500"
              >
                {TARGET_LIST_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {TARGET_LIST_KIND_LABELS[k]}
                  </option>
                ))}
              </select>
              <div className="flex items-center justify-between">
                {lists.length > 0 && (
                  <button type="button" onClick={() => setCreating(false)} className="text-xs text-neutral-500 hover:text-neutral-300">
                    Cancel
                  </button>
                )}
                <button
                  type="submit"
                  disabled={busy || !name.trim()}
                  className="ml-auto rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
                >
                  Create & save
                </button>
              </div>
            </form>
          )}
          {error && <p className="px-1 text-xs text-red-400">{error}</p>}
        </div>
      </div>
    </div>
  )
}
