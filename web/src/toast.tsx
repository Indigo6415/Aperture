import { useEffect, useState } from 'react'

type ToastKind = 'info' | 'error' | 'success'
interface Toast {
  id: number
  message: string
  kind: ToastKind
}

// A tiny module-level pub/sub instead of context -- showToast is called from
// places with no natural component state to hold a result in (context menu
// actions in particular, which fire from wherever the user right-clicked),
// so it needs to work as a plain function callable from anywhere.
let nextId = 1
let toasts: Toast[] = []
let listeners: ((toasts: Toast[]) => void)[] = []

function emit() {
  for (const l of listeners) l(toasts)
}

export function showToast(message: string, kind: ToastKind = 'info') {
  const id = nextId++
  toasts = [...toasts, { id, message, kind }]
  emit()
  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id)
    emit()
  }, 3500)
}

// ToastHost renders every active toast bottom-right; mount it once near the
// app root.
export function ToastHost() {
  const [items, setItems] = useState<Toast[]>(toasts)
  useEffect(() => {
    listeners.push(setItems)
    return () => {
      listeners = listeners.filter((l) => l !== setItems)
    }
  }, [])

  if (items.length === 0) return null
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
      {items.map((t) => (
        <div
          key={t.id}
          className={`pointer-events-auto max-w-xs rounded border px-3 py-2 text-xs shadow-lg ${
            t.kind === 'error'
              ? 'border-red-800 bg-red-950/90 text-red-200'
              : t.kind === 'success'
                ? 'border-emerald-800 bg-emerald-950/90 text-emerald-200'
                : 'border-neutral-700 bg-neutral-900/95 text-neutral-200'
          }`}
        >
          {t.message}
        </div>
      ))}
    </div>
  )
}
