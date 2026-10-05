import { useEffect, useState } from 'react'

type ToastKind = 'info' | 'error' | 'success'

// ToastOptions tune one toast beyond its kind: a color tints the left accent
// bar (the notification engine passes a rule's color here) and a title shows
// a bold label above the message. Both are optional, so every existing
// showToast(message, kind) call is unaffected.
export interface ToastOptions {
  color?: string
  title?: string
  duration?: number
}

interface Toast {
  id: number
  message: string
  kind: ToastKind
  color?: string
  title?: string
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

export function showToast(message: string, kind: ToastKind = 'info', opts: ToastOptions = {}) {
  const id = nextId++
  toasts = [...toasts, { id, message, kind, color: opts.color, title: opts.title }]
  emit()
  // Auto-dismiss after the (optionally overridden) lifetime.
  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id)
    emit()
  }, opts.duration ?? 3500)
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
          // A color (from a notification rule) tints the left accent bar and
          // overrides the kind-based border; without one, the kind picks the
          // palette exactly as before.
          style={t.color ? { borderLeftColor: t.color, borderLeftWidth: 3 } : undefined}
          className={`pointer-events-auto max-w-xs rounded border px-3 py-2 text-xs shadow-lg ${
            t.color
              ? 'border-neutral-700 bg-neutral-900/95 text-neutral-200'
              : t.kind === 'error'
                ? 'border-red-800 bg-red-950/90 text-red-200'
                : t.kind === 'success'
                  ? 'border-emerald-800 bg-emerald-950/90 text-emerald-200'
                  : 'border-neutral-700 bg-neutral-900/95 text-neutral-200'
          }`}
        >
          {t.title && <div className="mb-0.5 font-semibold" style={t.color ? { color: t.color } : undefined}>{t.title}</div>}
          {t.message}
        </div>
      ))}
    </div>
  )
}
