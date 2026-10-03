import { useState } from 'react'

// ScanErrorNotice is the failure block every scanner's output shows when its
// run errored. It opens expanded so the error is never missed, and a toggle
// folds it down to a one-line header when the operator wants the output
// tidy -- the same show/hide control for every scanner, so they all behave
// alike.
export function ScanErrorNotice({ message, label = 'Scan failed' }: { message?: string; label?: string }) {
  const [shown, setShown] = useState(true)

  return (
    <div className="rounded-lg border border-red-800 bg-red-950/40 text-xs text-red-300">
      <div className="flex items-center gap-2 p-3">
        <span className="min-w-0 flex-1 truncate font-medium">{label}</span>
        <button
          type="button"
          aria-expanded={shown}
          onClick={() => setShown((v) => !v)}
          className="shrink-0 rounded border border-red-800 px-2 py-0.5 text-[11px] text-red-300 transition-colors hover:border-red-600 hover:text-red-100"
        >
          {shown ? 'Hide error' : 'Show error'}
        </button>
      </div>
      {shown && message && <p className="break-words border-t border-red-900 px-3 py-2 text-red-300/90">{message}</p>}
    </div>
  )
}
