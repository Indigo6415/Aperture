// ProgressBar renders a determinate percentage bar when total is known, or
// a pulsing indeterminate bar (feroxbuster's recursive crawling makes its
// total request count unknowable upfront) with a running result count
// otherwise.
export function ProgressBar({ done, total }: { done: number; total: number }) {
  if (total > 0) {
    const pct = Math.min(100, Math.round((done / total) * 100))
    return (
      <div className="flex items-center gap-2">
        <div className="h-1.5 w-32 overflow-hidden rounded-full bg-neutral-800">
          <div className="h-full rounded-full bg-sky-500 transition-[width]" style={{ width: `${pct}%` }} />
        </div>
        <span className="whitespace-nowrap font-mono text-xs text-neutral-500">
          {done.toLocaleString()}/{total.toLocaleString()}
        </span>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-32 overflow-hidden rounded-full bg-neutral-800">
        <div className="h-full w-1/3 animate-pulse rounded-full bg-sky-500" />
      </div>
      <span className="whitespace-nowrap font-mono text-xs text-neutral-500">{done.toLocaleString()} results</span>
    </div>
  )
}
