import type { Job, RunStatus } from '../types'
import { useCollapsible } from '../collapsible'

// Local to this file rather than shared with CaseView's own STATUS_DOT --
// JobHistory only ever needs the running/done/error trio, and importing
// CaseView from here (which itself imports JobHistory) would make the two
// files circularly dependent.
const STATUS_DOT: Record<'running' | 'done' | 'error', string> = {
  running: '#facc15',
  done: '#34d399',
  error: '#f87171',
}

// JobHistory is a tab's past-job log -- collapsed to a one-line "N jobs ▸"
// bar by default (it's secondary, backward-looking info, not something that
// needs to permanently occupy space above the results table), expandable on
// click. A still-running job's Stop control stays visible on the collapsed
// bar itself so cancelling one never requires expanding the whole history.
export function JobHistory({
  jobs,
  statusOf,
  onCancel,
  panelKey,
}: {
  jobs: Job[]
  statusOf: (job: Job) => RunStatus
  onCancel: (job: Job) => void
  panelKey: string
}) {
  const [open, setOpen] = useCollapsible(`jobHistory.${panelKey}`, false)
  const running = jobs.filter((j) => statusOf(j) === 'running')

  return (
    <div className="shrink-0 border-b border-neutral-800">
      <div className="flex items-center gap-2 px-3 py-1.5 text-xs">
        <button onClick={() => setOpen(!open)} className="shrink-0 text-neutral-500 hover:text-neutral-300">
          {open ? '▾' : '▸'} {jobs.length} job{jobs.length === 1 ? '' : 's'}
        </button>
        {running.length > 0 && (
          <span className="flex items-center gap-1.5 text-amber-400">
            <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_DOT.running }} />
            {running.length} running
          </span>
        )}
        {/* Every running job gets a Stop here, so none needs the history expanded
            to be reachable. With several, each one names its first target so the
            buttons can be told apart. */}
        {running.length > 0 && (
          <div className="ml-auto flex min-w-0 items-center gap-1.5">
            {running.length > 1 && (
              <button
                onClick={() => running.forEach((job) => onCancel(job))}
                title="Stop every running job"
                className="flex shrink-0 items-center rounded border border-red-900 px-2 py-0.5 text-red-400 hover:border-red-500 hover:text-red-300"
              >
                Stop all ({running.length})
              </button>
            )}
            {running.map((job) => (
              <button
                key={job.id}
                onClick={() => onCancel(job)}
                title={`Stop ${job.targets.join(', ')}`}
                className="flex min-w-0 shrink items-center gap-1 rounded border border-red-900 px-2 py-0.5 text-red-400 hover:border-red-500 hover:text-red-300"
              >
                Stop
                {running.length > 1 && <span className="min-w-0 truncate font-mono text-[11px] text-red-300/80">{job.targets[0]}</span>}
              </button>
            ))}
          </div>
        )}
      </div>
      {open && (
        <div className="divide-y divide-neutral-900 border-t border-neutral-900">
          {[...jobs].reverse().map((job) => {
            const status = statusOf(job)
            return (
              <div key={job.id} className="flex items-center gap-2 px-3 py-1.5 text-xs">
                <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS_DOT[status === 'running' ? 'running' : status === 'failed' ? 'error' : 'done'] }} />
                <span className="truncate font-mono text-neutral-300">{job.targets.join(', ')}</span>
                <span className="shrink-0 text-neutral-600">{status}</span>
                <span className="shrink-0 text-neutral-600">{new Date(job.createdAt).toLocaleTimeString()}</span>
                {status === 'running' && (
                  <button onClick={() => onCancel(job)} className="ml-auto shrink-0 rounded border border-red-900 px-2 py-0.5 text-red-400 hover:border-red-500 hover:text-red-300">
                    Stop
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
