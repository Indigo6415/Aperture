import { useEffect, useState } from 'react'
import { api, ApiError } from '../api'
import type { ActivityEvent } from '../types'

// ACTIVITY_DOT buckets an event's kind (see store.LogActivity's callers for
// the full list of kinds, e.g. "target_added", "job_finished",
// "credential_added", "report_exported") by its prefix, so a new kind added
// later still gets a sensible color instead of falling through to nothing.
function dotColorFor(kind: string): string {
  if (kind.startsWith('target_')) return '#a3a3a3' // neutral-400
  if (kind.startsWith('job_')) return '#38bdf8' // sky-400
  if (kind.startsWith('credential_')) return '#fbbf24' // amber-400
  if (kind.startsWith('report_')) return '#34d399' // emerald-400
  return '#6b7280' // neutral-500
}

// ActivityTimeline is a case's engagement log: targets added/removed, jobs
// started/finished, credentials saved/removed, reports exported -- a
// chronological record for writing up an engagement, not a live view (no
// websocket -- see LogActivity's callers in internal/api for what's
// recorded). Refetches on mount and via the Refresh button.
export function ActivityTimeline({ caseId }: { caseId: string }) {
  const [events, setEvents] = useState<ActivityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = () => {
    setLoading(true)
    setError('')
    api
      .listActivity(caseId)
      .then(setEvents)
      .catch((err) => setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }

  useEffect(load, [caseId])

  return (
    <div className="mx-auto h-full max-w-3xl overflow-y-auto px-4 py-6">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Activity</h1>
          <p className="mt-1 text-xs text-neutral-500">A chronological log of what's happened in this case.</p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="rounded border border-neutral-700 px-2.5 py-1 text-xs text-neutral-400 hover:border-sky-600 hover:text-sky-300 disabled:opacity-50"
        >
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {error && <div className="mb-4 rounded-lg border border-red-800 bg-red-950/40 p-3 text-xs text-red-300">{error}</div>}

      {!loading && events.length === 0 && !error && (
        <div className="flex h-40 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
          Nothing logged yet -- add a target or launch a job to get started.
        </div>
      )}

      <ul className="divide-y divide-neutral-900 rounded-lg border border-neutral-800 bg-neutral-950/40">
        {events.map((e) => (
          <li key={e.id} className="flex items-start gap-3 px-3 py-2 text-xs">
            <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: dotColorFor(e.kind) }} />
            <span className="min-w-0 flex-1 break-words text-neutral-300">{e.message}</span>
            <span className="shrink-0 whitespace-nowrap text-neutral-600">{new Date(e.createdAt).toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
