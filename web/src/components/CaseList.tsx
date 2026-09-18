import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import type { CaseSummary } from '../types'
import { SummaryCard } from './SummaryCard'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { showToast } from '../toast'

// How often the case list is repolled while at least one case has a job
// running, so the "Running…" pills stay live without a bespoke
// multi-case WebSocket just for the list.
const POLL_MS = 3000

type StatusFilter = 'all' | 'running' | 'idle'

// CaseList is the app's home view: create a new (empty) case, or jump back
// into one you've already started. Nothing about starting a case runs any
// tool -- targets are added and jobs launched only once you're inside it.
export function CaseList({ onOpen }: { onOpen: (caseId: string) => void }) {
  const { openMenu } = useContextMenu()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const [cases, setCases] = useState<CaseSummary[]>([])
  const [filterText, setFilterText] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')

  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout>

    const tick = () => {
      api.listCases().then((next) => {
        if (cancelled) return
        setCases(next)
        timer = setTimeout(tick, next.some((c) => c.running) ? POLL_MS : POLL_MS * 4)
      })
    }
    tick()

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [])

  const summary = useMemo(
    () => ({
      cases: cases.length,
      targets: cases.reduce((n, c) => n + c.targetCount, 0),
      findings: cases.reduce((n, c) => n + c.findingCount, 0),
      running: cases.filter((c) => c.running).length,
    }),
    [cases],
  )

  const filteredCases = useMemo(() => {
    const needle = filterText.trim().toLowerCase()
    return cases.filter((c) => {
      if (needle && !c.name.toLowerCase().includes(needle)) return false
      if (statusFilter === 'running' && !c.running) return false
      if (statusFilter === 'idle' && c.running) return false
      return true
    })
  }, [cases, filterText, statusFilter])

  const deleteCase = async (c: CaseSummary) => {
    try {
      await api.deleteCase(c.id)
      setCases((prev) => prev.filter((x) => x.id !== c.id))
      showToast(`Deleted case "${c.name}"`, 'success')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = name.trim()
    if (!trimmed) return
    setCreating(true)
    setError('')
    try {
      const { caseId } = await api.createCase(trimmed, description.trim() || undefined)
      onOpen(caseId)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex max-w-2xl flex-col items-center justify-center gap-10 px-6 py-10">
        <div className="w-full text-center">
          <h1 className="mb-2 text-3xl font-semibold text-neutral-100">Aperture</h1>
          <p className="mb-4 text-sm text-neutral-500">
            Start a case, then add targets and run tools against them yourself — nothing scans on its own.
          </p>
          <form onSubmit={submit} className="flex flex-col gap-2">
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Case name (e.g. Acme Corp — Q3 pentest)"
              className="rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-3 text-lg text-neutral-100 outline-none focus:border-sky-500"
            />
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (optional)"
              className="rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-2 text-sm text-neutral-100 outline-none focus:border-sky-500"
            />
            <button
              type="submit"
              disabled={creating || !name.trim()}
              className="rounded-lg bg-sky-600 px-6 py-3 text-lg font-medium text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {creating ? 'Creating…' : 'Create case'}
            </button>
          </form>

          {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
        </div>

        {cases.length > 0 && (
          <div className="grid w-full grid-cols-2 gap-3 sm:grid-cols-4">
            <SummaryCard label="Cases" value={summary.cases} />
            <SummaryCard label="Targets" value={summary.targets} />
            <SummaryCard label="Findings" value={summary.findings} />
            <SummaryCard label="Running now" value={summary.running} accent={summary.running > 0} />
          </div>
        )}

        {cases.length > 0 && (
          <div className="w-full">
            <div className="mb-2 flex items-center gap-2 px-1">
              <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">Cases</h2>
              <span className="text-xs text-neutral-600">
                ({filteredCases.length} of {cases.length})
              </span>
              <input
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                placeholder="Filter by name…"
                className="ml-auto w-48 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none focus:border-sky-500"
              />
              <div className="flex overflow-hidden rounded border border-neutral-700 text-xs">
                {(['all', 'running', 'idle'] as StatusFilter[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => setStatusFilter(f)}
                    className={`px-2 py-1 capitalize ${statusFilter === f ? 'bg-neutral-700 text-neutral-100' : 'text-neutral-500 hover:text-neutral-300'}`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
              {filteredCases.length === 0 && <p className="px-4 py-8 text-center text-sm text-neutral-600">No cases match this filter.</p>}
              {filteredCases.map((c) => (
                <div
                  key={c.id}
                  onClick={() => onOpen(c.id)}
                  onContextMenu={(e) => {
                    e.stopPropagation()
                    openMenu(e, [
                      { label: 'Open case', onSelect: () => onOpen(c.id) },
                      { label: 'Copy name', onSelect: () => copyToClipboard(c.name, 'Copied name') },
                      'separator',
                      { label: 'Delete case', onSelect: () => deleteCase(c), danger: true },
                    ])
                  }}
                  className="flex cursor-pointer items-center justify-between gap-4 px-4 py-3 hover:bg-neutral-900"
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-neutral-100">{c.name}</p>
                    <p className="truncate text-xs text-neutral-500">
                      {c.description ? `${c.description} · ` : ''}
                      {c.targetCount} target{c.targetCount === 1 ? '' : 's'} · {c.jobCount} job{c.jobCount === 1 ? '' : 's'} · {c.findingCount} finding
                      {c.findingCount === 1 ? '' : 's'}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className={`rounded-full px-2 py-0.5 text-xs ${c.running ? 'bg-amber-900/40 text-amber-400' : 'bg-neutral-800 text-neutral-400'}`}>
                      {c.running ? 'Running…' : 'Idle'}
                    </span>
                    <p className="text-xs text-neutral-500">{new Date(c.createdAt).toLocaleString()}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
