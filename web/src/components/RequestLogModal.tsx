import { Fragment, useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../api'
import type { NodeRequestLog, RequestRecord } from '../types'
import { statusHexColor } from '../statusColor'
import { CopyButton } from './CopyButton'
import { useContextMenu } from '../contextMenu'
import { sendToTester } from '../testerHandoff'
import { isHit, parseRawRequest } from '../requestLog'
import {
  EMPTY_REQUEST_FILTERS,
  buildPredicates,
  hasActiveFilters,
  isInvalidFilter,
  nextSort,
  sortRecords,
  type RequestFilters,
  type SortKey,
  type SortState,
} from '../requestFilters'

// RequestLogModal is the "Inspect requests" view for one target of a scan:
// every HTTP request its node made, in the order they were sent. Each row
// shows the attributes at a glance; expanding it fetches the full raw request
// and response, which the list deliberately leaves out so opening the view stays
// cheap for a large fuzz run.
//
// Hits are the requests a finding reported, shaded orange. Each column has its
// own filter in a row under the headers, and a click on a header sorts by that
// column. The quick search also matches inside request and response bodies, and
// runs on the server since the bodies aren't loaded into the list.
//
// Chain view nests each request under the request whose redirect led to it,
// Wireshark-style. A request is only linked to a cause when the client followed
// a redirect, so requests from clients that don't follow redirects stay at the
// top level.
//
// It renders through a portal because the target sidebar it is opened from
// scrolls and clips its contents, and a fixed overlay inside that would be
// cut off.
export function RequestLogModal({
  runId,
  nodeId,
  target,
  onClose,
}: {
  runId: string
  nodeId: string
  target: string
  onClose: () => void
}) {
  const [log, setLog] = useState<NodeRequestLog | null>(null)
  const [loadError, setLoadError] = useState('')
  const [detailError, setDetailError] = useState('')
  const [filter, setFilter] = useState('')
  // search holds the server's answer for one quick-search text. It is kept
  // alongside that text so a late answer for an older query is never shown as
  // the result of a newer one.
  const [search, setSearch] = useState<{ q: string; requests: RequestRecord[] } | null>(null)
  const [filters, setFilters] = useState<RequestFilters>(EMPTY_REQUEST_FILTERS)
  const [sort, setSort] = useState<SortState | null>(null)
  const [chainView, setChainView] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  // Full records fetched on expand or send, keyed by request id, so collapsing
  // and re-expanding a row doesn't hit the server again.
  const [details, setDetails] = useState<Record<number, RequestRecord>>({})
  const { openMenu } = useContextMenu()

  useEffect(() => {
    // Ignore a response that lands after the modal has closed or moved on to
    // a different node, so a slow request can't overwrite newer state.
    let cancelled = false
    api
      .listNodeRequests(runId, nodeId)
      .then((l) => {
        if (!cancelled) setLog(l)
      })
      .catch((err) => {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      cancelled = true
    }
  }, [runId, nodeId])

  useEffect(() => {
    // Escape dismisses the modal, the same as the context menu it replaces.
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // Quick search goes to the server, because it matches inside bodies the list
  // doesn't carry. The request waits briefly after typing stops, so each
  // keystroke doesn't start its own search, and a stale answer is dropped.
  useEffect(() => {
    const q = filter.trim()
    if (!q) return
    let cancelled = false
    const timer = window.setTimeout(() => {
      api
        .listNodeRequests(runId, nodeId, q)
        .then((l) => {
          if (!cancelled) setSearch({ q, requests: l.requests })
        })
        .catch((err) => {
          if (!cancelled) setDetailError(err instanceof Error ? err.message : String(err))
        })
    }, 250)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [filter, runId, nodeId])

  // The distinct methods in this log, sorted, so the method filter offers only
  // values that can match.
  const methods = useMemo(() => {
    if (!log) return []
    return [...new Set(log.requests.map((r) => r.method))].sort()
  }, [log])

  // byRef indexes the log by each exchange's ref, so a row can find the request
  // that caused it.
  const byRef = useMemo(() => {
    const m = new Map<string, RequestRecord>()
    for (const r of log?.requests ?? []) if (r.ref) m.set(r.ref, r)
    return m
  }, [log])

  // position numbers each request by where it sits in the log, so the cause
  // column can say "#12" and mean the twelfth request sent.
  const position = useMemo(() => {
    const m = new Map<number, number>()
    ;(log?.requests ?? []).forEach((r, i) => m.set(r.id, i + 1))
    return m
  }, [log])

  // causes counts, for each request, how many requests it caused. A hop with a
  // count is a redirect that was followed.
  const causes = useMemo(() => {
    const m = new Map<number, number>()
    for (const r of log?.requests ?? []) {
      const cause = r.fromRef ? byRef.get(r.fromRef) : undefined
      if (cause) m.set(cause.id, (m.get(cause.id) ?? 0) + 1)
    }
    return m
  }, [log, byRef])

  const q = filter.trim()
  // Quick search is the server's answer for the current text. While a new
  // answer is on its way the previous one stays up, marked as searching.
  const searching = q !== '' && search?.q !== q
  const base = useMemo(() => {
    if (!log) return []
    if (!q) return log.requests
    return search?.requests ?? []
  }, [log, q, search])

  // Column filters narrow the quick-search result (or the whole log), and every
  // active one must match.
  const filtered = useMemo(() => {
    const preds = buildPredicates(filters)
    return base.filter((r) => preds.every((p) => p(r)))
  }, [base, filters])

  // shown is what the table renders: a sorted flat list, or the chain tree. The
  // chain keeps log order, since a sort would break up the parent-child layout.
  const shown = useMemo<ChainRow[]>(
    () => (chainView ? buildChain(filtered, byRef) : sortRecords(filtered, sort).map((row) => ({ row, depth: 0 }))),
    [chainView, filtered, sort, byRef],
  )

  const anyFilter = filter.trim() !== '' || hasActiveFilters(filters)

  // hasChains is false when no request in the log has a cause that is also in
  // the log. Chain view then looks exactly like the flat list, so the view says why.
  const hasChains = useMemo(
    () => (log?.requests ?? []).some((r) => (r.fromRef && byRef.has(r.fromRef)) || (r.callbackCount ?? 0) > 0),
    [log, byRef],
  )

  // setColumn updates one column's filter text, leaving the others alone.
  const setColumn = (column: keyof RequestFilters, value: string) => setFilters((f) => ({ ...f, [column]: value }))

  // clickSort steps a column through ascending, descending, and unsorted.
  const clickSort = (key: SortKey) => setSort((current) => nextSort(current, key))

  // loadDetail returns one row's full exchange, fetching it the first time
  // and reusing the copy kept in details after that.
  const loadDetail = async (id: number): Promise<RequestRecord> => {
    const cached = details[id]
    if (cached) return cached
    const rec = await api.getNodeRequest(runId, nodeId, id)
    setDetails((d) => ({ ...d, [id]: rec }))
    return rec
  }

  // toggle expands or collapses one row and fetches its raw exchange the
  // first time it is opened.
  const toggle = async (id: number) => {
    if (expandedId === id) {
      setExpandedId(null)
      return
    }
    setExpandedId(id)
    try {
      await loadDetail(id)
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : String(err))
    }
  }

  // sendRecordToTester hands a request's method, URL, headers and body to the
  // Tester, then closes this modal so the Tester tab behind it is visible.
  const sendRecordToTester = (rec: RequestRecord) => {
    const { headers, body } = parseRawRequest(rec.requestRaw ?? '')
    sendToTester(rec.url, rec.method, headers, body)
    onClose()
  }

  // sendRowToTester is the right-click action. The row may not have its raw
  // exchange yet, so it is fetched before the handoff.
  const sendRowToTester = async (r: RequestRecord) => {
    try {
      sendRecordToTester(await loadDetail(r.id))
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : String(err))
    }
  }

  // jumpTo brings a request into view from elsewhere in the log, such as the
  // request that caused a row. It clears the filters and quick search that could
  // be hiding it, expands it, and scrolls to it.
  const jumpTo = (target: RequestRecord) => {
    setFilter('')
    setFilters(EMPTY_REQUEST_FILTERS)
    setExpandedId(target.id)
    // The row only exists once React has committed the cleared filters, which
    // happens before this zero-delay timer runs.
    setTimeout(() => document.getElementById(`request-row-${target.id}`)?.scrollIntoView({ block: 'center' }), 0)
    loadDetail(target.id).catch((err) => setDetailError(err instanceof Error ? err.message : String(err)))
  }

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      // Stop right-clicks here from reaching the app-wide fallback menu, so the
      // browser's own menu (for copying selected text) stays available.
      onContextMenu={(e) => e.stopPropagation()}
    >
      <div
        className="flex h-[85vh] w-full max-w-6xl flex-col rounded-lg border border-neutral-700 bg-neutral-900 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
          <h2 className="min-w-0 flex-1 truncate text-xs font-semibold uppercase tracking-wide text-neutral-300">
            Requests — <span className="font-mono normal-case tracking-normal text-neutral-400">{target}</span>
          </h2>
          <button type="button" onClick={onClose} className="text-neutral-500 hover:text-neutral-300" title="Close">
            ✕
          </button>
        </div>

        <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
          <div className="relative min-w-0 flex-1">
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Quick search: URL, method, status, or body…"
              className="w-full rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-xs text-neutral-200 placeholder:text-neutral-600 focus:border-sky-600 focus:outline-none"
            />
            {searching && <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-neutral-500">searching…</span>}
          </div>
          {anyFilter && (
            <button
              type="button"
              onClick={() => {
                setFilter('')
                setFilters(EMPTY_REQUEST_FILTERS)
              }}
              className="shrink-0 text-xs text-neutral-500 hover:text-neutral-300"
            >
              Clear filters
            </button>
          )}
          <button
            type="button"
            aria-pressed={chainView}
            onClick={() => setChainView((v) => !v)}
            title="Nest each request under the request that caused it. Sorting is off while this is on."
            className={`shrink-0 rounded border px-2 py-0.5 text-xs ${
              chainView ? 'border-sky-600 bg-sky-950/40 text-sky-300' : 'border-neutral-700 text-neutral-400 hover:text-neutral-200'
            }`}
          >
            Chain view
          </button>
          <span className="flex shrink-0 items-center gap-1.5 text-xs text-neutral-500">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-orange-500/60" />
            hit
          </span>
          {log && (
            <span className="shrink-0 text-xs text-neutral-500">
              {anyFilter || chainView ? `${shown.length} of ${log.requests.length}` : `${log.requests.length}`} request
              {log.requests.length === 1 ? '' : 's'}
            </span>
          )}
        </div>

        {detailError && <div className="border-b border-red-900/50 bg-red-950/20 px-3 py-1.5 text-xs text-red-300">{detailError}</div>}

        {chainView && log && !hasChains && (
          <div className="border-b border-neutral-800 bg-neutral-950 px-3 py-1.5 text-xs text-neutral-400">
            No request in this log caused another, and no redirect reached a callback. Chains form when a client follows a redirect or a
            redirect's Location reaches the collaborator, so this view matches the flat list.
          </div>
        )}

        <div className="min-h-0 flex-1 overflow-auto">
          {loadError ? (
            <p className="p-4 text-xs text-red-300">{loadError}</p>
          ) : !log ? (
            <p className="p-4 text-xs text-neutral-500">Loading…</p>
          ) : log.requests.length === 0 ? (
            // Explains the empty case rather than leaving the view looking broken.
            // External tools run as separate processes, so their traffic is never
            // seen by Aperture's transport and can't appear here.
            <p className="p-4 text-xs leading-relaxed text-neutral-500">
              No requests were recorded for this target. Traffic from external tools such as feroxbuster, ffuf, katana, and nuclei runs as a
              separate process and isn't captured.
            </p>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-neutral-900 text-left text-neutral-500">
                <tr>
                  <th className="px-3 py-1.5 font-medium">#</th>
                  <SortHeader label="Method" sortKey="method" sort={sort} disabled={chainView} onSort={clickSort} />
                  <SortHeader label="Status" sortKey="status" sort={sort} disabled={chainView} onSort={clickSort} />
                  <th className="px-3 py-1.5 font-medium">From</th>
                  <SortHeader label="URL" sortKey="url" sort={sort} disabled={chainView} onSort={clickSort} />
                  <SortHeader label="Size" sortKey="size" sort={sort} disabled={chainView} onSort={clickSort} align="right" />
                  <SortHeader label="Time" sortKey="time" sort={sort} disabled={chainView} onSort={clickSort} align="right" />
                  <SortHeader label="Sent" sortKey="sent" sort={sort} disabled={chainView} onSort={clickSort} align="right" />
                </tr>
                <tr className="border-b border-neutral-800">
                  <th className="px-2 pb-1.5 font-normal" />
                  <th className="px-2 pb-1.5 font-normal">
                    <select
                      value={filters.method}
                      onChange={(e) => setColumn('method', e.target.value)}
                      className={filterInputClass(false)}
                    >
                      <option value="">All</option>
                      {methods.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                  </th>
                  <th className="px-2 pb-1.5 font-normal">
                    <FilterInput
                      value={filters.status}
                      invalid={isInvalidFilter('status', filters.status)}
                      placeholder="200, 2xx, >=400"
                      onChange={(v) => setColumn('status', v)}
                    />
                  </th>
                  <th className="px-2 pb-1.5 font-normal" />
                  <th className="px-2 pb-1.5 font-normal">
                    <FilterInput value={filters.url} placeholder="contains…" onChange={(v) => setColumn('url', v)} />
                  </th>
                  <th className="px-2 pb-1.5 font-normal">
                    <FilterInput
                      value={filters.size}
                      invalid={isInvalidFilter('size', filters.size)}
                      placeholder=">1kb"
                      align="right"
                      onChange={(v) => setColumn('size', v)}
                    />
                  </th>
                  <th className="px-2 pb-1.5 font-normal">
                    <FilterInput
                      value={filters.time}
                      invalid={isInvalidFilter('time', filters.time)}
                      placeholder=">500ms"
                      align="right"
                      onChange={(v) => setColumn('time', v)}
                    />
                  </th>
                  <th className="px-2 pb-1.5 font-normal">
                    <FilterInput
                      value={filters.sent}
                      invalid={isInvalidFilter('sent', filters.sent)}
                      placeholder="14:00-14:05"
                      align="right"
                      onChange={(v) => setColumn('sent', v)}
                    />
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map(({ row: r, depth, callbacks }) => {
                  if (callbacks !== undefined) {
                    // The callback row of a redirect. It isn't a request, so it has no
                    // click target and no cells beyond its label.
                    return (
                      <tr key={`callback-${r.id}`} className="border-t border-neutral-800 bg-sky-950/10">
                        <td colSpan={8} className="px-3 py-1.5 text-sky-300" style={{ paddingLeft: `${12 + depth * 16}px` }}>
                          <span className="mr-1 text-neutral-600">↳</span>
                          collaborator callback ×{callbacks}
                          <span className="ml-2 text-neutral-500">from the redirect #{position.get(r.id)} above</span>
                        </td>
                      </tr>
                    )
                  }
                  const hit = isHit(r)
                  const cause = r.fromRef ? byRef.get(r.fromRef) : undefined
                  const caused = causes.get(r.id) ?? 0
                  // Rows with an open detail keep the selected tint; hits keep
                  // their orange so they stay findable while expanded.
                  const rowTone = hit
                    ? 'bg-orange-500/10 hover:bg-orange-500/20'
                    : expandedId === r.id
                      ? 'bg-neutral-800/40'
                      : 'hover:bg-neutral-800/50'
                  return (
                    <Fragment key={r.id}>
                      <tr
                        id={`request-row-${r.id}`}
                        onClick={() => toggle(r.id)}
                        onContextMenu={(e) => {
                          // Handled here, so the app-wide fallback menu doesn't replace this one.
                          e.stopPropagation()
                          openMenu(e, [{ label: 'Send to Tester', onSelect: () => void sendRowToTester(r) }])
                        }}
                        className={`cursor-pointer border-t border-neutral-800 ${rowTone}`}
                      >
                        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px] text-neutral-500">
                          #{position.get(r.id)}
                          {caused > 0 && (
                            <span className="ml-1.5 text-sky-500" title={`Caused ${caused} later request${caused === 1 ? '' : 's'}`}>
                              →{caused}
                            </span>
                          )}
                        </td>
                        <td
                          className="px-3 py-1.5 font-mono text-neutral-300"
                          // A left bar marks hits too, so they still show when the row is scrolled.
                          style={hit ? { boxShadow: 'inset 3px 0 0 #f97316' } : undefined}
                        >
                          {r.method}
                        </td>
                        <td className="px-3 py-1.5 font-mono" style={{ color: r.error ? '#f87171' : statusHexColor(r.statusCode) }}>
                          {r.error ? 'error' : r.statusCode}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[11px]">
                          {cause ? (
                            <button
                              type="button"
                              onClick={(e) => {
                                // Keep this click from also toggling the row.
                                e.stopPropagation()
                                jumpTo(cause)
                              }}
                              className="text-sky-400 hover:text-sky-300"
                              title={`${cause.statusCode} ${cause.method} ${cause.url}`}
                            >
                              ↩ #{position.get(cause.id)}
                            </button>
                          ) : r.fromRef ? (
                            <span className="text-neutral-600" title="The request that caused this one isn't in this log">
                              ↩ ?
                            </span>
                          ) : (
                            <span className="text-neutral-700">—</span>
                          )}
                        </td>
                        <td
                          className={`max-w-0 w-full truncate px-3 py-1.5 font-mono ${hit ? 'text-orange-200' : 'text-neutral-200'}`}
                          style={depth > 0 ? { paddingLeft: `${12 + depth * 16}px` } : undefined}
                          title={r.url}
                        >
                          {depth > 0 && <span className="mr-1 text-neutral-600">↳</span>}
                          {(r.callbackCount ?? 0) > 0 && (
                            <span
                              className="mr-2 rounded border border-sky-800 px-1 text-[10px] text-sky-300"
                              title="Collaborator hits this redirect's Location led to"
                            >
                              callback ×{r.callbackCount}
                            </span>
                          )}
                          {r.url}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5 text-right text-neutral-400">{formatBytes(r.size)}</td>
                        <td className="whitespace-nowrap px-3 py-1.5 text-right text-neutral-400">{r.error ? '—' : `${r.ttfbMs} ms`}</td>
                        <td className="whitespace-nowrap px-3 py-1.5 text-right text-neutral-500">{new Date(r.timestamp).toLocaleTimeString()}</td>
                      </tr>
                      {expandedId === r.id && (
                        <tr className="border-t border-neutral-800 bg-neutral-950">
                          <td colSpan={8} className="p-3">
                            <ExchangeDetail
                              record={details[r.id]}
                              source={details[r.id]?.fromRef ? byRef.get(details[r.id].fromRef!) : undefined}
                              onSendToTester={sendRecordToTester}
                              onJump={jumpTo}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
                {log.requests.length > 0 && shown.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-3 py-4 text-center text-neutral-500">
                      No requests match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {log && log.requests.length >= log.limit && (
          // Reaching the cap means later requests were never stored, so the list
          // is a prefix of the real traffic and the UI must say so.
          <div className="border-t border-amber-900/50 bg-amber-950/20 px-3 py-1.5 text-xs text-amber-200">
            This log is capped at {log.limit.toLocaleString()} requests per target; anything after that wasn't recorded.
          </div>
        )}
      </div>
    </div>,
    document.body,
  )
}

// ChainRow is one visible request in the chain view, with how many hops it sits
// below the request that caused it. A top-level request has depth 0.
interface ChainRow {
  row: RequestRecord
  depth: number
  // callbacks is set on the synthetic row that stands for collaborator hits a
  // redirect led to. It has no request of its own, so row is the redirect.
  callbacks?: number
}

// buildChain arranges the visible requests as a tree. Each request sits directly
// under the request whose redirect led to it, one step deeper per hop. A request
// whose cause isn't in the visible list (it was filtered out, or was never
// logged) starts a new tree at the top, so no request disappears when a filter
// hides its cause. The list is in log order, so siblings stay in the order sent.
function buildChain(list: RequestRecord[], byRef: Map<string, RequestRecord>): ChainRow[] {
  const shownIds = new Set(list.map((r) => r.id))
  const children = new Map<number, RequestRecord[]>()
  const roots: RequestRecord[] = []
  // Each request is either a root or the child of exactly one visible request,
  // so every row is placed once.
  for (const r of list) {
    const cause = r.fromRef ? byRef.get(r.fromRef) : undefined
    if (cause && shownIds.has(cause.id)) {
      children.set(cause.id, [...(children.get(cause.id) ?? []), r])
    } else {
      roots.push(r)
    }
  }
  const out: ChainRow[] = []
  // walk adds a request, then every request it caused, depth first. A cause always
  // comes earlier in the log than its effects, so the recursion can't loop.
  const walk = (row: RequestRecord, depth: number) => {
    out.push({ row, depth })
    // A redirect that reached the collaborator gets a row for the callback under
    // it, before anything the client sent next.
    if (row.callbackCount) out.push({ row, depth: depth + 1, callbacks: row.callbackCount })
    for (const c of children.get(row.id) ?? []) walk(c, depth + 1)
  }
  for (const r of roots) walk(r, 0)
  return out
}

// SortHeader is a column label that sorts the table when clicked. The arrow
// shows the active direction, and a faint double arrow marks a sortable column
// that isn't the active one.
function SortHeader({
  label,
  sortKey,
  sort,
  disabled,
  onSort,
  align = 'left',
}: {
  label: string
  sortKey: SortKey
  sort: SortState | null
  disabled: boolean
  onSort: (key: SortKey) => void
  align?: 'left' | 'right'
}) {
  const active = sort?.key === sortKey
  const arrow = active ? (sort.dir === 'asc' ? '▲' : '▼') : '↕'
  return (
    <th
      className="px-3 py-1.5 font-medium"
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        type="button"
        disabled={disabled}
        onClick={() => onSort(sortKey)}
        title={disabled ? 'Sorting is off in chain view' : `Sort by ${label.toLowerCase()}`}
        className={`flex w-full items-center gap-1 hover:text-neutral-300 disabled:cursor-default disabled:hover:text-neutral-500 ${
          align === 'right' ? 'justify-end' : ''
        } ${active ? 'text-neutral-200' : ''}`}
      >
        {label}
        <span className={`text-[10px] ${active ? 'text-sky-400' : 'text-neutral-700'}`}>{arrow}</span>
      </button>
    </th>
  )
}

// filterInputClass styles a column filter. An input whose text didn't parse gets
// a red border so the user can see why it isn't narrowing the list.
function filterInputClass(invalid: boolean, align: 'left' | 'right' = 'left'): string {
  return `w-full min-w-0 rounded border bg-neutral-950 px-1.5 py-0.5 font-mono text-[11px] text-neutral-200 placeholder:text-neutral-600 focus:outline-none ${
    invalid ? 'border-red-700 focus:border-red-500' : 'border-neutral-700 focus:border-sky-600'
  } ${align === 'right' ? 'text-right' : ''}`
}

// FilterInput is one column's text filter. align right-justifies the text for
// the numeric columns so it lines up with the values under it.
function FilterInput({
  value,
  onChange,
  placeholder,
  invalid = false,
  align = 'left',
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  invalid?: boolean
  align?: 'left' | 'right'
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      title={invalid ? 'Not a valid filter; it is ignored until it parses' : undefined}
      className={filterInputClass(invalid, align)}
    />
  )
}

// ExchangeDetail shows one expanded request: which request caused it and a Send
// to Tester action, then the raw request on the left and the raw response on the
// right, each with its own copy button. A failed request has no response, so it
// shows the error in place of the response pane.
function ExchangeDetail({
  record,
  source,
  onSendToTester,
  onJump,
}: {
  record: RequestRecord | undefined
  source: RequestRecord | undefined
  onSendToTester: (rec: RequestRecord) => void
  onJump: (rec: RequestRecord) => void
}) {
  if (!record) return <p className="text-xs text-neutral-500">Loading…</p>
  const panes = record.error ? (
    <div className="space-y-2">
      <p className="text-xs text-red-300">{record.error}</p>
      <Pane title="Request" text={record.requestRaw ?? ''} />
    </div>
  ) : (
    <div className="grid gap-3 lg:grid-cols-2">
      <Pane title="Request" text={record.requestRaw ?? ''} />
      <Pane title="Response" text={record.responseRaw ?? ''} />
    </div>
  )
  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 text-xs text-neutral-400">
          {record.fromRef && (
            <>
              Caused by{' '}
              {source ? (
                <>
                  <span className="font-mono" style={{ color: statusHexColor(source.statusCode) }}>
                    {source.statusCode}
                  </span>{' '}
                  <span className="break-all font-mono text-neutral-300">
                    {source.method} {source.url}
                  </span>{' '}
                  <button type="button" onClick={() => onJump(source)} className="text-sky-400 hover:text-sky-300">
                    Show
                  </button>
                </>
              ) : (
                <span className="text-neutral-500">a request that isn't in this log</span>
              )}
            </>
          )}
        </div>
        <button
          type="button"
          onClick={() => onSendToTester(record)}
          className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
        >
          Send to Tester
        </button>
      </div>
      {record.location && (
        <div className="break-all text-xs text-neutral-400">
          Redirects to <span className="font-mono text-neutral-300">{record.location}</span>
        </div>
      )}
      {(record.callbacks?.length ?? 0) > 0 && (
        <div className="rounded border border-sky-900/60 bg-sky-950/20 p-2 text-xs">
          <div className="mb-1 font-semibold text-sky-300">Collaborator callbacks ({record.callbacks!.length})</div>
          {record.callbacks!.map((c) => (
            <div key={c.id} className="font-mono text-[11px] text-neutral-300">
              {new Date(c.timestamp).toLocaleTimeString()} {c.protocol} {c.method ?? ''} {c.path ?? ''}
              {c.query ? `?${c.query}` : ''} from {c.remoteAddr}
              {c.identifier ? <span className="text-neutral-500"> [{c.identifier}]</span> : null}
            </div>
          ))}
        </div>
      )}
      {panes}
    </div>
  )
}

// Pane is one labeled, scrollable block of raw HTTP text with a copy button.
function Pane({ title, text }: { title: string; text: string }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wide text-neutral-500">{title}</span>
        <CopyButton text={text} />
      </div>
      <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border border-neutral-800 bg-neutral-900 p-2 font-mono text-[11px] text-neutral-300">
        {text || '(empty)'}
      </pre>
    </div>
  )
}

// formatBytes renders a byte count in the largest unit that keeps it under
// 1024, with one decimal place above bytes.
function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}
