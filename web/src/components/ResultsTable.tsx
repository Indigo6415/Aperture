import { Fragment, useMemo, useState } from 'react'
import type { Finding, TriageStatus } from '../types'
import { statusHexColor } from '../statusColor'
import { extensionOf, hostnameOf } from '../url'
import { isDangerousExtension } from '../extensions'
import { api, screenshotPreviewEnabled } from '../api'
import { FacetFilterBar, type FacetDimension } from './FacetFilterBar'
import { copyToClipboard, useContextMenu } from '../contextMenu'
import { sendToJwtScanner } from '../jwtHandoff'
import { sendToProbe } from '../probeHandoff'
import { sendToSecretScan } from '../secretScanHandoff'
import { sendToBypass403 } from '../bypass403Handoff'
import { sendToTester } from '../testerHandoff'
import { showToast } from '../toast'

type SortKey = 'url' | 'statusCode' | 'extension' | 'contentLength' | 'words' | 'lines' | 'sourceTool' | 'triageStatus'

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: 'statusCode', label: 'Status' },
  { key: 'url', label: 'URL' },
  { key: 'extension', label: 'Ext' },
  { key: 'contentLength', label: 'Size' },
  { key: 'words', label: 'Words' },
  { key: 'lines', label: 'Lines' },
  { key: 'sourceTool', label: 'Tool' },
  { key: 'triageStatus', label: 'Triage' },
]

// TRIAGE_META is one consistent label/color per triage status, for the
// per-row dropdown and the facet filter's badges alike.
const TRIAGE_META: Record<TriageStatus, { label: string; cls: string }> = {
  new: { label: 'New', cls: 'border-neutral-700 bg-neutral-900 text-neutral-400' },
  confirmed: { label: 'Confirmed', cls: 'border-red-700 bg-red-950/40 text-red-300' },
  false_positive: { label: 'False positive', cls: 'border-neutral-800 bg-neutral-900 text-neutral-600' },
  reported: { label: 'Reported', cls: 'border-emerald-700 bg-emerald-950/40 text-emerald-300' },
}

// triageMetaOf falls back to TRIAGE_META.new for any status TRIAGE_META
// doesn't recognize -- a finding streamed live over the websocket the
// instant a job emits it, before a round trip through the store, so it's
// worth not trusting f.triageStatus to always be one of the four known
// values here.
function triageMetaOf(status: TriageStatus): { label: string; cls: string } {
  return TRIAGE_META[status] ?? TRIAGE_META.new
}

// sortValueOf reads the value a given SortKey sorts by -- a plain property
// for everything but 'extension', which isn't a Finding field and has to
// be derived from the URL the same way the Ext column/facet do.
function sortValueOf(f: Finding, key: SortKey): string | number {
  return key === 'extension' ? (extensionOf(f.url) ?? '') : f[key]
}

// statusTextClass is the Tailwind-class counterpart to statusHexColor, for
// table cells (which use a class) rather than inline-styled chips/badges.
function statusTextClass(code: number): string {
  if (code >= 200 && code < 300) return 'text-emerald-400'
  if (code >= 300 && code < 400) return 'text-sky-400'
  if (code >= 400 && code < 500) return 'text-amber-400'
  if (code >= 500) return 'text-red-400'
  return 'text-neutral-400'
}

// extensionOf returns undefined for paths with no extension, but that's a
// real, common, filterable category here (most brute-forced paths have no
// extension) -- unlike the size/words/lines dimensions, where "undefined"
// means "not applicable to this row" and should always pass through. So
// this dimension maps it to an explicit "none" value instead of leaving it
// undefined, and drops FacetFilterBar's blanket "missing value always
// passes" behavior for that value alone.
const NO_EXTENSION = '(none)'

const FINDING_DIMENSIONS: FacetDimension<Finding>[] = [
  { key: 'statusCode', label: 'Status', getValue: (f) => f.statusCode, colorFor: (v) => statusHexColor(Number(v)) },
  {
    key: 'extension',
    label: 'Extension',
    getValue: (f) => extensionOf(f.url) ?? NO_EXTENSION,
    warningFor: (v) => isDangerousExtension(String(v)),
  },
  { key: 'contentLength', label: 'Size', getValue: (f) => f.contentLength },
  { key: 'words', label: 'Words', getValue: (f) => f.words },
  { key: 'lines', label: 'Lines', getValue: (f) => f.lines },
  { key: 'triageStatus', label: 'Triage', getValue: (f) => triageMetaOf(f.triageStatus).label },
]

// rowKey uniquely identifies a finding within one ResultsTable -- the same
// key scheme the row's React key already used, reused here to track which
// row is currently expanded.
function rowKey(f: Finding): string {
  return `${f.sourceNodeId}:${f.id}`
}

// defaultTargetValue is what a checked row promotes to when the caller
// doesn't override it: the finding's hostname, or its full URL if it has
// none (e.g. a malformed entry) -- good enough for ffuf subdomain/vhost
// results, where the hostname is the thing worth re-scanning. A caller
// scanning for re-scannable paths (feroxbuster) overrides this with the
// full URL instead.
function defaultTargetValue(f: Finding): string {
  return hostnameOf(f.url) ?? f.url
}

export function ResultsTable({
  findings,
  caseId,
  facetPlacement = 'top',
  selectable = false,
  deriveTargetValue = defaultTargetValue,
  onPromote,
}: {
  findings: Finding[]
  caseId?: string
  // 'right' puts the FacetFilterBar in a sidebar next to the table instead
  // of a row above it -- used by the Content Discovery tab, which also
  // wants room above the table for its per-target progress panel.
  facetPlacement?: 'top' | 'right'
  // selectable renders a checkbox column plus a "Save selected to case"
  // toolbar action -- the promote-to-target flow. Off by default so a
  // caller with no case context (there currently is none, but this keeps
  // the component safe to reuse without a case) doesn't get a dead button.
  selectable?: boolean
  // deriveTargetValue is what a checked row promotes to -- defaults to the
  // finding's hostname (right for ffuf subdomain/vhost results); a caller
  // scanning for re-scannable paths (feroxbuster) overrides this to the
  // full URL.
  deriveTargetValue?: (f: Finding) => string
  onPromote?: (values: string[]) => Promise<void> | void
}) {
  // The Preview column only makes sense while the screenshot preview
  // feature is enabled -- otherwise every thumbnail would just be a
  // permanent placeholder for images the backend never captures.
  const showPreview = Boolean(caseId) && screenshotPreviewEnabled
  const extraCols = (selectable ? 1 : 0) + (showPreview ? 1 : 0)
  const { openMenu } = useContextMenu()
  // triageOverrides holds this component's own optimistic view of a
  // finding's triage status/note, keyed by finding.id -- the persisted
  // value only ever refreshes from the server on the next full findings
  // fetch (job re-run, tab reopen), so an edit here has to be layered on
  // top of the `findings` prop rather than waiting on it.
  const [triageOverrides, setTriageOverrides] = useState<Record<string, { status: TriageStatus; note: string }>>({})
  const annotated = useMemo(
    () =>
      findings.map((f) => {
        const o = triageOverrides[f.id]
        return o ? { ...f, triageStatus: o.status, triageNote: o.note || undefined } : f
      }),
    [findings, triageOverrides],
  )
  const [faceted, setFaceted] = useState<Finding[]>(annotated)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('statusCode')
  const [sortDir, setSortDir] = useState<1 | -1>(1)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [promoting, setPromoting] = useState(false)

  // updateTriage applies immediately (so the dropdown/note feel instant)
  // and rolls back if the save fails -- a finding's triage state otherwise
  // has nowhere else to live client-side.
  const updateTriage = async (f: Finding, status: TriageStatus, note: string) => {
    setTriageOverrides((prev) => ({ ...prev, [f.id]: { status, note } }))
    try {
      await api.updateFindingTriage(f.id, status, note || undefined)
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
      setTriageOverrides((prev) => {
        const next = { ...prev }
        delete next[f.id]
        return next
      })
    }
  }

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const filtered = needle
      ? faceted.filter(
          (f) => f.url.toLowerCase().includes(needle) || String(f.statusCode).includes(needle) || f.sourceTool.toLowerCase().includes(needle),
        )
      : faceted
    return [...filtered].sort((a, b) => {
      const av = sortValueOf(a, sortKey)
      const bv = sortValueOf(b, sortKey)
      const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv))
      return cmp * sortDir
    })
  }, [faceted, search, sortKey, sortDir])

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setSortDir((d) => (d === 1 ? -1 : 1))
    else {
      setSortKey(key)
      setSortDir(1)
    }
  }

  const toggleChecked = (key: string) => {
    setChecked((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const allVisibleChecked = rows.length > 0 && rows.every((f) => checked.has(rowKey(f)))
  const toggleAllVisible = () => {
    setChecked((prev) => {
      const next = new Set(prev)
      if (allVisibleChecked) rows.forEach((f) => next.delete(rowKey(f)))
      else rows.forEach((f) => next.add(rowKey(f)))
      return next
    })
  }

  const promoteSelected = async () => {
    if (!onPromote || checked.size === 0) return
    setPromoting(true)
    try {
      const values = [...new Set(rows.filter((f) => checked.has(rowKey(f))).map(deriveTargetValue))]
      await onPromote(values)
      setChecked(new Set())
    } finally {
      setPromoting(false)
    }
  }

  const facetBar = (
    <FacetFilterBar
      items={annotated}
      dimensions={FINDING_DIMENSIONS}
      onChange={setFaceted}
      restrictStatusByDefault
      orientation={facetPlacement === 'right' ? 'column' : 'row'}
    />
  )

  const body = (
    <>
      <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
        <input
          className="w-64 rounded border border-neutral-700 bg-neutral-800 px-2 py-1 text-sm text-neutral-100 outline-none focus:border-sky-500"
          placeholder="Search URL, status, tool…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <span className="text-xs text-neutral-500">
          {rows.length} of {findings.length} finding{findings.length === 1 ? '' : 's'}
        </span>
        {selectable && (
          <button
            onClick={promoteSelected}
            disabled={promoting || checked.size === 0}
            className="ml-auto rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {promoting ? 'Saving…' : `Save selected to case (${checked.size})`}
          </button>
        )}
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-neutral-950">
            <tr>
              {selectable && (
                <th className="w-8 border-b border-neutral-800 px-3 py-2">
                  <input type="checkbox" checked={allVisibleChecked} onChange={toggleAllVisible} className="accent-sky-500" />
                </th>
              )}
              {showPreview && (
                <th className="border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500">Preview</th>
              )}
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  onClick={() => toggleSort(col.key)}
                  className="cursor-pointer select-none whitespace-nowrap border-b border-neutral-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-neutral-500 hover:text-neutral-300"
                >
                  {col.label}
                  {sortKey === col.key && (sortDir === 1 ? ' ▲' : ' ▼')}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const ext = extensionOf(f.url)
              const dangerous = isDangerousExtension(ext)
              const key = rowKey(f)
              const isExpanded = expanded === key
              return (
                <Fragment key={key}>
                  <tr
                    onClick={() => setExpanded(isExpanded ? null : key)}
                    onContextMenu={(e) => {
                      e.stopPropagation()
                      openMenu(e, [
                        { label: 'Copy URL', onSelect: () => copyToClipboard(f.url, 'Copied URL') },
                        { label: 'Open in new tab', onSelect: () => window.open(f.url, '_blank', 'noopener,noreferrer') },
                        { label: 'Send to JWT', onSelect: () => sendToJwtScanner(f.url) },
                        { label: 'Send to Probe', onSelect: () => sendToProbe(f.url) },
                        { label: 'Send to Secrets', onSelect: () => sendToSecretScan(f.url) },
                        { label: 'Send to 403 Bypass', onSelect: () => sendToBypass403(f.url) },
                        { label: 'Send to Tester', onSelect: () => sendToTester(f.url, f.method || 'GET', f.headers) },
                        'separator',
                        { label: isExpanded ? 'Collapse details' : 'Expand details', onSelect: () => setExpanded(isExpanded ? null : key) },
                      ])
                    }}
                    className={`cursor-pointer border-b border-neutral-900 hover:bg-neutral-900/60 ${dangerous ? 'bg-red-950/20' : ''} ${isExpanded ? 'bg-neutral-900/80' : ''}`}
                  >
                    {selectable && (
                      <td className="px-3 py-1.5" onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={checked.has(key)} onChange={() => toggleChecked(key)} className="accent-sky-500" />
                      </td>
                    )}
                    {caseId && screenshotPreviewEnabled && (
                      <td className="px-3 py-1.5">
                        <Thumbnail caseId={caseId} target={hostnameOf(f.url)} />
                      </td>
                    )}
                    <td className={`px-3 py-1.5 font-mono ${statusTextClass(f.statusCode)}`}>{f.statusCode}</td>
                    <td className="max-w-[480px] truncate px-3 py-1.5 font-mono text-neutral-200" title={f.url}>
                      <span className="mr-1 inline-block w-3 text-neutral-600">{isExpanded ? '▾' : '▸'}</span>
                      {dangerous && (
                        <span className="mr-1" title={`Potentially sensitive .${ext} file`}>
                          ⚠️
                        </span>
                      )}
                      {f.url}
                      <a
                        href={f.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        title="Open in new tab"
                        className="ml-1.5 text-neutral-600 hover:text-sky-400"
                      >
                        ↗
                      </a>
                    </td>
                    <td className={`px-3 py-1.5 font-mono text-xs ${dangerous ? 'font-semibold text-red-400' : 'text-neutral-500'}`}>{ext ?? '—'}</td>
                    <td className="px-3 py-1.5 text-neutral-400">{f.contentLength}</td>
                    <td className="px-3 py-1.5 text-neutral-400">{f.words}</td>
                    <td className="px-3 py-1.5 text-neutral-400">{f.lines}</td>
                    <td className="px-3 py-1.5 text-neutral-500">{f.sourceTool}</td>
                    <td className="px-3 py-1.5" onClick={(e) => e.stopPropagation()}>
                      <select
                        value={f.triageStatus in TRIAGE_META ? f.triageStatus : 'new'}
                        onChange={(e) => updateTriage(f, e.target.value as TriageStatus, f.triageNote ?? '')}
                        className={`rounded border px-1.5 py-0.5 text-[11px] font-medium outline-none ${triageMetaOf(f.triageStatus).cls}`}
                      >
                        {(Object.keys(TRIAGE_META) as TriageStatus[]).map((s) => (
                          <option key={s} value={s}>
                            {TRIAGE_META[s].label}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="border-b border-neutral-900 bg-neutral-950/60">
                      <td colSpan={COLUMNS.length + extraCols} className="px-3 py-3">
                        <FindingDetail finding={f} onTriageChange={(note) => updateTriage(f, f.triageStatus, note)} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={COLUMNS.length + extraCols} className="px-3 py-8 text-center text-neutral-600">
                  No findings yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )

  if (facetPlacement === 'right') {
    return (
      <div className="flex h-full overflow-hidden">
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">{body}</div>
        <div className="w-72 shrink-0 overflow-y-auto border-l border-neutral-800">{facetBar}</div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      {facetBar}
      {body}
    </div>
  )
}

// FindingDetail is the row a click on a finding expands into -- everything
// about that one request/response beyond what fits in the table's columns.
// Headers/redirect target are only present for tools that surface them
// (currently feroxbuster; ffuf's live text output doesn't carry headers),
// so those sections just don't render for a finding that has none.
function FindingDetail({ finding: f, onTriageChange }: { finding: Finding; onTriageChange: (note: string) => void }) {
  const headerEntries = f.headers ? Object.entries(f.headers) : []
  const [note, setNote] = useState(f.triageNote ?? '')
  // The note field is uncontrolled from the server's perspective until
  // Save is pressed -- resync it whenever a different finding's row (or an
  // update from elsewhere, e.g. a status-only edit) hands this a new value.
  // Done during render, comparing against the last values seen, so the
  // resync doesn't need a second render pass from an effect.
  const [synced, setSynced] = useState({ id: f.id, triageNote: f.triageNote })
  if (synced.id !== f.id || synced.triageNote !== f.triageNote) {
    setSynced({ id: f.id, triageNote: f.triageNote })
    setNote(f.triageNote ?? '')
  }

  return (
    <div className="flex flex-col gap-3 font-mono text-xs">
      <div className="flex items-center gap-2">
        <a href={f.url} target="_blank" rel="noopener noreferrer" className="break-all text-sky-400 hover:underline">
          {f.url}
        </a>
        <a
          href={f.url}
          target="_blank"
          rel="noopener noreferrer"
          className="shrink-0 rounded border border-neutral-700 px-1.5 py-0.5 text-neutral-300 hover:border-sky-500 hover:text-sky-400"
        >
          Open ↗
        </a>
        <button
          onClick={() => sendToTester(f.url, f.method || 'GET', f.headers)}
          className="shrink-0 rounded border border-neutral-700 px-1.5 py-0.5 text-neutral-300 hover:border-sky-500 hover:text-sky-400"
        >
          Send to Tester
        </button>
      </div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-3">
        <DetailField label="Method" value={f.method || 'GET'} />
        <DetailField label="Status" value={String(f.statusCode)} />
        <DetailField label="Content-Type" value={f.contentType} />
        <DetailField label="Content length" value={`${f.contentLength} bytes`} />
        <DetailField label="Words / Lines" value={`${f.words} / ${f.lines}`} />
        <DetailField label="Redirects to" value={f.redirectLocation} />
        <DetailField label="Tool" value={f.sourceTool} />
        <DetailField label="Timestamp" value={new Date(f.timestamp).toLocaleString()} />
      </div>
      {headerEntries.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Response headers</p>
          <div className="divide-y divide-neutral-900 rounded border border-neutral-800">
            {headerEntries.map(([name, value]) => (
              <div key={name} className="flex gap-2 px-2 py-1">
                <span className="w-40 shrink-0 text-neutral-500">{name}</span>
                <span className="break-all text-neutral-300">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      <div onClick={(e) => e.stopPropagation()}>
        <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-neutral-500">Triage note</p>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={2}
          placeholder="Why this is/isn't a real finding, follow-up needed, ..."
          className="w-full rounded border border-neutral-700 bg-neutral-950 px-2 py-1 font-sans text-xs text-neutral-200 outline-none focus:border-sky-500"
        />
        <button
          onClick={() => onTriageChange(note)}
          disabled={note === (f.triageNote ?? '')}
          className="mt-1 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Save note
        </button>
      </div>
    </div>
  )
}

function DetailField({ label, value }: { label: string; value?: string }) {
  if (!value) return null
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">{label}</p>
      <p className="text-neutral-200">{value}</p>
    </div>
  )
}

// Thumbnail renders a small preview of a finding's host, captured
// opportunistically by the backend (see api.captureScreenshot) once that
// host's HTTP recon check resolves a live URL. A host with none yet (still
// capturing, or no headless-Chrome-compatible browser installed) renders
// nothing rather than a broken-image icon.
export function Thumbnail({ caseId, target }: { caseId: string; target?: string }) {
  const [failed, setFailed] = useState(false)
  if (!target || failed) return <div className="h-8 w-12 rounded bg-neutral-900" />
  return (
    <img
      src={api.screenshotUrl(caseId, target)}
      onError={() => setFailed(true)}
      loading="lazy"
      className="h-8 w-12 rounded-sm object-cover object-top"
      alt=""
    />
  )
}
