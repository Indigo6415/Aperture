import { useMemo, useState } from 'react'
import type { Finding } from '../types'

type SortKey = 'url' | 'statusCode' | 'contentLength' | 'words' | 'lines' | 'sourceTool'

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: 'statusCode', label: 'Status' },
  { key: 'url', label: 'URL' },
  { key: 'contentLength', label: 'Size' },
  { key: 'words', label: 'Words' },
  { key: 'lines', label: 'Lines' },
  { key: 'sourceTool', label: 'Tool' },
]

function statusColor(code: number): string {
  if (code >= 200 && code < 300) return 'text-emerald-400'
  if (code >= 300 && code < 400) return 'text-sky-400'
  if (code >= 400 && code < 500) return 'text-amber-400'
  if (code >= 500) return 'text-red-400'
  return 'text-neutral-400'
}

export function ResultsTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('statusCode')
  const [sortDir, setSortDir] = useState<1 | -1>(1)

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const filtered = needle
      ? findings.filter(
          (f) => f.url.toLowerCase().includes(needle) || String(f.statusCode).includes(needle) || f.sourceTool.toLowerCase().includes(needle),
        )
      : findings
    return [...filtered].sort((a, b) => {
      const av = a[sortKey]
      const bv = b[sortKey]
      const cmp = typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv))
      return cmp * sortDir
    })
  }, [findings, filter, sortKey, sortDir])

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setSortDir((d) => (d === 1 ? -1 : 1))
    else {
      setSortKey(key)
      setSortDir(1)
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
        <input
          className="w-64 rounded border border-neutral-700 bg-neutral-800 px-2 py-1 text-sm text-neutral-100 outline-none focus:border-sky-500"
          placeholder="Filter by URL, status, tool…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="text-xs text-neutral-500">
          {rows.length} of {findings.length} finding{findings.length === 1 ? '' : 's'}
        </span>
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-neutral-950">
            <tr>
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
            {rows.map((f) => (
              <tr key={`${f.sourceNodeId}:${f.id}`} className="border-b border-neutral-900 hover:bg-neutral-900/60">
                <td className={`px-3 py-1.5 font-mono ${statusColor(f.statusCode)}`}>{f.statusCode}</td>
                <td className="max-w-[520px] truncate px-3 py-1.5 font-mono text-neutral-200" title={f.url}>
                  {f.url}
                </td>
                <td className="px-3 py-1.5 text-neutral-400">{f.contentLength}</td>
                <td className="px-3 py-1.5 text-neutral-400">{f.words}</td>
                <td className="px-3 py-1.5 text-neutral-400">{f.lines}</td>
                <td className="px-3 py-1.5 text-neutral-500">{f.sourceTool}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={COLUMNS.length} className="px-3 py-8 text-center text-neutral-600">
                  No findings yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
