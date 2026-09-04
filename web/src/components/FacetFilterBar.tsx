import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'

export type FacetValue = string | number

export interface FacetDimension<T> {
  key: string
  label: string
  getValue: (item: T) => FacetValue | undefined
  colorFor?: (value: FacetValue) => string
  // warningFor flags a value as worth calling out (e.g. a dangerous file
  // extension) -- rendered with its own color + a warning glyph regardless
  // of whether it's currently an active tag.
  warningFor?: (value: FacetValue) => boolean
}

// MAX_SUGGESTIONS caps how many distinct values feed each dimension's
// autocomplete <datalist> -- a soft cap for DOM size on a dimension with
// hundreds of distinct values, not a visibility limit like the old
// button-grid had (every distinct value can still be typed and matched
// even past this cap).
const MAX_SUGGESTIONS = 300

function compareValues(a: FacetValue, b: FacetValue): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b
  return String(a).localeCompare(String(b))
}

// FacetFilterBar renders one tag input per dimension (status code, body
// size, extension, ...). Typing a value and pressing Enter adds it as a
// matcher tag -- once a dimension has any matcher tags, only items whose
// value matches one of them pass (an OR within the dimension); dimensions
// still combine with AND. Prefixing the typed value with "-" adds it as a
// filter tag instead: an inverse match that hides items with that value
// regardless of what else matches (a value can't be both a matcher and a
// filter tag at once -- adding one clears the other). Clicking an active
// tag removes it. An item missing a dimension's value entirely (e.g. a
// passive subdomain with no ffuf response yet) is excluded once that
// dimension has an active matcher tag (it can't be confirmed to match), but
// is unaffected by filter tags alone (there's nothing there for those to
// hide).
//
// A dimension's own distinct values back its input's autocomplete
// suggestions (so it's still discoverable without typing blind), but
// unlike the old clickable chip grid, suggestions live in the browser's
// native dropdown instead of an always-rendered row -- so a dimension with
// dozens of distinct values (extensions, sizes, ...) never overflows or
// hides options.
//
// Active tag counts always reflect the *currently filtered* result set
// (after every dimension's matchers/filters are applied), not the full
// unfiltered `items` -- so once a filter narrows things down, each tag
// shows how many of that value remain visible right now.
export function FacetFilterBar<T>({
  items,
  dimensions,
  onChange,
}: {
  items: T[]
  dimensions: FacetDimension<T>[]
  onChange: (kept: T[]) => void
}) {
  const [included, setIncluded] = useState<Record<string, Set<FacetValue>>>({})
  const [excluded, setExcluded] = useState<Record<string, Set<FacetValue>>>({})
  const [drafts, setDrafts] = useState<Record<string, string>>({})

  const kept = useMemo(
    () =>
      items.filter((item) =>
        dimensions.every((dim) => {
          const v = dim.getValue(item)
          const includeSet = included[dim.key]
          const hasActiveInclude = !!includeSet && includeSet.size > 0
          // An item with no value for this dimension only survives when the
          // dimension has no active matcher tags -- once you've picked a
          // matcher (e.g. status code 200), items that were never scored on
          // this dimension (e.g. not yet verified) shouldn't slip through
          // as if they matched.
          if (v === undefined) return !hasActiveInclude
          const excludeSet = excluded[dim.key]
          if (excludeSet?.has(v)) return false
          if (hasActiveInclude) return includeSet!.has(v)
          return true
        }),
      ),
    [items, dimensions, included, excluded],
  )

  const facets = useMemo(
    () =>
      dimensions.map((dim) => {
        // Full-corpus counts decide which values exist as suggestions, and
        // in what order, so autocomplete stays stable while filtering.
        const totalCounts = new Map<FacetValue, number>()
        for (const item of items) {
          const v = dim.getValue(item)
          if (v === undefined) continue
          totalCounts.set(v, (totalCounts.get(v) ?? 0) + 1)
        }
        const allValues = [...totalCounts.keys()].sort((a, b) => totalCounts.get(b)! - totalCounts.get(a)! || compareValues(a, b))
        const suggestions = allValues.slice(0, MAX_SUGGESTIONS)

        // Displayed counts for active tags reflect the current filtered
        // result set.
        const keptCounts = new Map<FacetValue, number>()
        for (const item of kept) {
          const v = dim.getValue(item)
          if (v === undefined) continue
          keptCounts.set(v, (keptCounts.get(v) ?? 0) + 1)
        }

        // Maps a typed string back to the actual (possibly numeric)
        // FacetValue it refers to, so Set membership checks against
        // items' real values keep working.
        const byString = new Map<string, FacetValue>()
        for (const v of allValues) byString.set(String(v), v)

        const warnValues = allValues.filter((v) => dim.warningFor?.(v) ?? false)
        // Whether this dimension's values are numbers or strings, sampled
        // from whatever data is actually present -- used so a typed value
        // that hasn't appeared yet (e.g. pre-filtering for a status code
        // no result has hit yet) still resolves to the right type instead
        // of guessing from the text alone.
        const isNumeric = allValues.length > 0 && typeof allValues[0] === 'number'

        return { dim, suggestions, totalCounts, keptCounts, byString, warnValues, isNumeric }
      }),
    [items, kept, dimensions],
  )

  useEffect(() => {
    onChange(kept)
    // onChange intentionally excluded: callers pass an inline function, and
    // re-running this effect only needs to happen when the filtered set
    // itself changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kept])

  const setInclude = (dimKey: string, value: FacetValue) => {
    setIncluded((prev) => ({ ...prev, [dimKey]: new Set(prev[dimKey]).add(value) }))
    setExcluded((prev) => {
      if (!prev[dimKey]?.has(value)) return prev
      const next = new Set(prev[dimKey])
      next.delete(value)
      return { ...prev, [dimKey]: next }
    })
  }

  const setExclude = (dimKey: string, value: FacetValue) => {
    setExcluded((prev) => ({ ...prev, [dimKey]: new Set(prev[dimKey]).add(value) }))
    setIncluded((prev) => {
      if (!prev[dimKey]?.has(value)) return prev
      const next = new Set(prev[dimKey])
      next.delete(value)
      return { ...prev, [dimKey]: next }
    })
  }

  const removeInclude = (dimKey: string, value: FacetValue) => {
    setIncluded((prev) => {
      const next = new Set(prev[dimKey])
      next.delete(value)
      return { ...prev, [dimKey]: next }
    })
  }

  const removeExclude = (dimKey: string, value: FacetValue) => {
    setExcluded((prev) => {
      const next = new Set(prev[dimKey])
      next.delete(value)
      return { ...prev, [dimKey]: next }
    })
  }

  // resolveValue maps raw typed text to the dimension's real FacetValue
  // type -- an exact match against a value already seen wins outright;
  // otherwise it falls back to the dimension's sampled type (isNumeric)
  // rather than guessing from the text, so a numeric-looking string in a
  // string dimension (an extension literally named "123", say) isn't
  // misparsed into a number that could never match.
  const resolveValue = (raw: string, byString: Map<string, FacetValue>, isNumeric: boolean): FacetValue => {
    const known = byString.get(raw)
    if (known !== undefined) return known
    if (!isNumeric) return raw
    const asNumber = Number(raw)
    return raw !== '' && !Number.isNaN(asNumber) ? asNumber : raw
  }

  const submitDraft = (dimKey: string, byString: Map<string, FacetValue>, isNumeric: boolean) => {
    const raw = (drafts[dimKey] ?? '').trim()
    if (!raw) return
    if (raw.startsWith('-') && raw.length > 1) {
      setExclude(dimKey, resolveValue(raw.slice(1).trim(), byString, isNumeric))
    } else {
      setInclude(dimKey, resolveValue(raw, byString, isNumeric))
    }
    setDrafts((prev) => ({ ...prev, [dimKey]: '' }))
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>, dimKey: string, byString: Map<string, FacetValue>, isNumeric: boolean) => {
    if (e.key !== 'Enter') return
    e.preventDefault()
    submitDraft(dimKey, byString, isNumeric)
  }

  // toggleCriticalOnly is a one-click way to see only values a dimension
  // flags via warningFor (e.g. dangerous file extensions), without having
  // to type each one in by hand. A second click clears it.
  const toggleCriticalOnly = (dimKey: string, warnValues: FacetValue[]) => {
    setIncluded((prev) => {
      const current = prev[dimKey] ?? new Set<FacetValue>()
      const isCriticalOnly = warnValues.length > 0 && warnValues.every((v) => current.has(v)) && current.size === warnValues.length
      return { ...prev, [dimKey]: isCriticalOnly ? new Set() : new Set(warnValues) }
    })
    setExcluded((prev) => ({ ...prev, [dimKey]: new Set() }))
  }

  const visible = facets.filter((f) => f.suggestions.length > 1)
  if (visible.length === 0) return null

  // Status gets its own full-width row below the other dimensions' input
  // boxes (rendered separately below) rather than competing for space in
  // the same row, since its one-click button grid can run much wider than
  // a single type-to-match input.
  const inputFacets = visible.filter((f) => f.dim.key !== 'statusCode')
  const statusFacets = visible.filter((f) => f.dim.key === 'statusCode')

  return (
    <div className="border-b border-neutral-800">
      {inputFacets.length > 0 && (
        <div className="grid grid-cols-2 gap-x-6 gap-y-2 px-3 py-2 sm:grid-cols-4">
          {inputFacets.map(({ dim, suggestions, keptCounts, byString, warnValues, isNumeric }) => {
            const includeSet = included[dim.key] ?? new Set<FacetValue>()
            const excludeSet = excluded[dim.key] ?? new Set<FacetValue>()
            const hasTags = includeSet.size > 0 || excludeSet.size > 0
            const criticalActive = warnValues.length > 0 && warnValues.every((v) => includeSet.has(v)) && includeSet.size === warnValues.length
            const datalistId = `facet-suggestions-${dim.key}`
            return (
              <div key={dim.key} className="flex flex-col gap-1">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">{dim.label}</span>
                <div className="flex items-center gap-1">
                  <input
                    list={datalistId}
                    value={drafts[dim.key] ?? ''}
                    onChange={(e) => setDrafts((prev) => ({ ...prev, [dim.key]: e.target.value }))}
                    onKeyDown={(e) => onKeyDown(e, dim.key, byString, isNumeric)}
                    placeholder="value or -value"
                    className="w-full min-w-0 rounded border border-neutral-700 bg-neutral-900 px-2.5 py-1.5 font-mono text-xs text-neutral-200 outline-none placeholder:text-neutral-600 focus:border-sky-500"
                  />
                  <datalist id={datalistId}>
                    {suggestions.map((v) => (
                      <option key={v} value={String(v)} label={`${totalCountLabel(v, keptCounts)}`} />
                    ))}
                  </datalist>
                  {warnValues.length > 0 && (
                    <button
                      onClick={() => toggleCriticalOnly(dim.key, warnValues)}
                      title="Show only values flagged as potentially sensitive"
                      className={`shrink-0 rounded border px-2 py-1.5 font-mono text-xs transition-colors ${
                        criticalActive
                          ? 'border-red-500 bg-red-950/50 text-red-300'
                          : 'border-red-900 bg-transparent text-red-400 hover:border-red-700'
                      }`}
                    >
                      ⚠
                    </button>
                  )}
                </div>
                {hasTags && (
                  <div className="flex flex-wrap gap-1">
                    {[...includeSet].sort(compareValues).map((value) => {
                      const warn = dim.warningFor?.(value) ?? false
                      const count = keptCounts.get(value) ?? 0
                      return (
                        <button
                          key={`inc-${value}`}
                          onClick={() => removeInclude(dim.key, value)}
                          title={`${count} result${count === 1 ? '' : 's'} — click to remove`}
                          className={`rounded border px-1.5 py-0.5 font-mono text-xs transition-colors ${
                            warn ? 'border-red-500 bg-red-950/50 text-red-300' : 'border-sky-500 bg-sky-950/40 text-sky-300'
                          }`}
                          style={dim.colorFor ? { color: dim.colorFor(value) } : undefined}
                        >
                          {warn && '⚠ '}
                          {value}
                          <span className="ml-1 text-neutral-500">{count}</span>
                        </button>
                      )
                    })}
                    {[...excludeSet].sort(compareValues).map((value) => {
                      const count = keptCounts.get(value) ?? 0
                      return (
                        <button
                          key={`exc-${value}`}
                          onClick={() => removeExclude(dim.key, value)}
                          title={`${count} result${count === 1 ? '' : 's'} — excluded, click to remove`}
                          className="rounded border border-amber-600 bg-amber-950/30 px-1.5 py-0.5 font-mono text-xs text-amber-400 transition-colors"
                        >
                          − {value}
                          <span className="ml-1 text-amber-700">{count}</span>
                        </button>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
      {statusFacets.map(({ dim, suggestions, keptCounts }) => {
        const includeSet = included[dim.key] ?? new Set<FacetValue>()
        return (
          <div key={dim.key} className={`flex flex-wrap items-center gap-1.5 px-3 py-2 ${inputFacets.length > 0 ? 'border-t border-neutral-900' : ''}`}>
            <span className="text-[10px] font-semibold uppercase tracking-wide text-neutral-500">{dim.label}</span>
            {suggestions.map((v) => {
              const active = includeSet.has(v)
              const count = keptCounts.get(v) ?? 0
              return (
                <button
                  key={v}
                  onClick={() => (active ? removeInclude(dim.key, v) : setInclude(dim.key, v))}
                  title={`${count} result${count === 1 ? '' : 's'}`}
                  className={`rounded border px-2.5 py-1.5 font-mono text-xs transition-colors ${
                    active ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 hover:border-sky-600'
                  }`}
                  style={!active && dim.colorFor ? { color: dim.colorFor(v) } : undefined}
                >
                  {v}
                  <span className="ml-1 text-neutral-500">{count}</span>
                </button>
              )
            })}
          </div>
        )
      })}
    </div>
  )
}

function totalCountLabel(value: FacetValue, keptCounts: Map<FacetValue, number>): string {
  const n = keptCounts.get(value) ?? 0
  return `${n} result${n === 1 ? '' : 's'}`
}
