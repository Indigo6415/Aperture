import { useEffect, useState } from 'react'
import { api, ApiError } from '../api'

// ScopeEditor edits a case's scope: the hosts scans launched under it may
// touch. One pattern per line. The server validates every line, and a bad one
// comes back as a message here rather than being saved.
export function ScopeEditor({ caseId }: { caseId: string }) {
  const [text, setText] = useState('')
  const [saved, setSaved] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // The parent keys this component on the case ID, so a case change remounts it
  // with fresh state; the effect itself only runs the async load.
  useEffect(() => {
    let cancelled = false
    api
      .getCaseScope(caseId)
      .then((s) => {
        if (cancelled) return
        setSaved(s.patterns)
        setText(s.patterns.join('\n'))
        setError(null)
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof ApiError ? e.message : String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [caseId])

  // Splits the textarea into patterns, dropping blank lines. The server
  // de-duplicates and validates.
  const patterns = text
    .split('\n')
    .map((p) => p.trim())
    .filter(Boolean)
  const dirty = patterns.join('\n') !== saved.join('\n')

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      const res = await api.setCaseScope(caseId, patterns)
      setSaved(res.patterns)
      setText(res.patterns.join('\n'))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col gap-2 border-b border-neutral-800 bg-neutral-950 px-4 py-3">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-neutral-300">Scope</span>
        <span className="text-xs text-neutral-500">
          {saved.length === 0
            ? 'Unrestricted: scans may reach any host.'
            : `${saved.length} rule${saved.length === 1 ? '' : 's'}: scans refuse hosts outside these.`}
        </span>
      </div>
      <textarea
        value={text}
        disabled={loading}
        onChange={(e) => setText(e.target.value)}
        placeholder={'example.com        (the host and its subdomains)\n*.lab.test          (subdomains only)\n10.0.0.0/24        (a range)'}
        rows={Math.min(6, Math.max(3, patterns.length + 1))}
        spellCheck={false}
        className="w-full resize-y rounded border border-neutral-700 bg-neutral-900 px-2 py-1 font-mono text-xs text-neutral-200 outline-none focus:border-sky-500"
      />
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={save}
          disabled={!dirty || saving || loading}
          className="rounded bg-sky-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-40"
        >
          {saving ? 'Saving...' : 'Save scope'}
        </button>
        {dirty && !saving && <span className="text-xs text-amber-400">Unsaved changes</span>}
        {error && <span className="text-xs text-red-400">{error}</span>}
      </div>
    </div>
  )
}
