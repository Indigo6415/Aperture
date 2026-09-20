import { useEffect, useState } from 'react'
import { api, ApiError } from '../api'
import type { JobOptions, JobTemplate, Tool } from '../types'
import { inputBase } from '../formStyles'
import { showToast } from '../toast'

// JobTemplatePicker is the "reusable job-launch templates" feature: save
// the launcher's current tuning (preset/threads/timeout/rate/wordlist/
// scheme/hostSuffix/recursive, plus ffuf-custom's own fields) as a named,
// global (not case-scoped) template for tool, then load it back onto a
// future launcher without rebuilding it by hand. current is exactly the
// JobOptions object the caller's own start() already builds, so saving is
// a straight POST of it; onApply hands a loaded template's options back so
// the caller can spread them onto its own state setters.
export function JobTemplatePicker({ tool, current, onApply }: { tool: Tool; current: JobOptions; onApply: (options: JobOptions) => void }) {
  const [templates, setTemplates] = useState<JobTemplate[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [showSave, setShowSave] = useState(false)
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)

  const refresh = () => api.listJobTemplates(tool).then(setTemplates).catch(() => {})

  useEffect(() => {
    setSelectedId('')
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tool])

  const apply = () => {
    const t = templates.find((t) => t.id === selectedId)
    if (t) onApply(t.options)
  }

  const save = async () => {
    if (!name.trim()) return
    setSaving(true)
    try {
      await api.saveJobTemplate(tool, name.trim(), current)
      setName('')
      setShowSave(false)
      showToast(`Saved template "${name.trim()}"`, 'success')
      refresh()
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setSaving(false)
    }
  }

  const remove = async (id: string) => {
    try {
      await api.deleteJobTemplate(id)
      setSelectedId('')
      refresh()
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err), 'error')
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {templates.length > 0 && (
        <>
          <select value={selectedId} onChange={(e) => setSelectedId(e.target.value)} className={`${inputBase} w-auto`}>
            <option value="">Load template…</option>
            {templates.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={apply}
            disabled={!selectedId}
            className="rounded border border-neutral-700 px-2 py-0.5 text-xs text-neutral-400 hover:border-sky-600 hover:text-sky-300 disabled:opacity-50"
          >
            Apply
          </button>
          {selectedId && (
            <button type="button" onClick={() => remove(selectedId)} className="text-xs text-neutral-500 hover:text-red-400">
              Delete
            </button>
          )}
        </>
      )}
      {showSave ? (
        <>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Template name" className={`${inputBase} w-40`} />
          <button
            type="button"
            onClick={save}
            disabled={saving || !name.trim()}
            className="rounded bg-sky-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button type="button" onClick={() => setShowSave(false)} className="text-xs text-neutral-500 hover:text-neutral-300">
            Cancel
          </button>
        </>
      ) : (
        <button
          type="button"
          onClick={() => setShowSave(true)}
          className="rounded border border-neutral-800 px-2 py-0.5 text-xs text-neutral-500 hover:text-neutral-300"
        >
          Save current as template…
        </button>
      )}
    </div>
  )
}
