import { useEffect, useState } from 'react'
import { api } from '../api'
import type { WordlistCatalogEntry, WordlistInfo } from '../types'

// Wordlists lets the user browse what's installed, grab a well-known list
// (SecLists/dirb) with one click, or pull an arbitrary URL -- so the
// ffuf/feroxbuster nodes (and the auto-generated domain-scan flow) always
// have something real to point at without the user hunting a file down
// themselves first.
export function Wordlists() {
  const [installed, setInstalled] = useState<WordlistInfo[]>([])
  const [catalog, setCatalog] = useState<WordlistCatalogEntry[]>([])
  const [downloading, setDownloading] = useState<string | null>(null)
  const [customName, setCustomName] = useState('')
  const [customUrl, setCustomUrl] = useState('')
  const [error, setError] = useState('')

  const refresh = () => api.listWordlists().then(setInstalled)

  useEffect(() => {
    refresh()
    api.wordlistCatalog().then(setCatalog)
  }, [])

  const download = async (name: string, url?: string) => {
    setDownloading(name)
    setError('')
    try {
      await api.downloadWordlist(name, url)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setDownloading(null)
    }
  }

  const remove = async (name: string) => {
    if (!confirm(`Delete ${name}?`)) return
    await api.deleteWordlist(name)
    refresh()
  }

  const submitCustom = (e: React.FormEvent) => {
    e.preventDefault()
    const name = customName.trim()
    const url = customUrl.trim()
    if (!name || !url) return
    download(name, url)
    setCustomName('')
    setCustomUrl('')
  }

  const installedNames = new Set(installed.map((w) => w.name))

  return (
    <div className="mx-auto h-full max-w-3xl overflow-y-auto px-6 py-10">
      <h1 className="mb-6 text-xl font-semibold text-neutral-100">Wordlists</h1>

      <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Installed</h2>
      <div className="mb-8 divide-y divide-neutral-800 rounded-lg border border-neutral-800">
        {installed.map((w) => (
          <div key={w.name} className="flex items-center justify-between px-4 py-3">
            <div>
              <p className="font-mono text-sm text-neutral-100">
                {w.name}
                {w.builtin && (
                  <span className="ml-2 rounded-full border border-neutral-700 px-1.5 py-0.5 text-[10px] text-neutral-500">built-in</span>
                )}
              </p>
              <p className="text-xs text-neutral-500">
                {w.lines.toLocaleString()} lines · {formatSize(w.size)}
              </p>
            </div>
            {!w.builtin && (
              <button onClick={() => remove(w.name)} className="text-xs text-neutral-600 hover:text-red-400">
                Delete
              </button>
            )}
          </div>
        ))}
        {installed.length === 0 && <p className="px-4 py-8 text-center text-sm text-neutral-600">No wordlists yet.</p>}
      </div>

      <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Download common wordlists</h2>
      <div className="mb-8 divide-y divide-neutral-800 rounded-lg border border-neutral-800">
        {catalog.map((entry) => (
          <div key={entry.name} className="flex items-center justify-between px-4 py-3">
            <div>
              <p className="font-mono text-sm text-neutral-100">{entry.name}</p>
              <p className="text-xs text-neutral-500">{entry.description}</p>
            </div>
            <button
              onClick={() => download(entry.name, entry.url)}
              disabled={downloading === entry.name || installedNames.has(entry.name)}
              className="rounded border border-neutral-700 px-3 py-1 text-xs text-neutral-200 hover:border-neutral-500 disabled:opacity-40"
            >
              {installedNames.has(entry.name) ? 'Installed' : downloading === entry.name ? 'Downloading…' : 'Download'}
            </button>
          </div>
        ))}
      </div>

      <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Download from a URL</h2>
      <form onSubmit={submitCustom} className="flex gap-2">
        <input
          value={customName}
          onChange={(e) => setCustomName(e.target.value)}
          placeholder="filename.txt"
          className="w-48 rounded border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500"
        />
        <input
          value={customUrl}
          onChange={(e) => setCustomUrl(e.target.value)}
          placeholder="https://raw.githubusercontent.com/.../wordlist.txt"
          className="flex-1 rounded border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500"
        />
        <button
          type="submit"
          disabled={!!downloading}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          Download
        </button>
      </form>
      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
    </div>
  )
}

// formatSize renders a byte count the way a file browser would, so users
// judging whether a download is "small" don't have to do the math.
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
