import { useEffect, useState } from 'react'
import { api } from '../api'
import type { WordlistCatalogEntry, WordlistCategory, WordlistInfo } from '../types'

const CATEGORY_ORDER: WordlistCategory[] = ['directories', 'subdomains', 'extensions', 'misc']

const CATEGORY_META: Record<WordlistCategory, { label: string; hint: string }> = {
  directories: { label: 'Directories', hint: 'Content discovery (ffuf + feroxbuster -w)' },
  subdomains: { label: 'Subdomains', hint: 'Subdomain + vhost bruteforce (ffuf -w)' },
  extensions: { label: 'Extensions', hint: 'Content discovery -e/-x (one extension per line)' },
  misc: { label: 'Misc', hint: 'Not used by any scanner automatically' },
}

// nextCopyName picks a filename for a duplicate that doesn't collide with
// anything already installed, so "Duplicate" never needs to interrupt the
// user for a name -- name.txt -> name-copy.txt -> name-copy-2.txt, ...
function nextCopyName(existing: Set<string>, name: string): string {
  const dot = name.lastIndexOf('.')
  const base = dot > 0 ? name.slice(0, dot) : name
  const ext = dot > 0 ? name.slice(dot) : ''
  let candidate = `${base}-copy${ext}`
  let n = 2
  while (existing.has(candidate)) {
    candidate = `${base}-copy-${n}${ext}`
    n++
  }
  return candidate
}

// Wordlists lets the user browse what's installed, grab a well-known list
// (SecLists/dirb) with one click, or pull an arbitrary URL -- so the
// ffuf/feroxbuster nodes (and the auto-generated domain-scan flow) always
// have something real to point at without the user hunting a file down
// themselves first. Installed wordlists are organized into four category
// containers (Directories/Subdomains/Extensions/Misc); the auto-generated
// scan flows fuzz with whatever's tagged into the category their scanner
// needs, so dragging a downloaded list into the right container is what
// actually makes it get used, not just downloading it.
export function Wordlists() {
  const [installed, setInstalled] = useState<WordlistInfo[]>([])
  const [catalog, setCatalog] = useState<WordlistCatalogEntry[]>([])
  const [downloading, setDownloading] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [dragOverCategory, setDragOverCategory] = useState<WordlistCategory | null>(null)
  const [customName, setCustomName] = useState('')
  const [customUrl, setCustomUrl] = useState('')
  const [error, setError] = useState('')
  const [renaming, setRenaming] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')

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

  const moveToCategory = async (name: string, category: WordlistCategory) => {
    setError('')
    setBusy(name)
    try {
      await api.setWordlistCategories(name, [category])
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  // startRenaming switches a wordlist row into its inline text-input state,
  // seeded with the current name so the user is editing rather than
  // starting from a blank field.
  const startRenaming = (name: string) => {
    setRenaming(name)
    setRenameValue(name)
  }

  // commitRename sends the edited name to the server and closes the inline
  // editor. A blank or unchanged value just closes the editor without an
  // API call, so pressing Escape-then-blur or clicking away doesn't rename
  // anything.
  const commitRename = async (name: string) => {
    const newName = renameValue.trim()
    if (!newName || newName === name) {
      setRenaming(null)
      return
    }
    setError('')
    setBusy(name)
    try {
      await api.renameWordlist(name, newName)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
      setRenaming(null)
    }
  }

  const duplicate = async (name: string) => {
    setError('')
    setBusy(name)
    try {
      const newName = nextCopyName(new Set(installed.map((w) => w.name)), name)
      await api.duplicateWordlist(name, newName)
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
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
    <div className="mx-auto h-full max-w-5xl overflow-y-auto px-6 py-10">
      <h1 className="mb-1 text-xl font-semibold text-neutral-100">Wordlists</h1>
      <p className="mb-6 text-sm text-neutral-500">
        Drag a wordlist into the category its scanner should use it for. Use{' '}
        <span className="font-mono text-neutral-400">⧉ Duplicate</span> to put the same list to work in two categories at once.
      </p>

      <div className="mb-10 grid grid-cols-1 gap-4 sm:grid-cols-2">
        {CATEGORY_ORDER.map((category) => {
          const meta = CATEGORY_META[category]
          const members = installed.filter((w) => w.categories.includes(category))
          const isDragTarget = dragOverCategory === category
          return (
            <div
              key={category}
              onDragOver={(e) => {
                e.preventDefault()
                e.dataTransfer.dropEffect = 'move'
                setDragOverCategory(category)
              }}
              onDragLeave={() => setDragOverCategory((c) => (c === category ? null : c))}
              onDrop={(e) => {
                e.preventDefault()
                setDragOverCategory(null)
                const name = e.dataTransfer.getData('text/plain')
                if (name && installedNames.has(name)) moveToCategory(name, category)
              }}
              className={`rounded-lg border p-3 transition-colors ${
                isDragTarget ? 'border-sky-500 bg-sky-950/20' : 'border-neutral-800 bg-neutral-900/30'
              }`}
            >
              <div className="mb-2 flex items-baseline justify-between">
                <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-300">{meta.label}</h2>
                <span className="text-[10px] text-neutral-600">{members.length}</span>
              </div>
              <p className="mb-3 text-[11px] text-neutral-600">{meta.hint}</p>
              <div className="flex flex-col gap-1.5">
                {members.map((w) => (
                  <div
                    key={w.name}
                    draggable={renaming !== w.name}
                    onDragStart={(e) => {
                      e.dataTransfer.setData('text/plain', w.name)
                      e.dataTransfer.effectAllowed = 'move'
                    }}
                    className={`flex items-center justify-between gap-2 rounded border border-neutral-700 bg-neutral-900 px-2 py-1.5 ${
                      busy === w.name ? 'opacity-50' : renaming === w.name ? '' : 'cursor-grab active:cursor-grabbing'
                    }`}
                  >
                    <div className="min-w-0 flex-1">
                      {renaming === w.name ? (
                        <input
                          autoFocus
                          value={renameValue}
                          onChange={(e) => setRenameValue(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') commitRename(w.name)
                            if (e.key === 'Escape') setRenaming(null)
                          }}
                          onBlur={() => commitRename(w.name)}
                          spellCheck={false}
                          className="w-full rounded border border-sky-600 bg-neutral-800 px-1 py-0.5 font-mono text-xs text-neutral-100 outline-none"
                        />
                      ) : (
                        <p className="truncate font-mono text-xs text-neutral-100">
                          {w.name}
                          {w.builtin && (
                            <span className="ml-1.5 rounded-full border border-neutral-700 px-1 py-px text-[9px] text-neutral-500">built-in</span>
                          )}
                        </p>
                      )}
                      <p className="text-[10px] text-neutral-500">
                        {w.lines.toLocaleString()} lines · {formatSize(w.size)}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {!w.builtin && renaming !== w.name && (
                        <button
                          onClick={() => startRenaming(w.name)}
                          disabled={busy === w.name}
                          title="Rename"
                          className="text-xs text-neutral-500 hover:text-sky-400 disabled:opacity-40"
                        >
                          ✎
                        </button>
                      )}
                      <button
                        onClick={() => duplicate(w.name)}
                        disabled={busy === w.name}
                        title="Duplicate into another category"
                        className="text-xs text-neutral-500 hover:text-sky-400 disabled:opacity-40"
                      >
                        ⧉
                      </button>
                      {!w.builtin && (
                        <button onClick={() => remove(w.name)} title="Delete" className="text-xs text-neutral-600 hover:text-red-400">
                          ✕
                        </button>
                      )}
                    </div>
                  </div>
                ))}
                {members.length === 0 && (
                  <p className="rounded border border-dashed border-neutral-800 px-2 py-3 text-center text-[11px] text-neutral-600">
                    Drag a wordlist here
                  </p>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

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
