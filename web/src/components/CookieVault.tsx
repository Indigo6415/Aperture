import { useState } from 'react'
import { api, ApiError } from '../api'
import type { CookieVaultEntry } from '../types'
import { inputBase } from '../formStyles'
import { showToast } from '../toast'

// CookieVault is a case's per-domain auth: one row per domain the case
// knows about (from its targets), each with a Cookie header that gets
// applied automatically to every request this case makes against that
// domain -- every tool that accepts a URL/target and a case ID picks it up
// on its own (see api.applyDomainCookie), unlike a Credential, which has to
// be picked per request. Scoped to this case, same as CredentialVault.
export function CookieVault({ caseId, entries, onChanged }: { caseId: string; entries: CookieVaultEntry[]; onChanged: () => void }) {
  const [newDomain, setNewDomain] = useState('')
  const [newCookie, setNewCookie] = useState('')
  const [addError, setAddError] = useState('')
  const [adding, setAdding] = useState(false)

  const addDomain = async () => {
    const domain = newDomain.trim().toLowerCase()
    if (!domain || adding) return
    setAdding(true)
    setAddError('')
    try {
      await api.setCookieVaultEntry(caseId, domain, newCookie.trim())
      setNewDomain('')
      setNewCookie('')
      showToast(`Added ${domain} to the cookie vault`, 'success')
      onChanged()
    } catch (err) {
      setAddError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err))
    } finally {
      setAdding(false)
    }
  }

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col gap-4 overflow-y-auto px-4 py-6">
      <div>
        <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Cookie Vault</h1>
        <p className="mt-1 text-xs text-neutral-500">
          Set a session cookie per domain and it's sent automatically with every request this case makes against that
          domain -- no need to pick a credential each time. An explicit Cookie header (typed by hand, or from a chosen
          credential) always wins over this. Scoped to this case.
        </p>
      </div>

      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
        <p className="mb-2 text-xs font-medium text-neutral-300">Add a domain</p>
        <div className="flex flex-col gap-1.5 sm:flex-row">
          <input
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="example.com"
            className={`${inputBase} sm:w-48`}
          />
          <input
            value={newCookie}
            onChange={(e) => setNewCookie(e.target.value)}
            placeholder="session=abc123; other=value"
            className={`${inputBase} flex-1`}
          />
          <button
            onClick={addDomain}
            disabled={!newDomain.trim() || adding}
            className="shrink-0 rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {adding ? 'Adding…' : 'Add'}
          </button>
        </div>
        {addError && <p className="mt-1.5 text-xs text-red-400">{addError}</p>}
      </div>

      <div className="space-y-2">
        {entries.length === 0 ? (
          <div className="flex h-24 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
            No domains yet -- add one above, or add a target to this case.
          </div>
        ) : (
          entries.map((e) => (
            // Keyed by domain+cookie, not just domain, so a successful
            // save/clear (which changes e.cookie once `entries` refreshes)
            // remounts the row with the new saved value as its starting
            // point, instead of needing an effect to resync local state.
            <CookieRow key={`${e.domain}:${e.cookie ?? ''}`} caseId={caseId} entry={e} onChanged={onChanged} />
          ))
        )}
      </div>
    </div>
  )
}

function CookieRow({ caseId, entry, onChanged }: { caseId: string; entry: CookieVaultEntry; onChanged: () => void }) {
  const [value, setValue] = useState(entry.cookie ?? '')
  const [saving, setSaving] = useState(false)
  const dirty = value !== (entry.cookie ?? '')

  const save = async (cookie: string) => {
    setSaving(true)
    try {
      await api.setCookieVaultEntry(caseId, entry.domain, cookie.trim())
      showToast(cookie.trim() ? `Cookie saved for ${entry.domain}` : `Cookie cleared for ${entry.domain}`, 'success')
      onChanged()
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err), 'error')
      setSaving(false)
    }
  }

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate font-mono text-xs font-medium text-neutral-200">{entry.domain}</span>
        {entry.cookie && !dirty && <span className="shrink-0 rounded-full bg-emerald-900/40 px-2 py-0.5 text-[10px] text-emerald-400">Active</span>}
      </div>
      <div className="mt-2 flex gap-1.5">
        <input
          value={value}
          onChange={(ev) => setValue(ev.target.value)}
          placeholder="session=abc123; other=value"
          className={`${inputBase} flex-1 font-mono text-xs`}
        />
        <button
          onClick={() => save(value)}
          disabled={!dirty || saving}
          className="shrink-0 rounded border border-sky-700 px-2.5 py-1.5 text-xs font-medium text-sky-300 hover:border-sky-500 hover:text-sky-200 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
        {entry.cookie && (
          <button
            onClick={() => save('')}
            disabled={saving}
            className="shrink-0 rounded border border-neutral-700 px-2.5 py-1.5 text-xs text-neutral-400 hover:border-red-500 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  )
}
