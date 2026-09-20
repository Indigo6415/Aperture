import { useState } from 'react'
import { api, ApiError } from '../api'
import type { Credential } from '../types'
import { CollapsibleFormPanel } from './CollapsibleFormPanel'
import { CopyButton } from './CopyButton'
import { useAutoCollapseOnce, useCollapsible } from '../collapsible'
import { inputBase } from '../formStyles'
import { showToast } from '../toast'

type HeaderRow = { name: string; value: string }

// CredentialVault is a case's saved auth bundles: a name plus whatever
// headers/cookie a request needs to authenticate, reusable from Repeater/
// JWT Scanner/Probe/Secret Scanner via CredentialPicker instead of being
// re-pasted into each tool by hand every time.
export function CredentialVault({ caseId, credentials, onChanged }: { caseId: string; credentials: Credential[]; onChanged: () => void }) {
  const [name, setName] = useState('')
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([{ name: 'Authorization', value: '' }])
  const [cookie, setCookie] = useState('')
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const [formOpen, setFormOpen] = useCollapsible('credentials.form', true)
  useAutoCollapseOnce(credentials.length > 0, setFormOpen)

  const addHeaderRow = () => setHeaderRows((rows) => [...rows, { name: '', value: '' }])
  const updateHeaderRow = (i: number, patch: Partial<HeaderRow>) =>
    setHeaderRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const removeHeaderRow = (i: number) => setHeaderRows((rows) => (rows.length === 1 ? rows : rows.filter((_, idx) => idx !== i)))

  const canSave = name.trim() !== '' && !saving

  const save = async () => {
    if (!canSave) return
    setSaving(true)
    setError('')
    try {
      const headers: Record<string, string> = {}
      for (const row of headerRows) {
        if (row.name.trim()) headers[row.name.trim()] = row.value
      }
      await api.addCredential(caseId, name.trim(), Object.keys(headers).length ? headers : undefined, cookie.trim() || undefined, notes.trim() || undefined)
      setName('')
      setHeaderRows([{ name: 'Authorization', value: '' }])
      setCookie('')
      setNotes('')
      showToast('Credential saved', 'success')
      onChanged()
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err)
      setError(message)
    } finally {
      setSaving(false)
    }
  }

  const remove = async (c: Credential) => {
    try {
      await api.deleteCredential(c.id)
      showToast(`Removed credential "${c.name}"`, 'success')
      onChanged()
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : err instanceof Error ? err.message : String(err), 'error')
    }
  }

  return (
    <div className="mx-auto flex h-full max-w-3xl flex-col gap-4 overflow-y-auto px-4 py-6">
      <CollapsibleFormPanel
        title="Credentials"
        open={formOpen}
        onToggle={() => setFormOpen(!formOpen)}
        summary={name.trim() ? `Save "${name}"` : 'No new credential'}
        onRun={save}
        canRun={canSave}
        loading={saving}
        runLabel="Save"
      >
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Credentials</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Save an auth bundle (headers and/or a cookie) once, then apply it from Repeater, the JWT Scanner, Probe, or Secret
            Scanner instead of re-pasting it every time. Scoped to this case.
          </p>
        </div>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Low-priv session" className={`mt-1 ${inputBase}`} />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Headers</span>
          <div className="mt-1 space-y-1.5">
            {headerRows.map((row, i) => (
              <div key={i} className="flex gap-1.5">
                <input
                  value={row.name}
                  onChange={(e) => updateHeaderRow(i, { name: e.target.value })}
                  placeholder="Name"
                  className={`${inputBase} flex-1`}
                />
                <input
                  value={row.value}
                  onChange={(e) => updateHeaderRow(i, { value: e.target.value })}
                  placeholder="Value"
                  className={`${inputBase} flex-1`}
                />
                <button
                  onClick={() => removeHeaderRow(i)}
                  className="rounded border border-neutral-700 px-2 text-sm text-neutral-400 hover:border-red-500 hover:text-red-400"
                  title="Remove header"
                >
                  ×
                </button>
              </div>
            ))}
            <button onClick={addHeaderRow} className="text-xs text-sky-400 hover:text-sky-300">
              + Add header
            </button>
          </div>
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Cookie</span>
          <input value={cookie} onChange={(e) => setCookie(e.target.value)} placeholder="session=abc123; other=value" className={`mt-1 ${inputBase}`} />
        </label>

        <label className="block">
          <span className="text-xs font-medium text-neutral-300">Notes</span>
          <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional" className={`mt-1 ${inputBase}`} />
        </label>

        {error && <p className="text-xs text-red-400">{error}</p>}

        <button
          onClick={save}
          disabled={!canSave}
          className="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save credential'}
        </button>
      </CollapsibleFormPanel>

      <div className="space-y-2">
        {credentials.length === 0 ? (
          <div className="flex h-24 items-center justify-center rounded-lg border border-dashed border-neutral-800 text-sm text-neutral-600">
            No saved credentials yet.
          </div>
        ) : (
          credentials.map((c) => <CredentialRow key={c.id} credential={c} onDelete={() => remove(c)} />)
        )}
      </div>
    </div>
  )
}

function CredentialRow({ credential, onDelete }: { credential: Credential; onDelete: () => void }) {
  const headerEntries = Object.entries(credential.headers ?? {})
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-3 text-xs">
      <div className="flex items-center gap-2">
        <span className="min-w-0 flex-1 truncate font-medium text-neutral-200">{credential.name}</span>
        <button onClick={onDelete} className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-neutral-400 hover:border-red-500 hover:text-red-400">
          Delete
        </button>
      </div>
      {credential.notes && <p className="mt-1 text-neutral-500">{credential.notes}</p>}
      {headerEntries.length > 0 && (
        <div className="mt-2 space-y-1">
          {headerEntries.map(([k, v]) => (
            <div key={k} className="flex items-center gap-2 font-mono text-[11px] text-neutral-400">
              <span className="text-neutral-600">{k}:</span>
              <span className="min-w-0 flex-1 truncate">{v}</span>
              <CopyButton text={v} />
            </div>
          ))}
        </div>
      )}
      {credential.cookie && (
        <div className="mt-2 flex items-center gap-2 font-mono text-[11px] text-neutral-400">
          <span className="text-neutral-600">Cookie:</span>
          <span className="min-w-0 flex-1 truncate">{credential.cookie}</span>
          <CopyButton text={credential.cookie} />
        </div>
      )}
    </div>
  )
}
