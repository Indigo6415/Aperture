import { useEffect, useState } from 'react'
import { api } from '../api'
import type { SettingsInfo } from '../types'

// Settings holds app-wide configuration that isn't tied to any one scan --
// currently just the DNSDumpster API key (see internal/recon/dnsdumpster.go),
// which every scan's DNSDumpster check reads back from the store at scan
// time. The key itself is never sent back down from the server once saved
// (see store.SettingsInfo) -- only whether one is set -- so this can only
// ever show "configured" or offer to replace it, never redisplay it.
export function Settings() {
  const [info, setInfo] = useState<SettingsInfo | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    api.getSettings().then(setInfo)
  }, [])

  const save = async () => {
    setSaving(true)
    setMessage('')
    try {
      const updated = await api.setDNSDumpsterKey(apiKey)
      setInfo(updated)
      setApiKey('')
      setMessage(updated.dnsdumpsterApiKeySet ? 'Saved' : 'Cleared')
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="mx-auto max-w-lg space-y-6 p-6">
      <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Settings</h1>

      <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <h2 className="text-sm font-medium text-neutral-100">DNSDumpster API key</h2>
        <p className="text-xs text-neutral-500">
          Powers the DNSDumpster check on every scan's Overview tab (DNS footprint + per-IP ASN/geo data), in addition to the
          built-in DNS/crt.sh lookups. Requires a key from{' '}
          <a href="https://dnsdumpster.com" className="text-sky-400 hover:text-sky-300" target="_blank" rel="noreferrer">
            dnsdumpster.com
          </a>
          . Scans run without one just skip that check.
        </p>
        <p className="text-xs text-neutral-400">
          Status:{' '}
          {info === null ? '…' : info.dnsdumpsterApiKeySet ? <span className="text-emerald-400">configured</span> : <span className="text-neutral-500">not configured</span>}
        </p>
        <div className="flex items-center gap-2 pt-1">
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={info?.dnsdumpsterApiKeySet ? 'Replace saved key…' : 'Paste API key…'}
            className="flex-1 rounded border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500"
          />
          <button
            onClick={save}
            disabled={saving || apiKey === ''}
            className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          {info?.dnsdumpsterApiKeySet && (
            <button
              onClick={async () => {
                setSaving(true)
                setMessage('')
                try {
                  setInfo(await api.setDNSDumpsterKey(''))
                  setMessage('Cleared')
                } finally {
                  setSaving(false)
                }
              }}
              disabled={saving}
              className="rounded border border-neutral-700 px-3 py-1.5 text-xs text-neutral-300 hover:border-red-500 hover:text-red-400 disabled:opacity-50"
            >
              Clear
            </button>
          )}
        </div>
        {message && <p className="text-xs text-neutral-500">{message}</p>}
      </div>
    </div>
  )
}
