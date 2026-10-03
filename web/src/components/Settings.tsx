import { useEffect, useState } from 'react'
import { api } from '../api'
import type { SettingsInfo } from '../types'
import { applyMode, applyTheme, getStoredMode, getStoredTheme, THEMES, type Mode, type Theme } from '../theme'

// KeyCard (below) renders one API-key card: DNSDumpster and NVD share the
// exact same save/clear/status shape (see internal/api/settings.go's
// handleSetDNSDumpsterKey/handleSetNVDKey), so both render through it. The
// key itself is never sent back down from the server once saved (see
// store.SettingsInfo) -- only whether one is set -- so this can only ever
// show "configured" or offer to replace it, never redisplay it.
export function Settings() {
  const [info, setInfo] = useState<SettingsInfo | null>(null)

  useEffect(() => {
    api.getSettings().then(setInfo)
  }, [])

  return (
    // Scroll container: the app shell clips overflow, so each page must scroll itself
    <div className="h-full overflow-y-auto">
    <div className="mx-auto max-w-lg space-y-6 p-6">
      <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Settings</h1>

      <ModeToggle />
      <ThemePicker />

      <KeyCard
        title="DNSDumpster API key"
        description={
          <>
            Powers the DNSDumpster check on every scan's Overview tab (DNS footprint + per-IP ASN/geo data), and its subdomains
            are merged with crt.sh's before verification. Requires a key from{' '}
            <a href="https://dnsdumpster.com" className="text-sky-400 hover:text-sky-300" target="_blank" rel="noreferrer">
              dnsdumpster.com
            </a>
            . Scans run without one just skip that check.
          </>
        }
        configured={info?.dnsdumpsterApiKeySet ?? null}
        save={(apiKey) => api.setDNSDumpsterKey(apiKey)}
        onSaved={setInfo}
      />

      <KeyCard
        title="NVD API key"
        description={
          <>
            Raises the rate limit for the CVE lookups the Technologies tab runs against every fingerprinted product/version,
            from 5 to 50 requests per 30 seconds. Requires a key from{' '}
            <a
              href="https://nvd.nist.gov/developers/request-an-api-key"
              className="text-sky-400 hover:text-sky-300"
              target="_blank"
              rel="noreferrer"
            >
              nvd.nist.gov
            </a>
            . Scans run without one just look up CVEs more slowly.
          </>
        }
        configured={info?.nvdApiKeySet ?? null}
        save={(apiKey) => api.setNVDKey(apiKey)}
        onSaved={setInfo}
      />

      <KeyCard
        title="HaveIBeenPwned API key"
        description={
          <>
            Powers the Breach Check tab, which looks up email addresses against HaveIBeenPwned's breach database. Requires a
            key from{' '}
            <a href="https://haveibeenpwned.com/API/Key" className="text-sky-400 hover:text-sky-300" target="_blank" rel="noreferrer">
              haveibeenpwned.com
            </a>
            -- unlike DNSDumpster/NVD, this one is required: HIBP's breached-account endpoint has rejected keyless requests
            since 2024.
          </>
        }
        configured={info?.hibpApiKeySet ?? null}
        save={(apiKey) => api.setHIBPKey(apiKey)}
        onSaved={setInfo}
      />
    </div>
    </div>
  )
}

function KeyCard({
  title,
  description,
  configured,
  save,
  onSaved,
}: {
  title: string
  description: React.ReactNode
  configured: boolean | null
  save: (apiKey: string) => Promise<SettingsInfo>
  onSaved: (info: SettingsInfo) => void
}) {
  const [apiKey, setApiKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')

  const doSave = async (value: string) => {
    setSaving(true)
    setMessage('')
    try {
      const updated = await save(value)
      onSaved(updated)
      setApiKey('')
      setMessage(value === '' ? 'Cleared' : 'Saved')
    } catch (err) {
      setMessage(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
      <h2 className="text-sm font-medium text-neutral-100">{title}</h2>
      <p className="text-xs text-neutral-500">{description}</p>
      <p className="text-xs text-neutral-400">
        Status: {configured === null ? '…' : configured ? <span className="text-emerald-400">configured</span> : <span className="text-neutral-500">not configured</span>}
      </p>
      <div className="flex items-center gap-2 pt-1">
        <input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={configured ? 'Replace saved key…' : 'Paste API key…'}
          className="flex-1 rounded border border-neutral-700 bg-neutral-950 px-2.5 py-1.5 text-sm text-neutral-100 outline-none focus:border-sky-500"
        />
        <button
          onClick={() => doSave(apiKey)}
          disabled={saving || apiKey === ''}
          className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
        {configured && (
          <button
            onClick={() => doSave('')}
            disabled={saving}
            className="rounded border border-neutral-700 px-3 py-1.5 text-xs text-neutral-300 hover:border-red-500 hover:text-red-400 disabled:opacity-50"
          >
            Clear
          </button>
        )}
      </div>
      {message && <p className="text-xs text-neutral-500">{message}</p>}
    </div>
  )
}

// ModeToggle is light/dark's own control, independent of ThemePicker below
// -- every palette in THEMES supports both (see index.css: each theme is
// defined once per mode), so which one is active is a separate choice from
// which palette is active, per explicit product decision (there used to be
// a single "Dark"/"Light" pair of palette entries; those are gone now that
// every palette can be either).
function ModeToggle() {
  const [mode, setMode] = useState<Mode>(() => getStoredMode())

  const pick = (m: Mode) => {
    applyMode(m)
    setMode(m)
  }

  return (
    <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
      <h2 className="text-sm font-medium text-neutral-100">Appearance</h2>
      <p className="text-xs text-neutral-500">Light or dark mode -- applies to whichever theme is selected below.</p>
      <div className="flex gap-2 pt-1">
        {(['light', 'dark'] as Mode[]).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => pick(m)}
            className={`flex-1 rounded border px-3 py-2 text-center text-xs font-medium capitalize ${
              mode === m ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-950 text-neutral-300 hover:border-sky-600'
            }`}
          >
            {m}
          </button>
        ))}
      </div>
    </div>
  )
}

// ThemePicker is a per-browser display preference (see theme.ts) rather
// than an account setting -- it applies instantly and never touches the
// backend, unlike every KeyCard above it on this page.
function ThemePicker() {
  const [theme, setTheme] = useState<Theme>(() => getStoredTheme())

  const pick = (id: Theme) => {
    applyTheme(id)
    setTheme(id)
  }

  return (
    <div className="space-y-2 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
      <h2 className="text-sm font-medium text-neutral-100">Theme</h2>
      <p className="text-xs text-neutral-500">Changes how Aperture looks in this browser -- applies instantly, nothing to save.</p>
      <div className="grid grid-cols-2 gap-2 pt-1 sm:grid-cols-3">
        {THEMES.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => pick(t.id)}
            title={t.description}
            className={`rounded border px-3 py-2 text-left text-xs ${
              theme === t.id ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-950 text-neutral-300 hover:border-sky-600'
            }`}
          >
            <span className="block font-medium">{t.label}</span>
            <span className="mt-0.5 block text-[11px] text-neutral-500">{t.description}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
