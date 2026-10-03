import { useState } from 'react'
import { api } from '../api'
import type { ActiveCallbackServer, CallbackSelection } from '../types'
import { showToast } from '../toast'

// CallbackPicker is the toggleable "Callback" button every OOB-capable
// scanner mounts (SSRF, Open Redirect, JWT Scanner): off by default (today's
// auto-managed/manual-only behavior, unchanged), toggling it open shows a
// dropdown of every currently active callback server (minted from here or
// from the Collaborator tab -- see handleListActiveCallbackServers),
// letting one long-lived, shared listener be picked and watched manually
// in the Collaborator tab while a scan runs against it. Selecting one sets
// `value`; the parent scanner includes it as the request's own "callback"
// field, and each test embeds a distinguishing identifier alongside it so a
// later hit in the Collaborator tab can be attributed back to the exact
// test that caused it (see CollaboratorInteraction.identifier).
export function CallbackPicker({
  value,
  onChange,
  className,
}: {
  value: CallbackSelection | null
  onChange: (value: CallbackSelection | null) => void
  className?: string
}) {
  const [open, setOpen] = useState(false)
  const [servers, setServers] = useState<ActiveCallbackServer[]>([])
  const [loading, setLoading] = useState(false)
  const [minting, setMinting] = useState<'aperture' | 'webhooksite' | null>(null)
  // label is only for display next to the toggle button once something's
  // selected -- value itself (provider+token) is all the parent/request
  // payload actually needs.
  const [label, setLabel] = useState('')

  const refresh = async () => {
    setLoading(true)
    try {
      setServers(await api.listActiveCallbackServers())
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setLoading(false)
    }
  }

  const toggleOpen = () => {
    const next = !open
    setOpen(next)
    // Refetch every time it's opened -- a server minted elsewhere (the
    // Collaborator tab, another tab's own CallbackPicker) since the last
    // time this one was open should still show up.
    if (next) refresh()
  }

  const select = (s: ActiveCallbackServer) => {
    onChange({ provider: s.provider, token: s.token })
    setLabel(s.label)
    setOpen(false)
  }

  const clear = () => {
    onChange(null)
    setLabel('')
  }

  const mintNew = async (provider: 'aperture' | 'webhooksite') => {
    setMinting(provider)
    try {
      if (provider === 'webhooksite') {
        const site = await api.newWebhookSiteToken()
        onChange({ provider: 'webhooksite', token: site.uuid })
        setLabel('webhook.site ' + site.uuid.slice(0, 8))
      } else {
        const token = await api.newCollaboratorToken()
        onChange({ provider: 'aperture', token: token.token })
        setLabel('Aperture ' + token.token.slice(0, 6))
      }
      setOpen(false)
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setMinting(null)
    }
  }

  return (
    <div className={`relative inline-block ${className ?? ''}`}>
      <button
        type="button"
        onClick={toggleOpen}
        title="Point this scanner's out-of-band tests at a shared callback server, watchable live in the Collaborator tab"
        className={`rounded border px-2.5 py-1 text-xs font-medium ${
          value ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
        }`}
      >
        Callback{value ? `: ${label || value.token.slice(0, 8)}` : ''}
      </button>

      {open && (
        <div className="absolute z-10 mt-1 w-72 rounded-lg border border-neutral-700 bg-neutral-900 p-2 shadow-lg">
          {value && (
            <button
              type="button"
              onClick={clear}
              className="mb-1 block w-full rounded px-2 py-1 text-left text-[11px] text-red-400 hover:bg-neutral-800"
            >
              Clear selection
            </button>
          )}
          {loading && <p className="px-2 py-1 text-[11px] text-neutral-500">Loading…</p>}
          {!loading && servers.length === 0 && (
            <p className="px-2 py-1 text-[11px] text-neutral-500">No active callback servers -- mint one below.</p>
          )}
          {!loading && servers.length > 0 && (
            <ul className="max-h-48 space-y-0.5 overflow-y-auto">
              {servers.map((s) => (
                <li key={s.token}>
                  <button
                    type="button"
                    onClick={() => select(s)}
                    className={`block w-full rounded px-2 py-1 text-left text-[11px] hover:bg-neutral-800 ${
                      value?.token === s.token ? 'bg-sky-950/40 text-sky-300' : 'text-neutral-300'
                    }`}
                  >
                    <span className="font-medium">{s.label}</span>
                    <span className="ml-1 text-neutral-500">({s.provider})</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-2 flex items-center gap-1.5 border-t border-neutral-800 pt-2">
            <button
              type="button"
              onClick={() => mintNew('aperture')}
              disabled={minting !== null}
              className="flex-1 rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 hover:border-sky-600 disabled:opacity-50"
            >
              {minting === 'aperture' ? 'Minting…' : '+ New (Aperture)'}
            </button>
            <button
              type="button"
              onClick={() => mintNew('webhooksite')}
              disabled={minting !== null}
              className="flex-1 rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 hover:border-sky-600 disabled:opacity-50"
            >
              {minting === 'webhooksite' ? 'Minting…' : '+ New (webhook.site)'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
