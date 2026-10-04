import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import type {
  ActiveCallbackServer,
  CollabTLSStatus,
  CollaboratorAddresses,
  CollaboratorConfigResponse,
  CollaboratorInteraction,
} from '../types'
import { CopyButton } from './CopyButton'
import { inputBase } from '../formStyles'
import { showToast } from '../toast'

// pollIntervalMs is how often an active token's interactions are re-fetched
// -- short-polled rather than pushed, since there's no WebSocket-backed
// stream for this the way a job run has (see internal/api's
// handleCollaboratorPoll doc comment). The active-servers list itself (see
// refreshServers) is refreshed on this same cadence, so a server minted
// from any scanner's own Callback picker (see CallbackPicker.tsx) shows up
// here within one tick without this tab needing to do anything special.
const pollIntervalMs = 4000

// Provider selects which backend a minted token is served by: 'aperture' is
// this same instance's own listener (internal/collaborator.Registry, above),
// 'webhooksite' proxies https://webhook.site instead -- no domain/answer-IP
// setup at all, at the cost of interaction data living on a third party's
// servers rather than this process's own memory. Both mint into the same
// active-servers list and poll through the same `watch` function, since
// handlers_collaborator.go reshapes a webhook.site hit into the same
// CollaboratorInteraction JSON shape the native listener returns.
type Provider = 'aperture' | 'webhooksite'

// Collaborator is Aperture's own out-of-band interaction listener panel
// (see internal/collaborator): configure the DNS side's domain/answer-IP
// once, mint (or pick) a server, and watch for anything that reaches it
// over HTTP or DNS -- the same manual workflow Burp Suite's Collaborator
// client offers, for confirming a blind vulnerability (SSRF, XXE, a blind
// injection callback) that doesn't show up anywhere in a normal HTTP
// response. Every scanner's own Callback picker (see CallbackPicker.tsx)
// mints from the exact same backend session list this tab lists and
// refreshes from (see refreshServers) -- minting one from a scanner's
// dropdown shows up here too, not just in that scanner, and this tab
// auto-watches whichever server is newest. webhook.site is offered
// alongside Aperture's own listener for the zero-setup case: mint a token
// there and get a link back immediately, no domain or DNS configuration
// required.
export function Collaborator() {
  const [config, setConfig] = useState<CollaboratorConfigResponse | null>(null)
  const [domain, setDomain] = useState('')
  const [answerIp, setAnswerIp] = useState('')
  const [dnsAddr, setDnsAddr] = useState('')
  const [callbackBase, setCallbackBase] = useState('')
  const [addresses, setAddresses] = useState<CollaboratorAddresses | null>(null)
  const [tls, setTls] = useState<CollabTLSStatus | null>(null)
  const [tlsBusy, setTlsBusy] = useState(false)
  const [savingConfig, setSavingConfig] = useState(false)

  const [provider, setProvider] = useState<Provider>('aperture')
  const [servers, setServers] = useState<ActiveCallbackServer[]>([])
  const [watching, setWatching] = useState<ActiveCallbackServer | null>(null)
  const [interactions, setInteractions] = useState<CollaboratorInteraction[]>([])
  const [minting, setMinting] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  // seenTokens tracks every token this tab has already noticed, across
  // refreshes, so a refresh can tell "a server that was already here" apart
  // from "a server that just appeared" (minted from this tab's own button,
  // or from any scanner's Callback picker) -- only the latter should steal
  // focus away from whatever's currently being watched.
  const seenTokens = useRef<Set<string>>(new Set())

  useEffect(() => {
    api.getCollaboratorConfig().then((cfg) => {
      setConfig(cfg)
      setDomain(cfg.domain)
      setAnswerIp(cfg.answerIp)
      setDnsAddr(cfg.dnsAddr)
      setCallbackBase(cfg.callbackBase)
    })
    // Detected addresses are informational: a failed lookup just leaves the
    // suggestion buttons out, and the manual field still works.
    api.getCollaboratorAddresses().then(setAddresses).catch(() => setAddresses(null))
    api.getCollabTLS().then(setTls).catch(() => setTls(null))
  }, [])

  // toggleTLS turns the callback listener's HTTPS side on or off. Turning it on
  // generates a certificate on first use (server side).
  const toggleTLS = async (enabled: boolean) => {
    setTlsBusy(true)
    try {
      setTls(await api.setCollabTLS(enabled))
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setTlsBusy(false)
    }
  }

  // regenerateTLS replaces the certificate, which changes its fingerprint.
  const regenerateTLS = async () => {
    setTlsBusy(true)
    try {
      setTls(await api.regenerateCollabTLS())
      showToast('Certificate regenerated', 'success')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setTlsBusy(false)
    }
  }

  const watch = (s: ActiveCallbackServer) => {
    setWatching(s)
    setInteractions([])
    if (pollRef.current) clearInterval(pollRef.current)
    const poll = async () => {
      try {
        setInteractions(s.provider === 'webhooksite' ? await api.pollWebhookSite(s.token) : await api.pollCollaborator(s.token))
      } catch {
        // Transient poll failure -- the next tick retries on its own, no
        // need to surface a toast for every missed beat.
      }
    }
    poll()
    pollRef.current = setInterval(poll, pollIntervalMs)
  }

  // refreshServers re-lists every active callback server -- called on
  // mount, right after this tab mints one of its own, and on a standing
  // interval so a server minted elsewhere (any scanner's own Callback
  // picker) shows up here too. A brand-new token id this tab hasn't seen
  // before (newest-first, so servers[0]) is auto-watched -- same posture as
  // this tab's own "New token" button always did before there could be
  // more than one active server at a time.
  const refreshServers = async () => {
    let list: ActiveCallbackServer[]
    try {
      list = await api.listActiveCallbackServers()
    } catch {
      return
    }
    setServers(list)
    const newest = list[0]
    if (newest && !seenTokens.current.has(newest.token)) {
      watch(newest)
    }
    seenTokens.current = new Set(list.map((s) => s.token))
  }

  useEffect(() => {
    refreshServers()
    const id = setInterval(refreshServers, pollIntervalMs)
    // Stops both poll loops if the tab/component unmounts -- otherwise
    // they'd keep firing requests against a panel nobody's looking at.
    return () => {
      clearInterval(id)
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  // saveConfig persists the whole config. An optional callbackOverride saves a
  // different callback base without waiting for the field to update, so the
  // Use buttons take effect in one click.
  const saveConfig = async (callbackOverride?: string) => {
    const base = (callbackOverride ?? callbackBase).trim()
    setSavingConfig(true)
    try {
      // Send every field: the server overwrites all of them on PUT, so
      // omitting callbackBase here would silently clear it.
      const cfg = await api.setCollaboratorConfig({
        domain: domain.trim(),
        answerIp: answerIp.trim(),
        dnsAddr: dnsAddr.trim(),
        callbackBase: base,
      })
      setConfig(cfg)
      setCallbackBase(cfg.callbackBase)
      showToast(cfg.dnsActive ? 'Saved -- DNS listener active' : 'Saved', cfg.dnsActive ? 'success' : 'info')
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setSavingConfig(false)
    }
  }

  const mintToken = async () => {
    setMinting(true)
    try {
      if (provider === 'webhooksite') {
        await api.newWebhookSiteToken()
      } else {
        await api.newCollaboratorToken()
      }
      // The mint response itself has everything needed to watch it
      // immediately, but going through refreshServers keeps this tab and
      // every scanner's Callback picker looking at the exact same list
      // (and its newest-first ordering) rather than a client-constructed
      // guess at the Session shape the backend just registered.
      await refreshServers()
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setMinting(false)
    }
  }

  const removeServer = async (s: ActiveCallbackServer) => {
    // Only drops it from every scanner's Callback picker dropdown (and this
    // list) -- the token itself, and anything already recorded against it,
    // is untouched, see handleRemoveActiveCallbackServer's own doc comment.
    await api.removeActiveCallbackServer(s.token).catch(() => {})
    setServers((prev) => prev.filter((x) => x.token !== s.token))
    seenTokens.current.delete(s.token)
    if (watching?.token === s.token) {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
      setWatching(null)
      setInteractions([])
    }
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-2xl space-y-6">
        <div>
          <h1 className="text-sm font-semibold uppercase tracking-wide text-neutral-400">Collaborator</h1>
          <p className="mt-1 text-xs text-neutral-500">
            Aperture's own out-of-band interaction listener -- mint a token, point a blind payload (an SSRF target, an XXE
            external entity, a blind-injection callback) at it, and see whether anything actually reached it over HTTP or DNS.
            The HTTP listener works immediately, reachable at this same Aperture instance's own address -- the DNS listener
            below needs a real domain's NS records pointed at wherever Aperture is reachable from the internet to also catch a
            blind SSRF that only leaks via DNS resolution.
          </p>
        </div>

        <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-medium text-neutral-100">HTTPS (self-signed)</h2>
            {tls && (
              <label className="flex items-center gap-2 text-xs text-neutral-300">
                <input
                  type="checkbox"
                  checked={tls.enabled}
                  disabled={tlsBusy}
                  onChange={(e) => toggleTLS(e.target.checked)}
                  className="accent-sky-500"
                />
                {tls.enabled ? 'On' : 'Off'}
              </label>
            )}
          </div>
          <p className="text-[11px] text-neutral-600">
            Serves HTTPS on the same callback port, so an https:// callback reaches the listener. The certificate is
            self-signed, so the calling side has to skip certificate verification (curl -k, verify=False). It's stored in
            Aperture's database, and turning HTTPS off keeps it so the fingerprint stays the same when re-enabled.
          </p>
          {tls?.cert && (
            <div className="space-y-1 text-[11px] text-neutral-500">
              <div>
                Fingerprint (SHA-256): <code className="break-all text-neutral-300">{tls.cert.fingerprint}</code>
              </div>
              <div>
                Valid until: <span className="text-neutral-300">{new Date(tls.cert.notAfter).toLocaleDateString()}</span>
              </div>
              <div>
                Names: <span className="text-neutral-300">{tls.cert.subjects.join(', ')}</span>
              </div>
            </div>
          )}
          {tls?.hasCert && (
            <button
              onClick={regenerateTLS}
              disabled={tlsBusy}
              className="rounded border border-neutral-700 px-3 py-1.5 text-xs text-neutral-200 hover:bg-neutral-800 disabled:opacity-50"
            >
              Regenerate certificate
            </button>
          )}
        </div>

        <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
          <h2 className="text-sm font-medium text-neutral-100">Callback address</h2>
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">Callback base URL</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              The address targets call back to -- your LAN IP or public IP with the forwarded port, e.g. http://192.168.1.20:8338
              or http://203.0.113.7:8338. The callback listener binds on -collab-addr (0.0.0.0:8338 by default). Leave empty to
              use the address this UI was opened on, which only works for targets that can reach it.
            </span>
            <input
              value={callbackBase}
              onChange={(e) => setCallbackBase(e.target.value)}
              placeholder="http://203.0.113.7:8338"
              className={`mt-1 ${inputBase}`}
            />
          </label>
          {addresses && (
            <div className="space-y-1.5 text-[11px]">
              {addresses.localBase ? (
                <div className="flex items-center gap-2">
                  <span className="text-neutral-500">Local (LAN):</span>
                  <code className="text-neutral-300">{addresses.localBase}</code>
                  <button onClick={() => saveConfig(addresses.localBase!)} disabled={savingConfig} className="text-sky-400 hover:text-sky-300 disabled:opacity-50">
                    Use &amp; save
                  </button>
                </div>
              ) : (
                <p className="text-neutral-600">No LAN IPv4 address detected.</p>
              )}
              {addresses.publicBase ? (
                <div className="flex items-center gap-2">
                  <span className="text-neutral-500">Public:</span>
                  <code className="text-neutral-300">{addresses.publicBase}</code>
                  <button onClick={() => saveConfig(addresses.publicBase!)} disabled={savingConfig} className="text-sky-400 hover:text-sky-300 disabled:opacity-50">
                    Use &amp; save
                  </button>
                </div>
              ) : (
                <p className="text-neutral-600">Public IP not detected{addresses.publicError ? ` (${addresses.publicError})` : ''}.</p>
              )}
              <p className="text-neutral-600">
                Public needs the router to forward port {addresses.collabPort} to this machine.
              </p>
            </div>
          )}
        </div>

        <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
          <h2 className="text-sm font-medium text-neutral-100">DNS listener configuration</h2>
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">Domain</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              A domain (or subdomain) you control, with its NS records pointed at wherever this Aperture instance is reachable
              from the internet.
            </span>
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="collab.example.com" className={`mt-1 ${inputBase}`} />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">Answer IP</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              This host's own public IP -- what an A-record query for a token's hostname resolves to, so a payload that
              completes its connection lands back on this same listener.
            </span>
            <input value={answerIp} onChange={(e) => setAnswerIp(e.target.value)} placeholder="203.0.113.10" className={`mt-1 ${inputBase}`} />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-neutral-300">DNS bind address</span>
            <span className="mt-0.5 block text-[11px] text-neutral-600">
              Defaults to :53 -- the standard DNS port, which usually needs elevated privileges to bind.
            </span>
            <input value={dnsAddr} onChange={(e) => setDnsAddr(e.target.value)} placeholder=":53" className={`mt-1 ${inputBase}`} />
          </label>
          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={() => saveConfig()}
              disabled={savingConfig}
              className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {savingConfig ? 'Saving…' : 'Save'}
            </button>
            {config && (
              <span className={`text-xs ${config.dnsActive ? 'text-emerald-400' : 'text-neutral-500'}`}>
                {config.dnsActive ? 'DNS listener active' : config.domain ? 'DNS listener not running' : 'DNS listener not configured'}
              </span>
            )}
          </div>
          {config?.dnsError && <p className="text-xs text-red-400">{config.dnsError}</p>}
        </div>

        <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-medium text-neutral-100">Active callback servers</h2>
            <button
              onClick={mintToken}
              disabled={minting}
              className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {minting ? 'Minting…' : 'New token'}
            </button>
          </div>
          <p className="text-[11px] text-neutral-600">
            Every server minted from here or from any scanner's own Callback picker shows up below -- this list is shared, so
            pointing a scan at one of these (instead of letting it manage its own throwaway token) means watching it live here
            works too.
          </p>

          <div className="flex items-center gap-1 rounded border border-neutral-800 bg-neutral-950 p-1 text-xs">
            <ProviderTab label="Aperture" active={provider === 'aperture'} onClick={() => setProvider('aperture')} />
            <ProviderTab label="webhook.site" active={provider === 'webhooksite'} onClick={() => setProvider('webhooksite')} />
          </div>
          {provider === 'webhooksite' && (
            <p className="text-[11px] text-neutral-600">
              Mints a token via webhook.site's own API -- no domain/DNS setup needed, but interaction data is stored on their
              servers rather than this instance's own memory.
            </p>
          )}

          {servers.length === 0 && <p className="text-xs text-neutral-600">No active callback servers yet.</p>}
          {servers.length > 0 && (
            <ul className="space-y-1.5">
              {servers.map((s) => (
                <li
                  key={s.token}
                  className={`flex items-center gap-2 rounded border px-2 py-1.5 text-xs ${
                    watching?.token === s.token ? 'border-sky-600 bg-sky-950/30' : 'border-neutral-800 bg-neutral-950'
                  }`}
                >
                  <button onClick={() => watch(s)} className="min-w-0 flex-1 truncate text-left">
                    <span className="font-medium text-neutral-200">{s.label}</span>
                    <span className="ml-1.5 text-neutral-500">({s.provider})</span>
                  </button>
                  {watching?.token === s.token && (
                    <span className="shrink-0 text-[10px] uppercase tracking-wide text-sky-400">Watching</span>
                  )}
                  <button
                    onClick={() => removeServer(s)}
                    className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-400 hover:border-red-500 hover:text-red-400"
                  >
                    Stop
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {watching && (
          <div className="space-y-3 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
            <h2 className="text-sm font-medium text-neutral-100">Watching: {watching.label}</h2>
            <div className="space-y-2">
              {watching.links?.localhost && <CallbackRow label="Localhost" value={watching.links.localhost} />}
              {watching.links?.private && <CallbackRow label="Private (LAN)" value={watching.links.private} />}
              {watching.links?.public && <CallbackRow label="Public" value={watching.links.public} />}
              {watching.links?.localhostTls && <CallbackRow label="Localhost (HTTPS)" value={watching.links.localhostTls} />}
              {watching.links?.privateTls && <CallbackRow label="Private (HTTPS)" value={watching.links.privateTls} />}
              {watching.links?.publicTls && <CallbackRow label="Public (HTTPS)" value={watching.links.publicTls} />}
              {!watching.links && <CallbackRow label="HTTP callback" value={watching.httpCallback} />}
              {watching.viewUrl ? (
                <a href={watching.viewUrl} target="_blank" rel="noreferrer" className="block text-[11px] text-sky-400 hover:text-sky-300">
                  Open on webhook.site →
                </a>
              ) : watching.dnsHostname ? (
                <CallbackRow label="DNS hostname" value={watching.dnsHostname} />
              ) : (
                <p className="text-[11px] text-neutral-600">DNS hostname unavailable -- configure a domain above to enable it.</p>
              )}
              <p className="text-[11px] text-neutral-600">Polling every {pollIntervalMs / 1000}s for interactions…</p>
            </div>

            {interactions.length > 0 && (
              <ul className="space-y-2">
                {interactions.map((hit) => (
                  <InteractionRow key={hit.id} hit={hit} />
                ))}
              </ul>
            )}
            {interactions.length === 0 && <p className="text-xs text-neutral-600">No interactions yet.</p>}
          </div>
        )}
      </div>
    </div>
  )
}

function ProviderTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 rounded px-2 py-1 font-medium transition-colors ${
        active ? 'bg-sky-600 text-white' : 'text-neutral-400 hover:text-neutral-200'
      }`}
    >
      {label}
    </button>
  )
}

function CallbackRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 rounded border border-neutral-800 bg-neutral-950 p-2">
      <span className="shrink-0 text-[10px] uppercase tracking-wide text-neutral-600">{label}</span>
      <code className="min-w-0 flex-1 break-all text-[11px] text-amber-300">{value}</code>
      <CopyButton text={value} />
    </div>
  )
}

function InteractionRow({ hit }: { hit: CollaboratorInteraction }) {
  return (
    <li className="rounded border border-emerald-800 bg-emerald-950/30 p-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded border border-emerald-700 bg-emerald-950/60 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-300">
          {hit.protocol}
        </span>
        <span className="font-mono text-neutral-300">{hit.remoteAddr}</span>
        <span className="text-neutral-600">{new Date(hit.timestamp).toLocaleString()}</span>
        {hit.identifier && (
          <span
            className="rounded border border-sky-800 bg-sky-950/40 px-1.5 py-0.5 font-mono text-[10px] text-sky-300"
            title="Which test this hit is attributed to -- a shared callback server embeds this alongside its token so concurrent tests stay distinguishable"
          >
            {hit.identifier}
          </span>
        )}
      </div>
      {hit.protocol === 'http' ? (
        <p className="mt-1 break-all text-neutral-400">
          {hit.method} {hit.path}
          {hit.query ? `?${hit.query}` : ''}
        </p>
      ) : (
        <p className="mt-1 break-all text-neutral-400">
          {hit.queryType} {hit.queryName}
        </p>
      )}
    </li>
  )
}
