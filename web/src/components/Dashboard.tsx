import { useEffect, useState } from 'react'
import { api } from '../api'
import type { ScanSummary } from '../types'

// Dashboard is the app's home view: a single domain input that kicks off a
// scan immediately, plus a list of recent scans to jump back into. This is
// the "you only have to enter a domain" entry point the rest of the app's
// tools (flow editor, wordlists) support rather than gate.
export function Dashboard({ onOpen }: { onOpen: (scanId: string) => void }) {
  const [domain, setDomain] = useState('')
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')
  const [scans, setScans] = useState<ScanSummary[]>([])

  useEffect(() => {
    api.listScans().then(setScans)
  }, [])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const target = domain.trim()
    if (!target) return
    setStarting(true)
    setError('')
    try {
      const { scanId } = await api.startScan(target)
      onOpen(scanId)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="mx-auto flex h-full max-w-2xl flex-col items-center justify-center gap-10 overflow-y-auto px-6 py-10">
      <div className="w-full text-center">
        <h1 className="mb-2 text-3xl font-semibold text-neutral-100">Aperture</h1>
        <p className="mb-8 text-sm text-neutral-500">
          Enter a domain — DNS, TLS, subdomains, WHOIS, and content discovery start immediately.
        </p>
        <form onSubmit={submit} className="flex gap-2">
          <input
            autoFocus
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
            className="flex-1 rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-3 text-lg text-neutral-100 outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={starting || !domain.trim()}
            className="rounded-lg bg-sky-600 px-6 py-3 text-lg font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {starting ? 'Starting…' : 'Scan'}
          </button>
        </form>
        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      </div>

      {scans.length > 0 && (
        <div className="w-full">
          <h2 className="mb-2 px-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">Recent scans</h2>
          <div className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
            {scans.map((s) => (
              <div
                key={s.id}
                onClick={() => onOpen(s.id)}
                className="flex cursor-pointer items-center justify-between px-4 py-3 hover:bg-neutral-900"
              >
                <p className="text-sm font-medium text-neutral-100">{s.domain}</p>
                <p className="text-xs text-neutral-500">{new Date(s.createdAt).toLocaleString()}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
