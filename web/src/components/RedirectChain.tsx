import type { ChainHop } from '../types'
import { SendToTesterButton } from './SendToTesterButton'
import { useContextMenu } from '../contextMenu'
import { sendToTester } from '../testerHandoff'

const KIND_LABEL: Record<ChainHop['kind'], string> = {
  probe: 'Probe',
  redirect: 'Redirect',
  callback: 'Callback',
}

// formatMs renders a duration compactly. Sub-millisecond values read as
// "<1 ms" rather than "0 ms", since a localhost hop can genuinely be that fast.
function formatMs(ms: number): string {
  if (ms < 1) return '<1 ms'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

// statusClass colors a status code by its class, so a 302 hop and a 500 hop
// read differently at a glance. A missing code (a hop that errored) is muted.
function statusClass(code?: number): string {
  if (code === undefined) return 'text-neutral-500'
  if (code >= 500) return 'text-red-400'
  if (code >= 400) return 'text-orange-400'
  if (code >= 300) return 'text-amber-300'
  if (code >= 200) return 'text-emerald-400'
  return 'text-neutral-400'
}

// RedirectChain shows every request from an open-redirect probe to its
// callback as a waterfall: one row per request, with its status, how long it
// took, and where it started relative to the probe. Each bar is placed on a
// shared timeline scaled to the whole chain, so a slow hop stands out against
// the rest.
export function RedirectChain({ chain }: { chain: ChainHop[] }) {
  const { openMenu } = useContextMenu()
  // The timeline ends at whichever request finishes last. The floor of 1 keeps
  // the percentages finite if every hop reported zero time.
  const total = Math.max(1, ...chain.map((h) => h.offsetMs + h.durationMs))

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className="text-[10px] uppercase tracking-wide text-neutral-600">Redirect chain</span>
        <span className="text-[11px] text-neutral-500">
          {chain.length} request{chain.length === 1 ? '' : 's'}
        </span>
        <span className="text-[11px] text-neutral-500">
          Total <span className="font-mono text-neutral-300">{formatMs(total)}</span>
        </span>
      </div>

      <ol className="space-y-1.5">
        {chain.map((h) => (
          // Right-click anywhere on the hop offers Send to Tester. stopPropagation
          // keeps the provider's root fallback menu from replacing this one.
          <li
            key={h.step}
            className="rounded border border-neutral-800 bg-neutral-900/60 p-2"
            onContextMenu={(e) => {
              e.stopPropagation()
              openMenu(e, [{ label: 'Send to Tester', onSelect: () => sendToTester(h.url, h.method || 'GET', h.headers) }])
            }}
          >
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="font-mono text-neutral-600">{h.step}</span>
              <span className="rounded border border-neutral-700 px-1.5 py-px text-[10px] uppercase tracking-wide text-neutral-400">
                {KIND_LABEL[h.kind]}
              </span>
              <span className="font-mono text-neutral-400">{h.method}</span>
              <span className={`font-mono font-semibold ${statusClass(h.statusCode)}`}>
                {h.error ? 'error' : h.statusCode ?? '—'}
              </span>
              <span className="ml-auto font-mono text-neutral-300">{formatMs(h.durationMs)}</span>
              <SendToTesterButton url={h.url} method={h.method} headers={h.headers} />
            </div>

            {/* Bar position is when the request went out; its width is how long it took. */}
            <div className="relative mt-1.5 h-1.5 rounded bg-neutral-800">
              <div
                className={`absolute inset-y-0 rounded ${h.error ? 'bg-red-500/70' : 'bg-sky-500/70'}`}
                style={{
                  left: `${(h.offsetMs / total) * 100}%`,
                  width: `${Math.max((h.durationMs / total) * 100, 0.5)}%`,
                }}
              />
            </div>

            <p className="mt-1.5 break-all font-mono text-[11px] text-neutral-300">{h.url}</p>
            {h.location && <p className="mt-0.5 break-all font-mono text-[11px] text-neutral-500">→ {h.location}</p>}
            {h.error && <p className="mt-0.5 break-all text-[11px] text-red-400">{h.error}</p>}
            <p className="mt-0.5 text-[10px] text-neutral-600">started +{formatMs(h.offsetMs)}</p>

            {h.headers && Object.keys(h.headers).length > 0 && (
              <details className="mt-1">
                <summary className="cursor-pointer text-[11px] text-neutral-500">
                  Sent headers ({Object.keys(h.headers).length})
                </summary>
                <dl className="mt-1 space-y-0.5 font-mono text-[11px]">
                  {Object.entries(h.headers).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <dt className="shrink-0 text-neutral-500">{k}:</dt>
                      <dd className="min-w-0 break-all text-neutral-300">{v}</dd>
                    </div>
                  ))}
                </dl>
              </details>
            )}
          </li>
        ))}
      </ol>
    </div>
  )
}
