import { useEffect, useRef, useState } from 'react'
import { IconBell } from './icons'
import { clearFeed, dismissNotification, getFeed, markAllRead, subscribeFeed, type FiredNotification } from '../notifications'

// NotificationCenter is the bell in the top nav: it shows a live unread badge
// and, when opened, the recent notifications any rule has fired this session
// (see notifications.ts). It is purely a reader of the engine's feed -- the
// engine fires notifications on its own; this just surfaces the backlog so one
// that toasted away while the operator was on another tab isn't lost.
export function NotificationCenter() {
  const [feed, setFeed] = useState<FiredNotification[]>(() => getFeed())
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  // Mirror the engine's feed into local state.
  useEffect(() => subscribeFeed(setFeed), [])

  // Close the dropdown on an outside click, so it behaves like a normal menu.
  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [open])

  const unread = feed.filter((n) => !n.read).length

  // Opening the center marks everything read (clears the badge).
  const toggle = () => {
    const next = !open
    setOpen(next)
    if (next && unread > 0) markAllRead()
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={toggle}
        title="Notifications"
        className={`relative flex items-center ${open ? 'text-sky-400' : 'text-neutral-400 hover:text-neutral-200'}`}
      >
        <IconBell className="h-4 w-4" />
        {/* Unread badge: only shown when something is waiting. */}
        {unread > 0 && (
          <span className="absolute -right-2 -top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-semibold text-white">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-7 z-[90] w-80 overflow-hidden rounded-lg border border-neutral-700 bg-neutral-900 shadow-xl">
          <div className="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-neutral-400">Notifications</span>
            {feed.length > 0 && (
              <button onClick={clearFeed} className="text-[11px] text-neutral-500 hover:text-neutral-300">
                Clear all
              </button>
            )}
          </div>
          <div className="max-h-96 overflow-y-auto">
            {feed.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-neutral-600">Nothing yet. Rules you configure in Settings → Notifications will show up here.</p>
            ) : (
              feed.map((n) => <NotificationRow key={n.id} n={n} />)
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// NotificationRow is one fired notification: a colored accent bar matching the
// rule's color, its rule name, message, and when it fired.
function NotificationRow({ n }: { n: FiredNotification }) {
  return (
    <div className="group flex items-start gap-2 border-b border-neutral-800/60 px-3 py-2 last:border-b-0" style={{ borderLeft: `3px solid ${n.color}` }}>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-xs font-medium text-neutral-200">{n.ruleName}</span>
          <span className="shrink-0 text-[10px] text-neutral-600">{relativeTime(n.at)}</span>
        </div>
        <p className="mt-0.5 break-words text-[11px] text-neutral-400">{n.message}</p>
      </div>
      {/* Dismiss one entry. Invisible until the row is hovered. */}
      <button
        onClick={() => dismissNotification(n.id)}
        className="shrink-0 text-neutral-600 opacity-0 transition group-hover:opacity-100 hover:text-neutral-300"
        title="Dismiss"
      >
        ×
      </button>
    </div>
  )
}

// relativeTime renders a compact "just now / 3m / 2h" stamp for the feed.
function relativeTime(at: number): string {
  const secs = Math.floor((Date.now() - at) / 1000)
  if (secs < 10) return 'just now'
  if (secs < 60) return `${secs}s`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h`
  return `${Math.floor(hours / 24)}d`
}
