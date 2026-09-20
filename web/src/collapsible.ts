import { useEffect, useState } from 'react'

// useCollapsible backs every collapsible side panel / launcher form in the
// app (TargetProgressPanel, the tool-tab launcher, JwtScan/Probe's form
// column) with one consistent, persisted open/closed flag instead of each
// panel inventing its own useState -- so a user's "keep this collapsed"
// choice survives switching tabs/cases and reloading the page, and every
// panel's toggle behaves identically.
//
// key should be a short, stable, panel-specific string (e.g.
// `launcher.feroxbuster`, `targetProgress`, `jwtscan.form`) -- namespaced
// under `aperture.collapse.` in localStorage so it can't collide with
// unrelated keys.
export function useCollapsible(key: string, defaultOpen: boolean): [boolean, (next: boolean) => void] {
  const storageKey = `aperture.collapse.${key}`
  const [open, setOpenState] = useState(() => {
    try {
      const stored = localStorage.getItem(storageKey)
      return stored === null ? defaultOpen : stored === 'open'
    } catch {
      return defaultOpen
    }
  })

  const setOpen = (next: boolean) => {
    setOpenState(next)
    try {
      localStorage.setItem(storageKey, next ? 'open' : 'closed')
    } catch {
      // Best-effort only -- a private window or blocked storage just means
      // the preference doesn't persist, not that the toggle should fail.
    }
  }

  return [open, setOpen]
}

// useAutoExpandOnce flips a collapsed panel open exactly once, the first
// time `trigger` becomes true after mount -- e.g. TargetProgressPanel
// expanding itself the first time a job starts running, so a user who left
// it collapsed doesn't miss that something just started. Never re-collapses
// or re-expands on its own after that; the user's own toggle always wins
// from then on.
export function useAutoExpandOnce(trigger: boolean, setOpen: (next: boolean) => void) {
  const [firedOnce, setFiredOnce] = useState(false)
  useEffect(() => {
    if (trigger && !firedOnce) {
      setFiredOnce(true)
      setOpen(true)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trigger, firedOnce])
}

// useAutoCollapseOnce is useAutoExpandOnce's mirror: the first time
// `trigger` becomes true after mount, the panel is collapsed -- used by
// JwtScan/Probe's form column, which starts open (there's nothing else to
// look at) and collapses itself once the first result arrives so the
// results column gets the width. A user who re-expands it afterward is
// never overridden again -- this only ever fires once.
export function useAutoCollapseOnce(trigger: boolean, setOpen: (next: boolean) => void) {
  const [firedOnce, setFiredOnce] = useState(false)
  useEffect(() => {
    if (trigger && !firedOnce) {
      setFiredOnce(true)
      setOpen(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trigger, firedOnce])
}
