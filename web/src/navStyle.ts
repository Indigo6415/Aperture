// navStyle.ts is the navbar-appearance preference, built as a deliberate
// parallel to theme.ts: a per-browser choice (not an account setting) that is
// read on load, applied instantly, and persisted to localStorage with the
// same throw-safe wrappers. Unlike theme.ts -- whose choice lands on an
// <html> attribute that CSS keys off of -- the navbar's four layouts differ
// structurally (one is even a vertical rail), so the choice is consumed by a
// React component (see Navbar.tsx) rather than by CSS. Because the picker
// (Settings.tsx) and the consumer (App.tsx) live in different parts of the
// tree, applyNavStyle also broadcasts the change so the live navbar updates
// without a reload -- see useNavStyle below.
import { useEffect, useState } from 'react'

export type NavStyle = 'minimal' | 'rail' | 'segmented' | 'terminal'

export interface NavStyleMeta {
  id: NavStyle
  label: string
  description: string
  // orientation tells the app shell whether this style is a top bar
  // ('horizontal') or a left rail ('vertical'), which flips the outer flex
  // direction in App.tsx. Kept here next to each style so App never has to
  // hard-code which ids are rails.
  orientation: 'horizontal' | 'vertical'
}

// NAV_STYLES lists every navbar design in the order the picker shows them.
// Each is intentionally distinct in layout and tone -- restrained neutrals
// rather than bright accents -- so the set reads as four genuine choices,
// not one design in four colors.
export const NAV_STYLES: NavStyleMeta[] = [
  { id: 'minimal', label: 'Minimal', description: 'Monochrome top bar, hairline underline marks the active page', orientation: 'horizontal' },
  { id: 'rail', label: 'Side Rail', description: 'Vertical rail down the left edge with stacked links', orientation: 'vertical' },
  { id: 'segmented', label: 'Segmented', description: 'Centered pill-style segmented control in a slim top bar', orientation: 'horizontal' },
  { id: 'terminal', label: 'Terminal', description: 'Monospace, bracketed links with a command-line feel', orientation: 'horizontal' },
]

const NAVSTYLE_STORAGE_KEY = 'aperture.navStyle'
const NAVSTYLE_EVENT = 'aperture:navstyle'
const DEFAULT_NAVSTYLE: NavStyle = 'minimal'

function isNavStyle(value: string | null): value is NavStyle {
  // A guard rather than a cast so a stale or hand-edited storage value can't
  // smuggle an unknown id into a component that only handles the four above.
  return value !== null && NAV_STYLES.some((s) => s.id === value)
}

// getStoredNavStyle reads the saved choice, falling back to the default on
// anything unexpected. The try/catch mirrors theme.ts: private browsing or
// blocked site data throws on read, and a cosmetic preference is never worth
// crashing over.
export function getStoredNavStyle(): NavStyle {
  try {
    const stored = localStorage.getItem(NAVSTYLE_STORAGE_KEY)
    return isNavStyle(stored) ? stored : DEFAULT_NAVSTYLE
  } catch {
    return DEFAULT_NAVSTYLE
  }
}

// isVertical answers whether a given style wants the left-rail layout, so the
// app shell can switch between a column (top bar) and a row (rail) without
// knowing the individual ids.
export function isVertical(style: NavStyle): boolean {
  return NAV_STYLES.find((s) => s.id === style)?.orientation === 'vertical'
}

// applyNavStyle persists the choice and broadcasts it on the same tab. The
// broadcast is what lets the picker in Settings update the live navbar in
// App immediately -- a plain localStorage write fires the native 'storage'
// event only in *other* tabs, never the one that made the change.
export function applyNavStyle(style: NavStyle) {
  try {
    localStorage.setItem(NAVSTYLE_STORAGE_KEY, style)
  } catch {
    // A failed save just means the choice won't survive a reload, not a
    // reason to throw -- same stance as theme.ts.
  }
  window.dispatchEvent(new CustomEvent<NavStyle>(NAVSTYLE_EVENT, { detail: style }))
}

// useNavStyle subscribes a component to the current navbar style: it seeds
// from storage on mount and then re-renders whenever applyNavStyle fires,
// whether from this tab (the custom event) or another one (the native
// 'storage' event). This is the only React-aware part of the module, kept
// here so every consumer gets the subscription for free.
export function useNavStyle(): NavStyle {
  const [style, setStyle] = useState<NavStyle>(() => getStoredNavStyle())

  useEffect(() => {
    // Same-tab updates: applyNavStyle dispatches this with the new id.
    const onCustom = (e: Event) => setStyle((e as CustomEvent<NavStyle>).detail)
    // Cross-tab updates: re-read storage so a change made in another tab is
    // reflected here too.
    const onStorage = (e: StorageEvent) => {
      if (e.key === NAVSTYLE_STORAGE_KEY) setStyle(getStoredNavStyle())
    }
    window.addEventListener(NAVSTYLE_EVENT, onCustom)
    window.addEventListener('storage', onStorage)
    return () => {
      window.removeEventListener(NAVSTYLE_EVENT, onCustom)
      window.removeEventListener('storage', onStorage)
    }
  }, [])

  return style
}
