// scannerNavStyle.ts is the scanner sidebar's layout preference -- the left
// nav inside a case that switches between Targets, Identify, and every
// scanner tab (see scannerNavData.ts for its contents, ScannerNav.tsx for
// the four renderings). Built the same way as navStyle.ts: a per-browser
// choice, persisted to localStorage, applied instantly, broadcast on change
// so the picker in Settings and the live sidebar inside an open case agree
// without a reload.
import { useEffect, useState } from 'react'

export type ScannerNavStyle = 'tiles' | 'list' | 'compact' | 'accordion'

export interface ScannerNavStyleMeta {
  id: ScannerNavStyle
  label: string
  description: string
}

// SCANNER_NAV_STYLES lists every sidebar layout in the order the picker
// shows them -- 'tiles' first since it's the sidebar's original shape.
export const SCANNER_NAV_STYLES: ScannerNavStyleMeta[] = [
  { id: 'tiles', label: 'Tiles', description: 'Two-column grid of icon tiles, grouped sections' },
  { id: 'list', label: 'List', description: 'Flat single-column list with inline group headers' },
  { id: 'compact', label: 'Compact Grid', description: 'Dense icon-only grid, label on hover' },
  { id: 'accordion', label: 'Accordion', description: 'One open group at a time, full-width rows' },
]

const STORAGE_KEY = 'aperture.scannerNavStyle'
const EVENT_NAME = 'aperture:scannernavstyle'
const DEFAULT_STYLE: ScannerNavStyle = 'tiles'

function isScannerNavStyle(value: string | null): value is ScannerNavStyle {
  return value !== null && SCANNER_NAV_STYLES.some((s) => s.id === value)
}

// getStoredScannerNavStyle reads the saved choice, falling back to the
// default on anything unexpected -- private browsing, blocked site data, or
// a stale/hand-edited value all land here rather than throwing.
export function getStoredScannerNavStyle(): ScannerNavStyle {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return isScannerNavStyle(stored) ? stored : DEFAULT_STYLE
  } catch {
    return DEFAULT_STYLE
  }
}

// applyScannerNavStyle persists the choice and broadcasts it on the same
// tab -- a plain localStorage write only fires the native 'storage' event in
// *other* tabs, so this is what lets the picker in Settings update a
// sidebar already open in this tab's case view.
export function applyScannerNavStyle(style: ScannerNavStyle) {
  try {
    localStorage.setItem(STORAGE_KEY, style)
  } catch {
    // A failed save just means the choice won't survive a reload.
  }
  window.dispatchEvent(new CustomEvent<ScannerNavStyle>(EVENT_NAME, { detail: style }))
}

// useScannerNavStyle subscribes a component to the current sidebar style:
// seeded from storage on mount, re-rendering on same-tab changes (the custom
// event) and cross-tab changes (the native 'storage' event).
export function useScannerNavStyle(): ScannerNavStyle {
  const [style, setStyle] = useState<ScannerNavStyle>(() => getStoredScannerNavStyle())

  useEffect(() => {
    const onCustom = (e: Event) => setStyle((e as CustomEvent<ScannerNavStyle>).detail)
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) setStyle(getStoredScannerNavStyle())
    }
    window.addEventListener(EVENT_NAME, onCustom)
    window.addEventListener('storage', onStorage)
    return () => {
      window.removeEventListener(EVENT_NAME, onCustom)
      window.removeEventListener('storage', onStorage)
    }
  }, [])

  return style
}
