import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { MouseEvent as ReactMouseEvent, ReactNode } from 'react'
import { showToast } from './toast'

export interface MenuItem {
  label: string
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
}
// 'separator' renders a thin divider between groups of related items.
export type MenuEntry = MenuItem | 'separator'

interface MenuState {
  x: number
  y: number
  items: MenuEntry[]
}

interface ContextMenuContextValue {
  // Components with something contextual to offer (a table row, a progress
  // bar, a scan card, ...) call this from their own onContextMenu handler.
  // React's synthetic event system still bubbles afterwards, so the handler
  // must also call e.stopPropagation() -- otherwise the root fallback below
  // would additionally fire and replace these items with the generic ones.
  openMenu: (e: ReactMouseEvent, items: MenuEntry[]) => void
}

const ContextMenuContext = createContext<ContextMenuContextValue | null>(null)

export function useContextMenu(): ContextMenuContextValue {
  const ctx = useContext(ContextMenuContext)
  if (!ctx) throw new Error('useContextMenu must be used within ContextMenuProvider')
  return ctx
}

// copyToClipboard is a small helper every context menu built with this
// module ends up wanting (copy a hostname/URL/domain) -- centralized here so
// every call site gets the same success/failure toast instead of each
// re-implementing it.
export function copyToClipboard(text: string, label = 'Copied') {
  navigator.clipboard
    .writeText(text)
    .then(() => showToast(`${label}: ${text}`, 'success'))
    .catch(() => showToast('Copy failed', 'error'))
}

// ContextMenuProvider replaces the browser's native right-click menu
// everywhere inside it: every right-click is intercepted (preventDefault),
// and either a caller-supplied contextual menu (via useContextMenu) or this
// component's own generic fallback is shown instead.
export function ContextMenuProvider({ children }: { children: ReactNode }) {
  const [menu, setMenu] = useState<MenuState | null>(null)
  const menuRef = useRef<HTMLDivElement | null>(null)

  const openMenu = useCallback((e: ReactMouseEvent, items: MenuEntry[]) => {
    e.preventDefault()
    setMenu({ x: e.clientX, y: e.clientY, items })
  }, [])

  const close = useCallback(() => setMenu(null), [])

  useEffect(() => {
    if (!menu) return
    const onMouseDown = () => close()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    const onScroll = () => close()
    window.addEventListener('mousedown', onMouseDown)
    window.addEventListener('keydown', onKey)
    window.addEventListener('scroll', onScroll, true)
    window.addEventListener('resize', close)
    return () => {
      window.removeEventListener('mousedown', onMouseDown)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('scroll', onScroll, true)
      window.removeEventListener('resize', close)
    }
  }, [menu, close])

  // Clamp the menu on-screen once its real size is known (it can't be
  // measured before the first render at the raw click position).
  useEffect(() => {
    if (!menu || !menuRef.current) return
    const rect = menuRef.current.getBoundingClientRect()
    const maxX = Math.max(4, window.innerWidth - rect.width - 4)
    const maxY = Math.max(4, window.innerHeight - rect.height - 4)
    const x = Math.min(menu.x, maxX)
    const y = Math.min(menu.y, maxY)
    if (x !== menu.x || y !== menu.y) setMenu((m) => (m ? { ...m, x, y } : m))
    // Only re-clamp when the menu's identity/content changes, not on every
    // render (setMenu above would otherwise re-trigger this effect forever).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [menu?.items, menu?.x, menu?.y])

  // fallbackItems backs any right-click nothing more specific claimed --
  // e.g. empty space in a tab, the nav bar, the login screen -- so the
  // native browser menu is never the thing that appears.
  const handleRootContextMenu = (e: ReactMouseEvent) => {
    openMenu(e, [
      { label: 'Reload page', onSelect: () => location.reload() },
      { label: 'Copy page URL', onSelect: () => copyToClipboard(location.href, 'Copied URL') },
    ])
  }

  return (
    <ContextMenuContext.Provider value={{ openMenu }}>
      <div onContextMenu={handleRootContextMenu} className="contents">
        {children}
      </div>
      {menu && (
        <div
          ref={menuRef}
          className="fixed z-[200] min-w-[190px] overflow-hidden rounded-md border border-neutral-700 bg-neutral-900 py-1 shadow-2xl"
          style={{ left: menu.x, top: menu.y }}
          onContextMenu={(e) => e.preventDefault()}
        >
          {menu.items.map((item, i) =>
            item === 'separator' ? (
              <div key={i} className="my-1 border-t border-neutral-800" />
            ) : (
              <button
                key={i}
                disabled={item.disabled}
                onClick={() => {
                  close()
                  item.onSelect()
                }}
                className={`block w-full px-3 py-1.5 text-left text-xs disabled:cursor-not-allowed disabled:opacity-40 ${
                  item.danger ? 'text-red-400 hover:bg-red-950/40' : 'text-neutral-200 hover:bg-neutral-800'
                }`}
              >
                {item.label}
              </button>
            ),
          )}
        </div>
      )}
    </ContextMenuContext.Provider>
  )
}
