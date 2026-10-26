import { useEffect, useState } from 'react'
import { api, ApiError } from './api'
import type { AuthUser } from './types'
import { CaseList } from './components/CaseList'
import { CaseView } from './components/CaseView'
import { Wordlists } from './components/Wordlists'
import { Login } from './components/Login'
import { Settings } from './components/Settings'
import { Navbar } from './components/Navbar'
import { ContextMenuProvider } from './contextMenu'
import { ToastHost } from './toast'
import { initNotifications, stopNotifications } from './notifications'
import { isVertical, useNavStyle } from './navStyle'

// View is a small discriminated union instead of a plain string so a view
// that needs an id (which case) carries it along rather than living in a
// second piece of state that could get out of sync. Exported so Navbar.tsx
// (which renders the active view's highlight/back-button) can share it
// instead of redeclaring an equivalent type that could drift from this one.
export type View = { name: 'caseList' } | { name: 'case'; caseId: string } | { name: 'wordlists' } | { name: 'settings' }

export default function App() {
  const [view, setView] = useState<View>({ name: 'caseList' })
  // undefined = still probing api.me() on load; null = signed out.
  const [user, setUser] = useState<AuthUser | null | undefined>(undefined)
  // Only the orientation (horizontal top bar vs. vertical rail) matters up
  // here -- which of the four styles that resolves to, and everything about
  // how it looks, is Navbar's own concern (see navStyle.ts/Navbar.tsx).
  const navStyle = useNavStyle()

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch((err) => {
        // Any failure other than "not signed in" (401) would otherwise be
        // silently swallowed into the login screen with no way to tell --
        // rethrowing keeps a genuine backend outage visible instead.
        if (err instanceof ApiError && err.status === 401) {
          setUser(null)
          return
        }
        throw err
      })
  }, [])

  // Start the notification engine once a user is authenticated (the global
  // events socket it opens needs the session cookie), and tear it down on
  // logout so a later session starts clean.
  useEffect(() => {
    if (user) {
      initNotifications()
      return () => stopNotifications()
    }
  }, [user])

  const logout = async () => {
    await api.logout()
    setUser(null)
    setView({ name: 'caseList' })
  }

  // ContextMenuProvider/ToastHost wrap every branch below (including the
  // loading/login screens) so the native right-click menu is suppressed
  // everywhere in the app, not just once a user is signed in.
  if (user === undefined) {
    return (
      <ContextMenuProvider>
        <div className="flex h-screen items-center justify-center bg-neutral-950 text-neutral-500">Loading…</div>
        <ToastHost />
      </ContextMenuProvider>
    )
  }
  if (user === null) {
    return (
      <ContextMenuProvider>
        <Login onLoggedIn={setUser} />
        <ToastHost />
      </ContextMenuProvider>
    )
  }

  return (
    <ContextMenuProvider>
      {/* The rail navbar style is a left sidebar rather than a top bar, so the
          outer shell needs to stack as a row instead of a column whenever
          it's active -- see navStyle.ts's isVertical. Every other style is
          horizontal and gets the original column layout. */}
      <div className={`flex h-screen bg-neutral-950 ${isVertical(navStyle) ? 'flex-row' : 'flex-col'}`}>
        <Navbar view={view} user={user} onNavigate={setView} onLogout={logout} />

        <div className="flex-1 overflow-hidden">
          {view.name === 'caseList' && <CaseList onOpen={(caseId) => setView({ name: 'case', caseId })} />}
          {view.name === 'case' && <CaseView caseId={view.caseId} />}
          {view.name === 'wordlists' && <Wordlists />}
          {view.name === 'settings' && <Settings />}
        </div>
      </div>
      <ToastHost />
    </ContextMenuProvider>
  )
}
