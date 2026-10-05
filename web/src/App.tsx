import { useEffect, useState } from 'react'
import { api, ApiError } from './api'
import type { AuthUser } from './types'
import { CaseList } from './components/CaseList'
import { CaseView } from './components/CaseView'
import { Wordlists } from './components/Wordlists'
import { Login } from './components/Login'
import { Settings } from './components/Settings'
import { NotificationCenter } from './components/NotificationCenter'
import { ContextMenuProvider } from './contextMenu'
import { ToastHost } from './toast'
import { initNotifications, stopNotifications } from './notifications'

// View is a small discriminated union instead of a plain string so a view
// that needs an id (which case) carries it along rather than living in a
// second piece of state that could get out of sync.
type View = { name: 'caseList' } | { name: 'case'; caseId: string } | { name: 'wordlists' } | { name: 'settings' }

export default function App() {
  const [view, setView] = useState<View>({ name: 'caseList' })
  // undefined = still probing api.me() on load; null = signed out.
  const [user, setUser] = useState<AuthUser | null | undefined>(undefined)

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
      <div className="flex h-screen flex-col bg-neutral-950">
        <nav className="flex shrink-0 items-center gap-4 border-b border-neutral-800 px-4 py-2 text-sm">
          <button onClick={() => setView({ name: 'caseList' })} className="font-semibold text-neutral-100 hover:text-sky-400">
            Aperture
          </button>
          {(view.name === 'wordlists' || view.name === 'settings') && (
            <button onClick={() => setView({ name: 'caseList' })} className="text-neutral-400 hover:text-neutral-200">
              ← Back to cases
            </button>
          )}
          <div className="ml-auto flex items-center gap-4">
            <button onClick={() => setView({ name: 'wordlists' })} className={navClass(view.name === 'wordlists')}>
              Wordlists
            </button>
            <button onClick={() => setView({ name: 'settings' })} className={navClass(view.name === 'settings')}>
              Settings
            </button>
            <NotificationCenter />
            <span className="text-neutral-600">|</span>
            <span className="text-neutral-500">{user.email}</span>
            <button onClick={logout} className="text-neutral-400 hover:text-neutral-200">
              Log out
            </button>
          </div>
        </nav>

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

function navClass(active: boolean): string {
  return active ? 'text-sky-400' : 'text-neutral-400 hover:text-neutral-200'
}
