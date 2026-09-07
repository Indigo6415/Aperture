import { useEffect, useState } from 'react'
import { api, ApiError } from './api'
import type { AuthUser } from './types'
import { Dashboard } from './components/Dashboard'
import { ScanView } from './components/ScanView'
import { Wordlists } from './components/Wordlists'
import { GraphView } from './components/GraphView'
import { Login } from './components/Login'
import { Settings } from './components/Settings'

// View is a small discriminated union instead of a plain string so a view
// that needs an id (which scan) carries it along rather than living in a
// second piece of state that could get out of sync. Graph is scoped to one
// scan (matching the rest of the app) so it carries that scan's id too.
type View = { name: 'dashboard' } | { name: 'scan'; scanId: string } | { name: 'wordlists' } | { name: 'settings' } | { name: 'graph'; scanId: string }

export default function App() {
  const [view, setView] = useState<View>({ name: 'dashboard' })
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

  const logout = async () => {
    await api.logout()
    setUser(null)
    setView({ name: 'dashboard' })
  }

  if (user === undefined) {
    return <div className="flex h-screen items-center justify-center bg-neutral-950 text-neutral-500">Loading…</div>
  }
  if (user === null) {
    return <Login onLoggedIn={setUser} />
  }

  return (
    <div className="flex h-screen flex-col bg-neutral-950">
      <nav className="flex shrink-0 items-center gap-4 border-b border-neutral-800 px-4 py-2 text-sm">
        <button onClick={() => setView({ name: 'dashboard' })} className="font-semibold text-neutral-100 hover:text-sky-400">
          Aperture
        </button>
        {view.name === 'graph' && (
          <button onClick={() => setView({ name: 'scan', scanId: view.scanId })} className="text-neutral-400 hover:text-neutral-200">
            ← Back to scan
          </button>
        )}
        {(view.name === 'wordlists' || view.name === 'settings') && (
          <button onClick={() => setView({ name: 'dashboard' })} className="text-neutral-400 hover:text-neutral-200">
            ← Back to dashboard
          </button>
        )}
        <div className="ml-auto flex items-center gap-4">
          <button onClick={() => setView({ name: 'wordlists' })} className={navClass(view.name === 'wordlists')}>
            Wordlists
          </button>
          <button onClick={() => setView({ name: 'settings' })} className={navClass(view.name === 'settings')}>
            Settings
          </button>
          <span className="text-neutral-600">|</span>
          <span className="text-neutral-500">{user.email}</span>
          <button onClick={logout} className="text-neutral-400 hover:text-neutral-200">
            Log out
          </button>
        </div>
      </nav>

      <div className="flex-1 overflow-hidden">
        {view.name === 'dashboard' && <Dashboard onOpen={(scanId) => setView({ name: 'scan', scanId })} />}
        {view.name === 'scan' && (
          <ScanView scanId={view.scanId} onOpenGraph={() => setView({ name: 'graph', scanId: view.scanId })} />
        )}
        {view.name === 'wordlists' && <Wordlists />}
        {view.name === 'settings' && <Settings />}
        {view.name === 'graph' && <GraphView scanId={view.scanId} />}
      </div>
    </div>
  )
}

function navClass(active: boolean): string {
  return active ? 'text-sky-400' : 'text-neutral-400 hover:text-neutral-200'
}
