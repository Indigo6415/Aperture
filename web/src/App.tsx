import { useState } from 'react'
import { Dashboard } from './components/Dashboard'
import { ScanView } from './components/ScanView'
import { Wordlists } from './components/Wordlists'
import { GraphView } from './components/GraphView'

// View is a small discriminated union instead of a plain string so a view
// that needs an id (which scan) carries it along rather than living in a
// second piece of state that could get out of sync. Graph is scoped to one
// scan (matching the rest of the app) so it carries that scan's id too.
type View = { name: 'dashboard' } | { name: 'scan'; scanId: string } | { name: 'wordlists' } | { name: 'graph'; scanId: string }

export default function App() {
  const [view, setView] = useState<View>({ name: 'dashboard' })

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
        {view.name === 'wordlists' && (
          <button onClick={() => setView({ name: 'dashboard' })} className="text-neutral-400 hover:text-neutral-200">
            ← Back to dashboard
          </button>
        )}
        <div className="ml-auto flex items-center gap-4">
          <button onClick={() => setView({ name: 'wordlists' })} className={navClass(view.name === 'wordlists')}>
            Wordlists
          </button>
        </div>
      </nav>

      <div className="flex-1 overflow-hidden">
        {view.name === 'dashboard' && <Dashboard onOpen={(scanId) => setView({ name: 'scan', scanId })} />}
        {view.name === 'scan' && (
          <ScanView scanId={view.scanId} onOpenGraph={() => setView({ name: 'graph', scanId: view.scanId })} />
        )}
        {view.name === 'wordlists' && <Wordlists />}
        {view.name === 'graph' && <GraphView scanId={view.scanId} />}
      </div>
    </div>
  )
}

function navClass(active: boolean): string {
  return active ? 'text-sky-400' : 'text-neutral-400 hover:text-neutral-200'
}
