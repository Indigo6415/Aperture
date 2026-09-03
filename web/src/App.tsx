import { useState } from 'react'
import { Dashboard } from './components/Dashboard'
import { FlowEditor } from './components/FlowEditor'
import { FlowList } from './components/FlowList'
import { ScanView } from './components/ScanView'
import { Wordlists } from './components/Wordlists'

// View is a small discriminated union instead of a plain string so a view
// that needs an id (which scan, which flow) carries it along rather than
// living in a second piece of state that could get out of sync.
type View = { name: 'dashboard' } | { name: 'scan'; scanId: string } | { name: 'wordlists' } | { name: 'flows'; flowId: string | null }

export default function App() {
  const [view, setView] = useState<View>({ name: 'dashboard' })

  return (
    <div className="flex h-screen flex-col bg-neutral-950">
      <nav className="flex shrink-0 items-center gap-4 border-b border-neutral-800 px-4 py-2 text-sm">
        <button onClick={() => setView({ name: 'dashboard' })} className="font-semibold text-neutral-100 hover:text-sky-400">
          Aperture
        </button>
        <div className="ml-auto flex items-center gap-4">
          <button onClick={() => setView({ name: 'wordlists' })} className={navClass(view.name === 'wordlists')}>
            Wordlists
          </button>
          <button onClick={() => setView({ name: 'flows', flowId: null })} className={navClass(view.name === 'flows')}>
            Flows
          </button>
        </div>
      </nav>

      <div className="flex-1 overflow-hidden">
        {view.name === 'dashboard' && <Dashboard onOpen={(scanId) => setView({ name: 'scan', scanId })} />}
        {view.name === 'scan' && (
          <ScanView
            scanId={view.scanId}
            onBack={() => setView({ name: 'dashboard' })}
            onOpenFlow={(flowId) => setView({ name: 'flows', flowId })}
          />
        )}
        {view.name === 'wordlists' && <Wordlists />}
        {view.name === 'flows' &&
          (view.flowId ? (
            <FlowEditor flowId={view.flowId} onBack={() => setView({ name: 'flows', flowId: null })} />
          ) : (
            <FlowList onOpen={(id) => setView({ name: 'flows', flowId: id })} />
          ))}
      </div>
    </div>
  )
}

function navClass(active: boolean): string {
  return active ? 'text-sky-400' : 'text-neutral-400 hover:text-neutral-200'
}
