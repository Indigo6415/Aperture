import type { View } from '../App'
import type { AuthUser } from '../types'
import { useNavStyle, type NavStyle } from '../navStyle'
import { NotificationCenter } from './NotificationCenter'

interface NavbarProps {
  view: View
  user: AuthUser
  onNavigate: (view: View) => void
  onLogout: () => void
}

// Navbar picks which of the four saved layouts to render (see navStyle.ts
// for the preference itself and Settings.tsx's NavStylePicker for where it's
// chosen) and passes every variant the same props, so swapping styles never
// changes what the navbar can do -- only how it looks. Each variant below is
// a fully separate layout rather than one skin reused with different
// classes, so they read as four genuinely different designs rather than
// recolors of each other.
export function Navbar(props: NavbarProps) {
  const style = useNavStyle()
  switch (style) {
    case 'rail':
      return <RailNav {...props} />
    case 'segmented':
      return <SegmentedNav {...props} />
    case 'terminal':
      return <TerminalNav {...props} />
    case 'minimal':
    default:
      return <MinimalNav {...props} />
  }
}

// showBack centralizes the one piece of logic every variant shares: the
// back-to-cases link only makes sense once you've left the case list.
function showBack(view: View): boolean {
  return view.name === 'wordlists' || view.name === 'settings'
}

// ---------------------------------------------------------------------
// Minimal -- a flat monochrome bar with a hairline underline marking the
// active page instead of a color fill. Closest in spirit to Aperture's
// original bar, but with the bright blue hover/active states replaced by
// neutral tones so it reads as restrained rather than playful.
function MinimalNav({ view, user, onNavigate, onLogout }: NavbarProps) {
  return (
    <nav className="flex shrink-0 items-center gap-5 border-b border-neutral-800 px-4 py-2.5 text-sm">
      <button onClick={() => onNavigate({ name: 'caseList' })} className="font-semibold tracking-tight text-neutral-100 hover:text-neutral-300">
        Aperture
      </button>
      {showBack(view) && (
        <button onClick={() => onNavigate({ name: 'caseList' })} className="text-neutral-500 hover:text-neutral-300">
          ← Back to cases
        </button>
      )}
      <div className="ml-auto flex items-center gap-5">
        <MinimalLink label="Wordlists" active={view.name === 'wordlists'} onClick={() => onNavigate({ name: 'wordlists' })} />
        <MinimalLink label="Settings" active={view.name === 'settings'} onClick={() => onNavigate({ name: 'settings' })} />
        <NotificationCenter />
        <span className="h-4 w-px bg-neutral-800" />
        <span className="text-neutral-500">{user.email}</span>
        <button onClick={onLogout} className="text-neutral-500 hover:text-neutral-300">
          Log out
        </button>
      </div>
    </nav>
  )
}

function MinimalLink({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`border-b-2 pb-0.5 pt-0.5 transition-colors ${
        active ? 'border-neutral-100 text-neutral-100' : 'border-transparent text-neutral-500 hover:text-neutral-300'
      }`}
    >
      {label}
    </button>
  )
}

// ---------------------------------------------------------------------
// Rail -- a vertical sidebar instead of a top bar. App.tsx checks
// isVertical(style) to flip the outer flex direction when this one's active,
// so the rest of the layout drops in beside it rather than under it.
function RailNav({ view, user, onNavigate, onLogout }: NavbarProps) {
  return (
    <nav className="flex w-48 shrink-0 flex-col border-r border-neutral-800 px-3 py-4 text-sm">
      <button
        onClick={() => onNavigate({ name: 'caseList' })}
        className="px-1 pb-4 text-left font-semibold tracking-tight text-neutral-100 hover:text-neutral-300"
      >
        Aperture
      </button>

      <div className="flex flex-col gap-0.5">
        <RailLink label="Cases" active={view.name === 'caseList' || view.name === 'case'} onClick={() => onNavigate({ name: 'caseList' })} />
        <RailLink label="Wordlists" active={view.name === 'wordlists'} onClick={() => onNavigate({ name: 'wordlists' })} />
        <RailLink label="Settings" active={view.name === 'settings'} onClick={() => onNavigate({ name: 'settings' })} />
      </div>

      <div className="mt-auto flex flex-col gap-3 border-t border-neutral-800 pt-3">
        <div className="flex items-center justify-between px-1">
          <span className="truncate text-xs text-neutral-500" title={user.email}>
            {user.email}
          </span>
          <NotificationCenter />
        </div>
        <button onClick={onLogout} className="rounded px-2 py-1.5 text-left text-xs text-neutral-500 hover:bg-neutral-900 hover:text-neutral-300">
          Log out
        </button>
      </div>
    </nav>
  )
}

function RailLink({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded px-2 py-1.5 text-left transition-colors ${
        active ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:bg-neutral-900 hover:text-neutral-200'
      }`}
    >
      {label}
    </button>
  )
}

// ---------------------------------------------------------------------
// Segmented -- the page switcher is a single pill-shaped segmented control
// (one bordered group, not three loose buttons), centered in its own slim
// bar with brand and account split to the corners. Reads as a toolbar
// rather than a row of links.
function SegmentedNav({ view, user, onNavigate, onLogout }: NavbarProps) {
  return (
    <nav className="flex shrink-0 items-center border-b border-neutral-800 px-4 py-2 text-sm">
      <div className="flex flex-1 items-center gap-3">
        <button onClick={() => onNavigate({ name: 'caseList' })} className="font-semibold tracking-tight text-neutral-100 hover:text-neutral-300">
          Aperture
        </button>
        {showBack(view) && (
          <button onClick={() => onNavigate({ name: 'caseList' })} className="text-xs text-neutral-500 hover:text-neutral-300">
            ← Back
          </button>
        )}
      </div>

      <div className="flex items-center gap-0.5 rounded-full border border-neutral-800 bg-neutral-900 p-0.5">
        <SegmentButton label="Cases" active={view.name === 'caseList' || view.name === 'case'} onClick={() => onNavigate({ name: 'caseList' })} />
        <SegmentButton label="Wordlists" active={view.name === 'wordlists'} onClick={() => onNavigate({ name: 'wordlists' })} />
        <SegmentButton label="Settings" active={view.name === 'settings'} onClick={() => onNavigate({ name: 'settings' })} />
      </div>

      <div className="flex flex-1 items-center justify-end gap-3">
        <NotificationCenter />
        <span className="hidden text-xs text-neutral-500 sm:inline">{user.email}</span>
        <button onClick={onLogout} className="rounded-full border border-neutral-800 px-3 py-1 text-xs text-neutral-400 hover:border-neutral-600 hover:text-neutral-200">
          Log out
        </button>
      </div>
    </nav>
  )
}

function SegmentButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
        active ? 'bg-neutral-100 text-neutral-900' : 'text-neutral-400 hover:text-neutral-200'
      }`}
    >
      {label}
    </button>
  )
}

// ---------------------------------------------------------------------
// Terminal -- monospace, bracketed links and a prompt-style brand, closest
// to the gray-on-black tooling aesthetic the rest of Aperture's domain
// (scanners, request logs) already lives in.
function TerminalNav({ view, user, onNavigate, onLogout }: NavbarProps) {
  return (
    <nav className="flex shrink-0 items-center gap-4 border-b border-neutral-800 bg-neutral-950 px-4 py-2 font-mono text-xs">
      <button onClick={() => onNavigate({ name: 'caseList' })} className="text-neutral-200 hover:text-neutral-400">
        aperture<span className="text-neutral-600">:~$</span>
      </button>
      {showBack(view) && (
        <button onClick={() => onNavigate({ name: 'caseList' })} className="text-neutral-600 hover:text-neutral-400">
          cd ..
        </button>
      )}
      <div className="ml-auto flex items-center gap-4">
        <TerminalLink label="wordlists" active={view.name === 'wordlists'} onClick={() => onNavigate({ name: 'wordlists' })} />
        <TerminalLink label="settings" active={view.name === 'settings'} onClick={() => onNavigate({ name: 'settings' })} />
        <NotificationCenter />
        <span className="text-neutral-700">#</span>
        <span className="text-neutral-600">{user.email}</span>
        <button onClick={onLogout} className="text-neutral-600 hover:text-neutral-400">
          logout
        </button>
      </div>
    </nav>
  )
}

function TerminalLink({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} className={active ? 'text-neutral-100' : 'text-neutral-600 hover:text-neutral-400'}>
      [{label}]
    </button>
  )
}

export type { NavStyle }
