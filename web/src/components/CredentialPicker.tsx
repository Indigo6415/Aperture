import type { Credential } from '../types'

// CredentialPicker lets a tool apply one saved case credential (see
// CredentialVault.tsx) to the request it's about to send -- clicking the
// already-selected one clears the selection. Unlike TargetButtons (which
// fills a field immediately on click), the actual header/cookie merge
// happens server-side from the selected id (see handlers_credentials.go's
// mergedCredentialHeaders), so all this does is track which credential is
// currently applied.
export function CredentialPicker({
  credentials,
  selected,
  onSelect,
  className,
}: {
  credentials: Credential[]
  selected?: string
  onSelect: (id: string | undefined) => void
  className?: string
}) {
  if (credentials.length === 0) return null
  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className ?? ''}`}>
      <span className="text-xs text-neutral-500">Credential</span>
      {credentials.map((c) => (
        <button
          key={c.id}
          type="button"
          onClick={() => onSelect(selected === c.id ? undefined : c.id)}
          title={`Apply saved credential ${c.name}`}
          className={`rounded border px-2 py-0.5 text-xs ${
            selected === c.id ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
          }`}
        >
          {c.name}
        </button>
      ))}
    </div>
  )
}
