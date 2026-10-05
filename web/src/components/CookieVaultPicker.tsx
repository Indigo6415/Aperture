import type { CookieVaultEntry } from '../types'

// CookieVaultPicker lets a tool apply one of the case's saved per-domain
// session cookies (see CookieVault.tsx) as an identity, the counterpart to
// CredentialPicker for the Credential Vault. Picking an entry fills the
// caller's Cookie field with that domain's cookie; picking the active one
// again clears it. Only domains that actually carry a cookie are offered,
// and the component renders nothing when there are none, so an empty vault
// adds no clutter.
export function CookieVaultPicker({
  entries,
  value,
  onPick,
  className,
}: {
  entries: CookieVaultEntry[]
  value: string
  onPick: (cookie: string) => void
  className?: string
}) {
  // Only entries with a stored cookie can stand in for an identity.
  const withCookie = entries.filter((e) => e.cookie)
  if (withCookie.length === 0) return null
  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className ?? ''}`}>
      <span className="text-xs text-neutral-500">Cookie vault</span>
      {withCookie.map((e) => {
        // An entry is active when its cookie is exactly what the field holds,
        // so editing the field by hand naturally drops the highlight.
        const active = e.cookie === value
        return (
          <button
            key={e.domain}
            type="button"
            onClick={() => onPick(active ? '' : e.cookie ?? '')}
            title={`Use the saved session cookie for ${e.domain}`}
            className={`rounded border px-2 py-0.5 text-xs ${
              active ? 'border-sky-500 bg-sky-950/40 text-sky-300' : 'border-neutral-700 bg-neutral-900 text-neutral-400 hover:border-sky-600'
            }`}
          >
            {e.domain}
          </button>
        )
      })}
    </div>
  )
}
