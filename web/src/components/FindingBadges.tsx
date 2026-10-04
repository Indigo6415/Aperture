import { statusTextClass } from '../statusColor'

// StatusBadge shows a finding's HTTP status code in the same colors the
// directory scanners use, so it reads at a glance without expanding the row.
// A finding with no status (statusCode unset or 0) gets a dim dash in the
// same slot, so the codes that are present still line up in one column.
export function StatusBadge({ code }: { code?: number }) {
  if (!code) {
    return <span className="w-8 shrink-0 text-right font-mono text-neutral-700">—</span>
  }
  return <span className={`w-8 shrink-0 text-right font-mono ${statusTextClass(code)}`}>{code}</span>
}

// CallbackTag marks a finding the target itself proved by calling back to
// Aperture's collaborator listener -- the strongest proof a blind check can
// give, since nothing had to show up in the HTTP response.
export function CallbackTag() {
  return (
    <span className="ml-2 inline-block rounded border border-fuchsia-700 bg-fuchsia-950 px-1.5 py-px align-middle text-[10px] font-semibold uppercase tracking-wide text-fuchsia-300">
      CALLBACK
    </span>
  )
}
