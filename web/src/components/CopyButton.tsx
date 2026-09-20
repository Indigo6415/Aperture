import { showToast } from '../toast'

// CopyButton is the small "Copy" affordance JwtScan and Probe both use next
// to a forged token / finding value -- pulled out once a second caller
// needed it rather than duplicating JwtScan's original inline definition.
export function CopyButton({ text }: { text: string }) {
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          showToast('Copied to clipboard', 'success')
        } catch {
          showToast('Could not copy to clipboard', 'error')
        }
      }}
      className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
    >
      Copy
    </button>
  )
}
