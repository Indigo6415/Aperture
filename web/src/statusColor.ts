// statusHexColor maps an HTTP status code to the color used for it
// everywhere a finding/subdomain/scan row shows one: FacetFilterBar chips
// (inline hex), and any plain-text status badge outside a table cell.
export function statusHexColor(code: number): string {
  if (code >= 200 && code < 300) return '#34d399'
  if (code >= 300 && code < 400) return '#38bdf8'
  if (code >= 400 && code < 500) return '#fbbf24'
  if (code >= 500) return '#f87171'
  return '#a3a3a3'
}

// statusTextClass is the Tailwind-class counterpart to statusHexColor, for
// table cells and text runs (which use a class) rather than inline-styled
// chips/badges. Every status-code display in the app goes through this or
// statusHexColor, so the directory scanners and the module scanners match.
export function statusTextClass(code: number): string {
  if (code >= 200 && code < 300) return 'text-emerald-400'
  if (code >= 300 && code < 400) return 'text-sky-400'
  if (code >= 400 && code < 500) return 'text-amber-400'
  if (code >= 500) return 'text-red-400'
  return 'text-neutral-400'
}
