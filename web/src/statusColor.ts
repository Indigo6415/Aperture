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
