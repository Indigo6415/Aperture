// hostnameOf/extensionOf centralize the "pull a piece out of a Finding's
// URL" parsing that ScanView, GraphView, and ResultsTable each need --
// invalid URLs (which shouldn't occur, but a malformed finding shouldn't
// crash the view) resolve to undefined rather than throwing.

// toAbsoluteUrl prepends https:// to a bare hostname/IP (e.g. a Target's
// stored value, as clicking one of TargetButtons hands back) so it's usable
// as a full request URL -- a value that already looks like it has a scheme
// is left untouched. Every scan tool's URL field (JWT Scanner, Secrets,
// Repeater, and Probe's target field, which also accepts a bare host but is
// normalized the same way here per explicit product decision) runs a
// target-button pick through this before setting its own state, so
// "example.com" never reaches the backend as a schemeless string (Go's
// http.NewRequest rejects that with "unsupported protocol scheme").
export function toAbsoluteUrl(value: string): string {
  const trimmed = value.trim()
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}/`
}

export function hostnameOf(url: string): string | undefined {
  try {
    return new URL(url).hostname
  } catch {
    return undefined
  }
}

// extensionOf returns a bare lowercase extension (no leading dot) for a
// URL's path, e.g. "sql" for "/backup/db.sql". Paths with no dot, or whose
// last segment starts with a dot (dotfiles like ".env" have no further
// extension to split off -- the whole name *is* the marker), return
// undefined.
export function extensionOf(url: string): string | undefined {
  let pathname: string
  try {
    pathname = new URL(url).pathname
  } catch {
    return undefined
  }
  const last = pathname.slice(pathname.lastIndexOf('/') + 1)
  const dot = last.lastIndexOf('.')
  if (dot <= 0) return undefined
  const ext = last.slice(dot + 1).toLowerCase()
  if (!ext || !/^[a-z0-9]+$/.test(ext)) return undefined
  return ext
}
