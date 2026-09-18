// jwtHandoff lets any "Send to JWT Scanner" context-menu item (added from
// deep inside CaseView/ResultsTable/HierarchyView/etc.) reach the
// currently-open case's JWT Scanner tab without threading a callback
// through every intermediate component -- the same module-level pub/sub
// shape as toast.tsx's showToast. The JWT Scanner lives inside CaseView, and
// only one case is ever open at a time, so there's always at most one
// listener: whichever CaseView is currently mounted.
export interface JwtScannerRequest {
  url: string
  // Monotonic, so the request re-applies even when the URL string is
  // identical to the last one sent -- CaseView's tabs stay permanently
  // mounted (see its own doc comment), so JwtScan can't rely on remounting
  // to pick up a fresh initial value the way a one-shot view could.
  seq: number
}

type Listener = (req: JwtScannerRequest) => void
let listeners: Listener[] = []
let seq = 0

// toProbeUrl turns a bare hostname/IP (as stored in Target.value, a
// HierarchyView host, a GraphCanvas target node, ...) into something the
// JWT scanner's "protected route to probe" field can send a request to.
// A value that already looks like a URL is left untouched.
function toProbeUrl(value: string): string {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}/`
}

// sendToJwtScanner is called from any right-click "Send to JWT Scanner"
// menu item; CaseView's subscriber switches to its JWT Scanner tab and
// prefills the URL field.
export function sendToJwtScanner(value: string) {
  seq += 1
  const req: JwtScannerRequest = { url: toProbeUrl(value), seq }
  for (const l of listeners) l(req)
}

export function onJwtScannerRequest(listener: Listener): () => void {
  listeners.push(listener)
  return () => {
    listeners = listeners.filter((l) => l !== listener)
  }
}
