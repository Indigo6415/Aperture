import { toAbsoluteUrl } from './url'

// repeaterHandoff mirrors jwtHandoff.ts/probeHandoff.ts exactly -- see
// jwtHandoff.ts's doc comment for the full rationale. Kept as its own tiny
// module rather than a shared generalization for the same reason those two
// stayed separate.
export interface RepeaterHandoffRequest {
  method: string
  url: string
  // headers seeds the Repeater's header rows -- e.g. a JWT test's forged
  // Authorization: Bearer token, or a finding's captured request headers.
  // Undefined/empty leaves the Repeater's own default (one blank row).
  headers?: Record<string, string>
  // Monotonic, so the request re-applies even when the URL string is
  // identical to the last one sent -- CaseView's tabs stay permanently
  // mounted, so Repeater can't rely on remounting to pick up a fresh
  // initial value the way a one-shot view could.
  seq: number
}

type Listener = (req: RepeaterHandoffRequest) => void
let listeners: Listener[] = []
let seq = 0

// sendToRepeater is called from any right-click "Send to Repeater" menu
// item; CaseView's subscriber switches to its Repeater tab and prefills the
// method/URL/header fields. method defaults to GET -- a Finding's own
// method (when known, e.g. from ResultsTable) can be passed instead.
export function sendToRepeater(value: string, method = 'GET', headers?: Record<string, string>) {
  seq += 1
  const req: RepeaterHandoffRequest = { method, url: toAbsoluteUrl(value), headers, seq }
  for (const l of listeners) l(req)
}

export function onRepeaterRequest(listener: Listener): () => void {
  listeners.push(listener)
  return () => {
    listeners = listeners.filter((l) => l !== listener)
  }
}
