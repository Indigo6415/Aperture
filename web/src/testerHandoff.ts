import { toAbsoluteUrl } from './url'

// testerHandoff mirrors jwtHandoff.ts/probeHandoff.ts/bypass403Handoff.ts
// exactly -- see jwtHandoff.ts's doc comment for the full rationale. Kept
// as its own tiny module rather than a shared generalization for the same
// reason those stayed separate. Unlike the others, this one also carries
// method/headers/body -- every scanner's "Send to Tester" action hands
// over the *exact* request that produced a finding (see each scanner's own
// CapturedRequest-shaped field), not just a bare URL, so the Tester loads
// ready to replay precisely what triggered it.
export interface TesterHandoffRequest {
  method: string
  url: string
  // headers seeds the Tester's header rows -- e.g. a CORS check's
  // attacker-chosen Origin, a JWT test's forged Authorization: Bearer
  // token, or a finding's captured request headers. Undefined/empty leaves
  // the Tester's own default (one blank row).
  headers?: Record<string, string>
  body?: string
  // Monotonic, so the request re-applies even when the URL string is
  // identical to the last one sent -- CaseView's tabs stay permanently
  // mounted, so the Tester can't rely on remounting to pick up a fresh
  // initial value the way a one-shot view could.
  seq: number
}

type Listener = (req: TesterHandoffRequest) => void
let listeners: Listener[] = []
let seq = 0

// sendToTester is called from any right-click "Send to Tester" menu item
// (on a scanner's finding, a raw Finding row, or a plain target/URL);
// CaseView's subscriber switches to its Tester tab and prefills the
// method/URL/header/body fields. method defaults to GET -- a finding's own
// captured method (when known) should be passed instead.
export function sendToTester(value: string, method = 'GET', headers?: Record<string, string>, body?: string) {
  seq += 1
  const req: TesterHandoffRequest = { method, url: toAbsoluteUrl(value), headers, body, seq }
  for (const l of listeners) l(req)
}

export function onTesterRequest(listener: Listener): () => void {
  listeners.push(listener)
  return () => {
    listeners = listeners.filter((l) => l !== listener)
  }
}
