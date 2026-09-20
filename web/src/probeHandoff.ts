import { toAbsoluteUrl } from './url'

// probeHandoff mirrors jwtHandoff.ts exactly -- see that file's doc comment
// for the full rationale (module-level pub/sub, same shape as
// toast.tsx's showToast). Kept as a separate module rather than a shared
// generalization since there are only two of these and each is tiny; a
// shared abstraction would cost more to read than it saves to write.
export interface ProbeRequest {
  target: string
  // Monotonic, so the request re-applies even when the target string is
  // identical to the last one sent -- CaseView's tabs stay permanently
  // mounted, so Probe can't rely on remounting to pick up a fresh initial
  // value the way a one-shot view could.
  seq: number
}

type Listener = (req: ProbeRequest) => void
let listeners: Listener[] = []
let seq = 0

// sendToProbe is called from any right-click "Send to Probe" menu item;
// CaseView's subscriber switches to its Probe tab and prefills the target
// field. Probe's own target field accepts a bare hostname/IP just fine
// (its backend infers scheme/port), but every scan tool's target-button/
// handoff path defaults to https:// the same way for consistency -- see
// toAbsoluteUrl.
export function sendToProbe(value: string) {
  seq += 1
  const req: ProbeRequest = { target: toAbsoluteUrl(value), seq }
  for (const l of listeners) l(req)
}

export function onProbeRequest(listener: Listener): () => void {
  listeners.push(listener)
  return () => {
    listeners = listeners.filter((l) => l !== listener)
  }
}
