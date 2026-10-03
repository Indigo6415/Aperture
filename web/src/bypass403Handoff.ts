import { toAbsoluteUrl } from './url'

// bypass403Handoff mirrors jwtHandoff.ts/probeHandoff.ts/secretScanHandoff.ts
// exactly -- see jwtHandoff.ts's doc comment for the full rationale.
export interface Bypass403HandoffRequest {
  url: string
  // Monotonic -- see SecretScanRequest.seq's doc comment.
  seq: number
}

type Listener = (req: Bypass403HandoffRequest) => void
let listeners: Listener[] = []
let seq = 0

// sendToBypass403 is called from any right-click "Send to 403 Bypass" menu
// item; CaseView's subscriber switches to its 403 Bypass tab and prefills
// the URL field.
export function sendToBypass403(value: string) {
  seq += 1
  const req: Bypass403HandoffRequest = { url: toAbsoluteUrl(value), seq }
  for (const l of listeners) l(req)
}

export function onBypass403Request(listener: Listener): () => void {
  listeners.push(listener)
  return () => {
    listeners = listeners.filter((l) => l !== listener)
  }
}
