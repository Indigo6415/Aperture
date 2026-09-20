import { toAbsoluteUrl } from './url'

// secretScanHandoff mirrors jwtHandoff.ts/probeHandoff.ts exactly -- see
// jwtHandoff.ts's doc comment for the full rationale. Kept as its own tiny
// module rather than a shared generalization for the same reason those two
// stayed separate.
export interface SecretScanRequest {
  url: string
  // Monotonic, so the request re-applies even when the URL string is
  // identical to the last one sent -- CaseView's tabs stay permanently
  // mounted, so SecretScan can't rely on remounting to pick up a fresh
  // initial value the way a one-shot view could.
  seq: number
}

type Listener = (req: SecretScanRequest) => void
let listeners: Listener[] = []
let seq = 0

// sendToSecretScan is called from any right-click "Send to Secret Scanner"
// menu item; CaseView's subscriber switches to its Secrets tab and prefills
// the URL field.
export function sendToSecretScan(value: string) {
  seq += 1
  const req: SecretScanRequest = { url: toAbsoluteUrl(value), seq }
  for (const l of listeners) l(req)
}

export function onSecretScanRequest(listener: Listener): () => void {
  listeners.push(listener)
  return () => {
    listeners = listeners.filter((l) => l !== listener)
  }
}
