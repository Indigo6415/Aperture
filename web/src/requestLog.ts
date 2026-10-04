import type { RequestRecord } from './types'

// DIRECT_SCAN_NODE_ID is the node a direct scan's requests are filed under. A
// scan started from a tool tab has no flow node, so its log is keyed by the
// scan's own ID with this fixed node name. Must match directScanNodeID in
// internal/api/handlers_requests.go.
export const DIRECT_SCAN_NODE_ID = 'scan'

// isHit reports whether a request is a hit: one that a finding the scan reported
// captured. The server decides this from the scan's own findings, so a 200 or
// 302 that the scan didn't report is not a hit.
export function isHit(r: RequestRecord): boolean {
  return r.hit === true
}

// parseRawRequest recovers the headers and body from a stored raw request so
// it can be replayed in the Tester. The raw form is the request line, then
// "Name: value" lines, a blank line, and the body. Host and Content-Length are
// dropped because the Tester derives both from the URL and the body it sends,
// and keeping a stale one would make the replay disagree with its own body.
export function parseRawRequest(raw: string): { headers: Record<string, string>; body?: string } {
  const lines = raw.split('\n')
  const headers: Record<string, string> = {}
  // Start at 1 to skip the request line; the loop stops at the blank line that
  // separates headers from the body.
  let i = 1
  while (i < lines.length && lines[i] !== '') {
    const colon = lines[i].indexOf(':')
    if (colon > 0) {
      const name = lines[i].slice(0, colon).trim()
      const lower = name.toLowerCase()
      if (lower !== 'host' && lower !== 'content-length') headers[name] = lines[i].slice(colon + 1).trim()
    }
    i++
  }
  // Everything after the blank line is the body, rejoined in case it contains
  // newlines of its own.
  const body = lines.slice(i + 1).join('\n')
  return { headers, body: body || undefined }
}
