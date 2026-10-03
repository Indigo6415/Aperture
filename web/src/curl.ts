// shellQuote wraps s in single quotes so a POSIX shell (bash/zsh) reads it
// back as one literal word. Inside single quotes nothing is special except
// the quote itself, so each embedded quote is closed, escaped, and reopened.
export function shellQuote(s: string): string {
  return "'" + s.replace(/'/g, `'\\''`) + "'"
}

export interface CurlRequest {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
  followRedirects: boolean
}

// buildCurl renders req as a copy-pasteable curl command that replays the
// same request the Tester sends. Each flag mirrors how tester.Send behaves:
//   -k  the Tester never verifies TLS (see tester.newClient), so curl must
//       skip verification too or self-signed targets fail to connect
//   -L  only when "Follow redirects" is on; otherwise curl stops at the
//       first 3xx, same as the Tester
//   -I  HEAD is sent as curl's head mode, not -X HEAD, which would hang
//       waiting for a body that never comes
// Headers with an empty value use curl's "Name;" form, which sends "Name:"
// with nothing after it. A plain "Name:" would make curl drop the header.
// --data-raw sends the body verbatim (no @file expansion). curl would add
// a Content-Type of application/x-www-form-urlencoded to any body, which the
// Tester never does, so an empty "Content-Type:" cancels that default.
export function buildCurl(req: CurlRequest): string {
  const method = req.method.toUpperCase()

  // Each entry is one flag and its value, kept together so every line of
  // the output reads as a complete option.
  const opts: string[] = ['-k']
  if (req.followRedirects) opts.push('-L')
  if (method === 'HEAD') opts.push('-I')
  else opts.push(`-X ${method}`)
  opts.push(shellQuote(req.url))

  for (const [name, value] of Object.entries(req.headers)) {
    opts.push(`-H ${shellQuote(value === '' ? `${name};` : `${name}: ${value}`)}`)
  }

  if (req.body) {
    // Loop over the header names rather than indexing, so a lowercase
    // "content-type" the user typed still counts as set.
    const hasContentType = Object.keys(req.headers).some((k) => k.toLowerCase() === 'content-type')
    if (!hasContentType) opts.push(`-H ${shellQuote('Content-Type:')}`)
    opts.push(`--data-raw ${shellQuote(req.body)}`)
  }

  // One option per line with a trailing backslash, so the command stays
  // readable in the panel and still pastes into a shell as-is.
  return 'curl ' + opts.join(' \\\n  ')
}
