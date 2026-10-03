#!/usr/bin/env bash
#
# ssrf_target.sh
# Minimal, deliberately vulnerable SSRF test target for Aperture development.
#
# Spins up a single-file Python HTTP server with one page containing an
# input box. Whatever URL you submit is fetched SERVER-SIDE with no
# validation (no scheme check, no host allowlist, no block on
# internal/metadata ranges) and the response body + headers are reflected
# back to you. Classic, unauthenticated SSRF — do not expose this port
# beyond your own test network.
#
# Usage:
#   chmod +x ssrf_target.sh
#   ./ssrf_target.sh [port]        # default port 8000
#
# Then browse to http://localhost:<port>/

set -euo pipefail

PORT="${1:-8000}"
WORKDIR="$(mktemp -d)"
APP="$WORKDIR/ssrf_app.py"

cat > "$APP" <<'PYEOF'
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

PAGE_TOP = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Aperture SSRF Test Target</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 700px; margin: 40px auto; }
    input[type=text] { width: 70%; padding: 6px; }
    button { padding: 6px 14px; }
    pre { background: #111; color: #0f0; padding: 12px; overflow-x: auto;
          white-space: pre-wrap; word-break: break-all; }
    .warn { color: #a00; font-size: 0.9em; }
  </style>
</head>
<body>
  <h2>URL Preview Tool</h2>
  <p>Enter a URL and the server will fetch it and show you the content.</p>
  <p class="warn">Intentionally vulnerable to SSRF — no URL/host validation is performed server-side.</p>
  <form method="GET" action="/fetch">
    <input type="text" name="url" placeholder="http://example.com" value="__PREFILL__">
    <button type="submit">Fetch</button>
  </form>
"""

PAGE_BOTTOM = "</body></html>"


def render_top(prefill=""):
    return PAGE_TOP.replace("__PREFILL__", prefill)


class Handler(BaseHTTPRequestHandler):
    server_version = "ApertureSSRFTarget/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[ssrf-target] %s - %s\n" % (self.address_string(), fmt % args))

    def _send_html(self, body, status=200):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._send_html(render_top() + PAGE_BOTTOM)
            return

        if parsed.path == "/fetch":
            qs = parse_qs(parsed.query)
            target = qs.get("url", [""])[0]

            if not target:
                self._send_html(render_top() + "<p>No url provided.</p>" + PAGE_BOTTOM)
                return

            result_html = render_top(self._escape(target))
            result_html += f"<h3>Request: {target}</h3>"

            # --- VULNERABLE: server-side fetch of attacker-supplied URL,  ---
            # --- no scheme allowlist, no host allowlist, no blocking of   ---
            # --- loopback / link-local / metadata / internal ranges.     ---
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "ApertureSSRFTarget/0.1"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    headers_text = "\n".join(f"{k}: {v}" for k, v in resp.getheaders())
                    raw = resp.read(20000)
                    try:
                        body_text = raw.decode("utf-8", errors="replace")
                    except Exception:
                        body_text = repr(raw)

                    result_html += "<h4>Response headers</h4>"
                    result_html += f"<pre>{self._escape(headers_text)}</pre>"
                    result_html += "<h4>Response body (first 20000 bytes)</h4>"
                    result_html += f"<pre>{self._escape(body_text)}</pre>"

            except urllib.error.HTTPError as e:
                result_html += f"<p>HTTP error: {e.code} {e.reason}</p>"
            except urllib.error.URLError as e:
                result_html += f"<p>URL error: {e.reason}</p>"
            except Exception as e:
                result_html += f"<p>Error: {e}</p>"

            result_html += PAGE_BOTTOM
            self._send_html(result_html)
            return

        self._send_html("<h1>404</h1>", status=404)

    @staticmethod
    def _escape(s):
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;"))


if __name__ == "__main__":
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[ssrf-target] Serving on http://0.0.0.0:{PORT}/  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[ssrf-target] Shutting down.")
        httpd.shutdown()
PYEOF

echo "[ssrf_target.sh] Starting SSRF test target on port ${PORT} (workdir: ${WORKDIR})"
exec python3 "$APP" "$PORT"
