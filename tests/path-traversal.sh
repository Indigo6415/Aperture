#!/usr/bin/env bash
# path-traversal.sh -- a deliberately vulnerable path traversal lab for
# exercising Aperture's path traversal scanner.
#
# Usage: ./path-traversal.sh [port]        (default port 8000)
#
# The server listens on 127.0.0.1 only. Every file it serves comes from a
# throwaway fake filesystem in a temp directory that is deleted on exit, so
# the real host filesystem is never read. Each endpoint below is vulnerable
# in a different way, one per scanner input surface:
#
#   GET  /download?file=<name>   query parameter (falls back to X-File-Name header)
#   GET  /profile                cookie "file"
#   POST /api/render             JSON body field "name" (send Content-Type: application/json)
#   GET  /static/<path>          nginx-style alias: "/static../etc/passwd" escapes the alias
#
# Behaviours the scanner's payloads hit:
#   - ../ sequences climb out of the app directory, clamped at the lab root
#   - \ separators are accepted as / (Windows-style paths)
#   - absolute paths and file:// URLs are accepted
#   - the query value is decoded a second time (double-encoding bypass)
#   - php://filter/convert.base64-encode/resource=... returns base64 content
set -euo pipefail

PORT="${1:-8000}"

exec python3 - "$PORT" <<'PY'
import base64
import http.server
import os
import posixpath
import re
import shutil
import sys
import tempfile
from urllib.parse import parse_qs, unquote, urlparse

PORT = int(sys.argv[1])

# Directories the lab's "app" uses, as paths inside the fake filesystem.
APP_DIR = "/var/www/html"
FILES_DIR = APP_DIR + "/files"
ALIAS_ROOT = "/static"

# Fake filesystem contents. etc/passwd and windows/win.ini carry the same
# signatures the scanner looks for, so a successful read is unmistakable.
CONTENTS = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                  "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    # Second Unix oracle: the scanner also reads /etc/issue, whose "\n \l"
    # agetty escape is its signature.
    "etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n",
    "windows/win.ini": "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n",
    "var/www/html/index.html": "<html><body><h1>Path traversal lab</h1>"
                               "<a href='/download?file=report.pdf'>report</a> "
                               "<a href='/static/app.js'>app.js</a></body></html>",
    "var/www/html/files/report.pdf": "%PDF-1.4 lab report",
    "var/www/html/files/notes.txt": "lab notes",
    "static/app.js": "console.log('lab');",
}

# Matches the PHP stream wrapper that returns a file base64-encoded.
PHP_WRAPPER = re.compile(r"^php://filter/(?:read=)?convert\.base64-encode/resource=(.*)$")

FS_ROOT = tempfile.mkdtemp(prefix="aperture-traversal-")


def build_fs():
    """Writes CONTENTS under FS_ROOT, creating directories as needed."""
    for rel, text in CONTENTS.items():
        full = os.path.join(FS_ROOT, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)


def resolve(user, base):
    """Joins user onto base the way a naive app does, with no containment check.

    The result is normalised inside a virtual root, so climbing above "/"
    stops at the lab root and the real host filesystem is never reached.
    """
    # Windows-style separators are accepted as path separators.
    user = user.replace("\\", "/")
    virtual = posixpath.normpath(posixpath.join(base, user))
    return os.path.join(FS_ROOT, virtual.lstrip("/"))


def fetch(value, base):
    """Returns (body bytes, is_base64) for a user-supplied file name, or None if missing."""
    # The PHP wrapper returns the file base64-encoded.
    wrapped = PHP_WRAPPER.match(value)
    if wrapped:
        data = read(resolve(wrapped.group(1), base))
        return None if data is None else (base64.b64encode(data), True)
    # file:// URLs are reduced to the absolute path they point at.
    value = re.sub(r"^file://(localhost)?", "", value)
    data = read(resolve(value, base))
    return None if data is None else (data, False)


def read(full):
    """Returns the bytes at full, or None when it is missing or not a regular file."""
    if not os.path.isfile(full):
        return None
    with open(full, "rb") as f:
        return f.read()


class Handler(http.server.BaseHTTPRequestHandler):
    """Routes requests to the vulnerable endpoints listed at the top of this file."""

    def do_GET(self):
        """Handles GET for the query, cookie, and alias endpoints."""
        parsed = urlparse(self.path)
        # The web server decodes the path once before routing, as real ones do.
        path = unquote(parsed.path)
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path in ("/", "/index.html"):
            return self.send_file(fetch("index.html", APP_DIR))

        if path == "/download":
            # The query value is decoded a second time, a common double-decoding bug.
            value = query.get("file", [None])[0]
            if value is None:
                value = self.headers.get("X-File-Name")
            if value is None:
                return self.send_text(400, "file parameter required")
            return self.send_file(fetch(unquote(value), FILES_DIR))

        if path == "/profile":
            cookie = self.headers.get("Cookie", "")
            match = re.search(r"(?:^|;\s*)file=([^;]*)", cookie)
            if not match:
                return self.send_text(200, "profile page")
            return self.send_file(fetch(match.group(1), FILES_DIR))

        if path.startswith(ALIAS_ROOT):
            # nginx-style alias: the remainder is joined onto the alias root without
            # a containment check, so "../" steps escape it.
            rest = path[len(ALIAS_ROOT):].lstrip("/")
            if rest == "":
                return self.send_text(404, "not found")
            return self.send_file(fetch(rest, ALIAS_ROOT))

        return self.send_text(404, "not found")

    def do_POST(self):
        """Handles POST for the JSON render endpoint."""
        if urlparse(self.path).path != "/api/render":
            return self.send_text(404, "not found")
        length = int(self.headers.get("Content-Length", 0))
        try:
            doc = __import__("json").loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.send_text(400, "invalid JSON")
        name = doc.get("name") if isinstance(doc, dict) else None
        if not isinstance(name, str):
            return self.send_text(400, "name is required")
        return self.send_file(fetch(name, FILES_DIR))

    def send_file(self, result):
        """Sends a fetch() result as a 200 response, or a 404 when the file is missing."""
        if result is None:
            return self.send_text(404, "not found")
        body, _ = result
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status, text):
        """Sends a plain-text response with the given status."""
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        """Prints one line per request to stderr."""
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def main():
    """Builds the fake filesystem, serves until interrupted, then removes it."""
    build_fs()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Path traversal lab on http://127.0.0.1:{PORT}")
    print("  GET  /download?file=report.pdf")
    print("  GET  /profile             (Cookie: file=report.pdf)")
    print("  POST /api/render          (JSON: {\"name\": \"report.pdf\"})")
    print("  GET  /static/app.js")
    print("Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        shutil.rmtree(FS_ROOT, ignore_errors=True)


if __name__ == "__main__":
    main()
PY
