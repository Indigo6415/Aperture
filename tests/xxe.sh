#!/usr/bin/env bash
# xxe.sh -- a deliberately vulnerable XML External Entity lab for exercising
# Aperture's XXE scanner.
#
# Usage: ./xxe.sh [port]        (default port 8001)
#
# The server listens on 127.0.0.1 only. Local file entities and XInclude read
# from a throwaway fake filesystem in a temp directory that is deleted on exit,
# so the real host filesystem is never read. The parser is emulated in Python
# (the stdlib has no entity-resolving parser), and behaves like a libxml2
# parser with entity expansion enabled:
#
#   POST|PUT /api/xml        vulnerable: resolves DOCTYPE entities and XInclude
#   POST|PUT /api/xml/safe   hardened: rejects any document with a DOCTYPE
#   GET      /               HTML page whose form and script point at /api/xml
#   GET      /api/status     JSON, not XML (a negative control for auto-discover)
#
# What the scanner's checks hit on /api/xml:
#   - internal entities expand, so the canary comes back in the response
#   - SYSTEM file:///etc/passwd and file:///C:/Windows/win.ini are read from the
#     fake filesystem, and a missing file leaks its path in a parser error
#   - <xi:include parse="text" href="file:///..."/> is resolved
#   - SYSTEM http(s):// entities are fetched for real (the scanner's blind
#     callback, and an SSRF to any URL the lab can reach). Their response body
#     is inserted into the document, the way a parser does.
#   - a parameter entity pointing at a remote DTD is fetched while parsing
#   - a malformed document gets a parser error back, so XML endpoints classify
set -euo pipefail

PORT="${1:-8001}"

exec python3 - "$PORT" <<'PY'
import html
import http.server
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

PORT = int(sys.argv[1])

# Fake filesystem contents. etc/passwd and win.ini carry the signatures the
# scanner looks for, so a successful read is unmistakable.
CONTENTS = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                  "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "Windows/win.ini": "; for 16-bit app support\n[fonts]\n[extensions]\n[files]\n",
    "app/config.txt": "db_password=lab-secret\n",
}

FS_ROOT = tempfile.mkdtemp(prefix="aperture-xxe-")

# Matches <!DOCTYPE name [internal subset]>. The subset is captured separately
# so entity declarations are only read from inside it.
DOCTYPE_RE = re.compile(r"<!DOCTYPE\b[^\[>]*(\[(.*?)\])?\s*>", re.S)
# Matches one entity declaration, general (<!ENTITY n ...>) or parameter
# (<!ENTITY % n ...>), with either a SYSTEM identifier or an inline value.
ENTITY_RE = re.compile(r'<!ENTITY\s+(%\s+)?([\w.-]+)\s+(?:SYSTEM\s+"([^"]*)"|"([^"]*)")\s*>')
ENTITY_REF_RE = re.compile(r"&([A-Za-z_][\w.-]*);")
PARAM_REF_RE = re.compile(r"%([\w.-]+);")
XINCLUDE_RE = re.compile(r'<xi:include\b[^>]*?href="([^"]+)"[^>]*/>')
PREDEFINED = {"amp", "lt", "gt", "quot", "apos"}


class XxeError(Exception):
    """A failure that the lab reports to the client as a parser error."""


def build_fs():
    """Writes CONTENTS under FS_ROOT, creating directories as needed."""
    for rel, text in CONTENTS.items():
        full = os.path.join(FS_ROOT, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(text)


def load(uri):
    """Returns the content an external entity or XInclude resolves to.

    file:// URIs are read from the fake filesystem, with the path clamped
    inside FS_ROOT. http(s):// URIs are fetched for real. Anything else, or a
    failed read, raises XxeError with libxml2's own wording for the failure.
    """
    if uri.startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(uri, timeout=5) as resp:
                return resp.read(4096).decode("utf-8", "replace")
        except Exception:
            raise XxeError(f'warning: failed to load external entity "{uri}"')

    if uri.startswith("file://"):
        # file:///C:/Windows/win.ini -> Windows/win.ini, file:///etc/passwd -> etc/passwd.
        path = re.sub(r"^file://(localhost)?", "", uri).replace("\\", "/")
        path = re.sub(r"^/?[A-Za-z]:/", "", path)
        # normpath on an absolute path drops any "../" that would climb above
        # the root, so the join below stays inside FS_ROOT.
        rel = os.path.normpath("/" + path).lstrip("/")
        full = os.path.join(FS_ROOT, rel)
        if os.path.isfile(full):
            with open(full, "r") as f:
                return f.read()

    raise XxeError(f'warning: failed to load external entity "{uri}"\nparser error : failed to load external entity "{uri}"')


def expand(body, entities):
    """Replaces every &name; reference with the entity it names."""
    def repl(m):
        name = m.group(1)
        if name in PREDEFINED:
            return m.group(0)
        if name not in entities:
            raise XxeError(f"parser error : Entity '{name}' not defined")
        kind, value = entities[name]
        # Internal entities are plain text with character references decoded.
        # External ones are loaded from their URI.
        return html.unescape(value) if kind == "value" else load(value)

    return ENTITY_REF_RE.sub(repl, body)


def parse_document(raw):
    """Resolves a document's DOCTYPE, XInclude and entities, then checks it is well-formed.

    Returns the document as the parser would hand it on, with the DOCTYPE
    removed and every reference expanded. Raises XxeError or ET.ParseError when
    the document can't be parsed.
    """
    entities = {}
    internal = ""
    body = raw
    doctype = DOCTYPE_RE.search(raw)
    if doctype:
        internal = doctype.group(2) or ""
        for d in ENTITY_RE.finditer(internal):
            is_param, name, system, value = d.group(1), d.group(2), d.group(3), d.group(4)
            if is_param:
                continue
            entities[name] = ("system", system) if system is not None else ("value", value)
        # Parameter entities are loaded when the subset references them. This
        # is how a blind XXE fetches a remote DTD, even when nothing is echoed.
        param_uris = {d.group(2): d.group(3) for d in ENTITY_RE.finditer(internal) if d.group(1) and d.group(3)}
        for name in PARAM_REF_RE.findall(internal):
            if name in param_uris:
                try:
                    load(param_uris[name])
                except XxeError:
                    pass
        body = raw[: doctype.start()] + raw[doctype.end():]

    # XInclude is resolved by the server building its own document, so the
    # DOCTYPE isn't needed for it.
    body = XINCLUDE_RE.sub(lambda m: load(m.group(1)), body)
    body = expand(body, entities)
    # A well-formedness check. ElementTree raises ParseError on a bad document,
    # which becomes the parser error the scanner's classifier looks for.
    ET.fromstring(body)
    return body


class Handler(http.server.BaseHTTPRequestHandler):
    """Routes requests to the endpoints listed at the top of this file."""

    def do_GET(self):
        """Serves the HTML page, the JSON status endpoint, and a 404 for anything else."""
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            page = ('<html><body><h1>XML lab</h1>'
                    '<form action="/api/xml" method="post"><textarea name="doc"></textarea></form>'
                    '<script>fetch("/api/xml", {method: "POST"})</script>'
                    '<a href="/api/status">status</a></body></html>')
            return self.send_body(200, "text/html; charset=utf-8", page)
        if path == "/api/status":
            return self.send_body(200, "application/json", json.dumps({"ok": True}))
        return self.send_body(404, "text/plain; charset=utf-8", "not found")

    def do_POST(self):
        """Handles POST for the XML endpoints."""
        self.handle_xml()

    def do_PUT(self):
        """Handles PUT for the XML endpoints."""
        self.handle_xml()

    def handle_xml(self):
        """Parses the request body as XML on the vulnerable and hardened endpoints."""
        path = urlparse(self.path).path
        if path not in ("/api/xml", "/api/xml/safe"):
            return self.send_body(404, "text/plain; charset=utf-8", "not found")
        length = int(self.headers.get("Content-Length", 0))
        # Decoded as text, and the parser doesn't look at Content-Type. Like
        # libxml2, it reads whatever it's given.
        raw = self.rfile.read(length).decode("utf-8", "replace")

        if path == "/api/xml/safe" and "<!DOCTYPE" in raw:
            return self.send_body(400, "text/plain; charset=utf-8", "parser error : DOCTYPE is not allowed")
        try:
            out = parse_document(raw)
        except XxeError as e:
            return self.send_body(400, "text/plain; charset=utf-8", str(e))
        except ET.ParseError as e:
            return self.send_body(400, "text/plain; charset=utf-8", f"parser error : {e}")
        return self.send_body(200, "application/xml; charset=utf-8", out)

    def send_body(self, status, content_type, text):
        """Sends text as the response body with the given status and content type."""
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
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
    print(f"XXE lab on http://127.0.0.1:{PORT}")
    print("  POST /api/xml        vulnerable XML endpoint")
    print("  POST /api/xml/safe   rejects DOCTYPE")
    print("  GET  /               page with a form pointing at /api/xml")
    print("  GET  /api/status     JSON, not XML")
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
