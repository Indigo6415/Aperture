#!/usr/bin/env bash
set -euo pipefail

PORT=8080
HOST=127.0.0.1

cat > /tmp/cors-demo.html <<'EOF'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CORS Demo</title>
  <style>
    body { font: 16px system-ui; max-width: 900px; margin: 40px auto; }
    pre { background:#111; color:#0f0; padding:16px; overflow:auto; }
    button { padding:10px 16px; }
  </style>
</head>
<body>
  <h1>CORS demonstration</h1>
  <p>
    This page is served from <code>http://127.0.0.1:8080</code>.
  </p>

  <button onclick="testCors()">Test CORS</button>
  <pre id="output">Waiting...</pre>

<script>
async function testCors() {
  const output = document.getElementById("output");
  output.textContent = "Requesting https://api.twilio.com/ ...";

  try {
    const response = await fetch("https://api.twilio.com/", {
      method: "GET",
      credentials: "include"
    });

    const body = await response.text();

    output.textContent =
      `HTTP ${response.status}\n\n` +
      `Browser was able to read the response.\n\n` +
      body;
  } catch (err) {
    output.textContent =
      "Browser blocked the cross-origin request:\n\n" + err;
  }
}
</script>
</body>
</html>
EOF

echo "Starting CORS demo:"
echo "  http://$HOST:$PORT"
echo
echo "Press Ctrl-C to stop."

cd /tmp
python3 -m http.server "$PORT" --bind "$HOST"

