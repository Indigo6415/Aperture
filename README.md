# Aperture

A graphical front end for CLI recon/enumeration tools, organized around
**cases**: start a case, add targets to it (by hand, or by promoting results
from a tool run), then launch a scanner against whichever targets you pick —
[feroxbuster](https://github.com/epi052/feroxbuster) or
[katana](https://github.com/projectdiscovery/katana) for content discovery
(wordlist-based and crawl-based, respectively), [ffuf](https://github.com/ffuf/ffuf),
[subfinder](https://github.com/projectdiscovery/subfinder), or
[amass](https://github.com/owasp-amass/amass) for subdomain enumeration, and
[httpx](https://github.com/projectdiscovery/httpx) or
[WhatWeb](https://github.com/urbanadventurer/WhatWeb) for bulk HTTP
probing/tech fingerprinting. An "Identify" action runs passive/read-only
recon (DNS/TLS/HTTP/WHOIS, certificate-transparency subdomain discovery)
against selected targets. Nothing runs automatically —
every job is one you explicitly launched, and any running job can be
stopped. Findings from a job's results can be selected and saved back to the
case as new targets, so a case builds up over time into a full picture you
can export as a report — shipped as a single static Go binary with the
frontend embedded.

## Install

`install.sh` (macOS/Linux) and `install.ps1` (Windows) install everything —
Go, Node, ffuf, feroxbuster, nuclei, subfinder, amass, httpx, katana (plus,
best-effort, WhatWeb on macOS/Linux) — build Aperture from this checkout,
and put `aperture` on your `PATH`. Safe to re-run any time to update
everything to latest; no admin/root required beyond your OS's usual
package-manager prompts.

```sh
./install.sh                              # macOS/Linux
powershell -ExecutionPolicy Bypass -File install.ps1   # Windows
```

## Prerequisites

If you'd rather set things up yourself instead of using the installer:

- `ffuf` and `feroxbuster` installed and on `PATH`
- `subfinder`, `amass`, `httpx`, and `katana` on `PATH` for their respective
  tabs (each degrades gracefully to "not available" via `GET /api/tools` if
  missing — nothing else in Aperture is affected)
- `whatweb` on `PATH` for the WhatWeb tab (Ruby-based; not installed by
  `install.ps1` on Windows)
- Go 1.23+ (to build the backend)
- Node 20+ (only needed to rebuild the frontend)

## Build

```sh
cd web && npm install && npm run build   # outputs into internal/webui/dist
cd .. && go build -o aperture ./cmd/aperture
```

`go build` alone works too as long as `internal/webui/dist` already has a
built frontend in it (it's committed, so a fresh clone builds immediately;
rebuild the frontend step above after making UI changes).

## Run

```sh
./aperture                 # serves the UI on http://127.0.0.1:8080 and opens it
./aperture -addr :9000 -db ./aperture.db -open=false
```

## Development

Run the Go backend and the Vite dev server side by side; Vite proxies
`/api` and `/ws` to the backend so there's no CORS to deal with:

```sh
go run ./cmd/aperture -addr 127.0.0.1:8080   # terminal 1
cd web && npm run dev                        # terminal 2, http://localhost:5173
```

## Layout

- `cmd/aperture` — CLI entrypoint
- `internal/model` — the common `Finding` data model every adapter normalizes into
- `internal/adapters` — subprocess wrappers around ffuf/feroxbuster (nuclei/nmap/webfuzz also live here, kept registered but unused for now)
- `internal/engine` — DAG flow executor (filter/merge/table/export nodes + adapters), driving each job's flow
- `internal/recon` — fast stdlib-only DNS/TLS/HTTP/WHOIS checks, passive (crt.sh + DNSDumpster) subdomain discovery with two-path liveness verification, and web technology fingerprinting -- run on demand by an "Identify" job, never automatically
- `internal/cve` — live NVD CVE lookups for fingerprinted technology versions
- `internal/techfp` — the curated web technology fingerprint signature set
- `internal/store` — SQLite persistence (cases, targets, jobs, findings)
- `internal/api` — REST + WebSocket server
- `internal/webui` — embeds the built frontend (`internal/webui/dist`) into the binary
- `web` — React + Tailwind frontend
