# Aperture

A recon/enumeration suite with a web UI: a node-based flow editor for chaining
[ffuf](https://github.com/ffuf/ffuf) and [feroxbuster](https://github.com/epi052/feroxbuster)
scans together, filtering/merging their output, and visualizing results —
shipped as a single static Go binary with the frontend embedded.

## Install

`install.sh` (macOS/Linux) and `install.ps1` (Windows) install everything —
Go, Node, ffuf, feroxbuster — build Aperture from this checkout, and put
`aperture` on your `PATH`. Safe to re-run any time to update everything to
latest; no admin/root required beyond your OS's usual package-manager prompts.

```sh
./install.sh                              # macOS/Linux
powershell -ExecutionPolicy Bypass -File install.ps1   # Windows
```

## Prerequisites

If you'd rather set things up yourself instead of using the installer:

- `ffuf` and `feroxbuster` installed and on `PATH`
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
- `internal/adapters` — subprocess wrappers around ffuf/feroxbuster
- `internal/engine` — DAG flow executor (filter/merge/table/export nodes + adapters)
- `internal/store` — SQLite persistence (flows, runs, findings)
- `internal/api` — REST + WebSocket server
- `internal/webui` — embeds the built frontend (`internal/webui/dist`) into the binary
- `web` — React + React Flow + Tailwind frontend
