# Handoff: Estate Hierarchy view (replaces Aperture's full-page Graph view)

## Overview

Replaces `GraphView` — today a d3-force scatter of unlabeled circles — with an explicit
five-tier hierarchy: **site → cluster → subdomain → technology → page group**. Clusters
collapse/expand, a selected host lights its whole path from the apex, and the two right-hand
panels show that host's fingerprinted technologies and its page groups. This is option **1a**
from the design conversation.

It answers four questions the current graph can't: where a technology lives, which subdomain
is riskiest, the shape of the estate, and where exposed files pool.

## About the design files

`Aperture Graph.dc.html` in this bundle is a **design reference written in HTML**, not
production code. It renders four cards: `#0a` (a recreation of today's Graph view at real
scale, for comparison), `#1a` (this design), `#1b`, `#1c` (the two options not chosen).
Recreate `#1a` in the existing `web/` React + Tailwind frontend using its established
patterns — do not port the HTML.

Two artifacts of the prototype's authoring environment that should **not** be reproduced:

1. Labels and node boxes are absolutely-positioned HTML `<div>`s overlaying a transparent
   `<svg>` that carries only the grid lines and link curves. In the React app, draw the whole
   canvas as SVG (`<rect>` + `<text>`) — the overlay exists only because the prototype tool
   could not put interpolated text inside `<text>`.
2. Colors are literal hex values inline. In the app they come from Tailwind classes matching
   the existing palette (see Design tokens below).

## Fidelity

**High-fidelity.** Colors, type sizes, geometry and interaction states are final. Every value
below is measured from the prototype.

## No backend work required

Everything is derivable from data the frontend already receives:

| Need | Source that already exists |
| --- | --- |
| apex + subdomains | `checks['<domain>::subdomains-verified'].data.subdomains` |
| per-host status | `checks['<host>::http'].data.statusCode` |
| technologies + CVEs | `checks['<host>::technologies'].data.technologies` → `TechDetection[]` with `.cves` |
| pages | content-discovery `Finding[]` per run (`api.listFindings`) |
| exposed files | `isDangerousExtension(extensionOf(f.url))` + `statusCode === 200` (`web/src/extensions.ts`) |
| live updates | the `watchScan` / `watchRun` sockets `useScanGraph` already opens |

No new endpoints, no Go changes, no schema changes.

## Files to add / change

```
web/src/estate.ts                       NEW  — clustering + risk, pure functions
web/src/useEstateModel.ts               NEW  — the tiered model, built on useScanGraph's sockets
web/src/components/HierarchyView.tsx    NEW  — the view itself
web/src/components/GraphView.tsx        EDIT — becomes a mode switch: hierarchy | graph | matrix
web/src/useScanGraph.ts                 EDIT — emit technology nodes; expose grouped pages
web/src/components/GraphCanvas.tsx      keep as-is (still used by the Overview preview and `graph` mode)
```

### `useScanGraph.ts` — two changes

1. `applyCheck` currently early-returns unless `check.kind === 'subdomains'`. Add a
   `technologies` branch: `check.domain` is the host, `check.data.technologies` is
   `TechDetection[]`. Emit one node per `(host, tech.name)` with the tech's `cves`, and an
   edge host → tech. Add `'technology'` to `GraphNodeType`.
2. Page nodes stay one-per-URL for the tables, but expose an additional memo that buckets them:
   key on the first path segment (`/wp-content/*`, `/api/v1/*`, `/assets/*`), plus one bucket per
   dangerous-extension 200 hit, kept as its own row so it can be rendered in the warning
   treatment. Cap at 9 groups per host, largest first. This is what keeps 3,000 pages legible.

### `estate.ts` — two pure functions

```ts
// clusterOf groups hosts that are the same application: identical fingerprint
// signature (sorted technology names) first, hostname prefix as the fallback for
// hosts with no fingerprint yet (mx1, smtp). Cluster labels are derived from the
// dominant CMS/framework in the group, or the prefix.
export function clusterOf(host: EstateHost): ClusterId

// riskOf is the sort key for hosts and the badge on clusters.
export function riskOf(host: EstateHost): number {
  return crit * 12 + high * 6 + medium * 2 + exposedFiles * 5
}
```

`crit/high/medium` come from counting `TechDetection.cves[].severity` (NVD vocabulary, same
strings `TechTable.tsx` already sorts on). `exposedFiles` is the count of that host's
content-discovery findings passing the `isDangerousExtension` + `200` test — the same rule
`ScanView.tsx`'s "Critical files" card uses, so the two numbers agree.

## Layout — exact geometry

Canvas is a fixed 1400 × 648 board inside the flex-1 area under the toolbar; it does not
reflow (pan/zoom can be added later, the tiers are positioned absolutely in board space).

| Tier | x | width | notes |
| --- | --- | --- | --- |
| Site (apex) | 16 | 190 | height 76, vertically centred at y 324 |
| Cluster | 230 | 216 | height 76, gap 18, the 6 rows centred as a block |
| Subdomain | 500 | 300 | height 32, gap 6, centred on y 330; only the expanded cluster's hosts |
| Technology panel | 880 | 490 | top 44; header 34 + 26 per row |
| Page-group panel | 880 | 490 | top = 44 + techPanelHeight + 40; 26 per row |

Vertical hairlines (`#1c1c20`, 1px) at x = 206, 456, 830 separate the tiers.

**Boxes** — square corners, no radius, 1px border, 3px accent bar flush to the left edge,
`padding: 0 12px 0 14px`, `display:flex; align-items:center; gap:10px`. Title and subtitle in a
`flex:1; min-width:0` column (gap 3px), meta right-aligned and `flex:none`. All three lines
`white-space:nowrap; overflow:hidden; text-overflow:ellipsis`.

**Links** are cubic béziers with horizontal control points, `fill:none`:

- apex → cluster: `M206,324 C 214,324 216,<cy> 230,<cy>`
- cluster → host: `M446,<clusterCy> C 470,<clusterCy> 474,<hostCy> 500,<hostCy>`
- host → panel: `M800,<hostCy> C 840,<hostCy> 840,<panelAnchorY> 880,<panelAnchorY>`

Stroke: the cluster's color at 1px (opacity 0.45), or `#38bdf8` at 2px when the row is
selected or hovered; opacity 0.14 for rows filtered out.

## Components, state and content

**Toolbar** (above the board, `border-b border-neutral-800`, `px-3 py-2`, one row):
tier chips (all on, decorative-but-real toggles) · a `⚠ exposed files & CVEs only` toggle ·
right-aligned: search input (200px, mono 12px, `focus:border-sky-500`), the count line
`"{pages} of 3,090 pages · {hosts}/36 hosts"`, and the existing sky-600 `Scan selected (n)`
button, which calls `api.runContentDiscovery(scanId, [domain, ...selected])` — the endpoint
already exists and already de-dupes covered targets.

**Cluster box**: title `−  Marketing & content` / `+  …` in Barlow Condensed 12.5px uppercase,
letter-spacing .05em; subtitle `6/6 hosts · 1,085 pages · 8 tech` in Barlow 11px `#71717a`;
meta `⚠ 14` in `#f87171` when the cluster holds exposed files. Open: background `#131318`,
border = cluster color, 1.5px. Closed: `#0d0d10` / `#2b2b2f` / 1px. Filtered to nothing: title
drops to `#52525b`.

**Host row**: name in mono 12.5px; meta `200  ·  88p  ·  4t  ·  ⚠4` in mono 11px (`#8a8a92`, or
`#f87171` when files > 0). Accent bar = `#f87171` if files > 0, else the status-code color from
the existing `statusColor.ts`. Selected: background `#12181f`, border `#38bdf8` 1.5px. Hover:
`#131317`.

**Technology panel**: header `Technologies on old` + `4 detected`, rows are
`{name}` / `{category}  ·  {n} CVE`, 26px tall, `border-bottom: 1px solid #131316`, 3px accent
bar in the category color. CVE count in `#f87171`.

**Page-group panel**: header `Page groups on old` + `88 pages`, rows are
`{path pattern}` / a 120px bar (fill proportional to the largest group) / `{status}  ·  {count}`.
Dangerous-file rows: background `#1a0d0d`, text `#fca5a5`, `⚠ ` prefix, red bar and accent.

**State** (all local to the view):

```ts
expanded: ClusterId | null     // which cluster is open — click a cluster box toggles
selHost:  string | null        // drives both right-hand panels — click a host row
hover:    string | null        // lights the cluster→host→panel path
q:        string               // matches hostname or technology name
riskOnly: boolean              // hosts with 0 files and 0 CVEs drop out
selected: Set<string>          // "Scan selected"
```

Filtering dims rather than removes: a host that fails the filter keeps its row but renders at
`#3f3f46` text with its link at opacity 0.14, and its cluster's count reads `2/6 hosts`. That's
deliberate — the estate's shape must stay stable while you filter.

Reuse `FacetFilterBar` for the search/risk controls if you want its tag semantics: add
`technology` and `cluster` dimensions and its existing include/exclude tags give you the pivot
for free.

## Design tokens

| Role | Value | Tailwind equivalent in this codebase |
| --- | --- | --- |
| board / page ground | `#0a0a0a` | `bg-neutral-950` |
| panel ground | `#0c0c0e`, `#0d0d10` | — (use arbitrary value) |
| hairline border | `#262626` / `#2b2b2f` | `border-neutral-800` |
| tier divider | `#1c1c20` | — |
| row divider | `#131316`, `#17171a` | `divide-neutral-900` |
| primary text | `#f5f5f5` / `#e5e5e5` | `text-neutral-100` / `text-neutral-200` |
| secondary | `#a3a3a3` → `#8a8a92` → `#71717a` → `#52525b` → `#3f3f46` | `text-neutral-400/500/600/700` |
| accent (selection, links) | `#38bdf8`, hover `#7dd3fc`, button `#0284c7` | `sky-400 / sky-300 / sky-600` |
| status 2xx/3xx/4xx/5xx | `#34d399` `#38bdf8` `#fbbf24` `#f87171` | already in `statusColor.ts` |
| danger | `#f87171`, tint `#1a0d0d`, text `#fca5a5` | `red-400` / `red-950/20` / `red-300` |
| cluster colors | `#a78bfa` `#38bdf8` `#fbbf24` `#5980a6` `#34d399` `#f87171` | violet/sky/amber/steel/emerald/red-400 |
| tech categories | server `#5980a6` · language `#a78bfa` · framework `#38bdf8` · cms `#fbbf24` · cdn `#34d399` | — |

**Type**: Barlow Condensed 600 for headings and cluster titles (uppercase, letter-spacing
.05–.08em); Barlow 400 for body and subtitles; IBM Plex Mono 400/500 for every hostname, path,
status code, count and column header. Sizes used: 9.5px (uppercase mono labels,
letter-spacing .16em), 11px (meta), 11.5–12px (body/mono rows), 12.5px (titles, hostnames),
13px (nav). Nothing below 9.5px.

The steel `#5980a6`, the Barlow/Barlow Condensed pairing, the square corners, the visible tier
grid and the `+` registration marks on the card frames come from the **Industry** design system
bound to this project; the dark ground and sky accent come from your existing app. Registration
marks are decoration on the design board and can be dropped inside the app if they read as
noise there.

## Interactions

- **Click cluster box** → toggle `expanded`; opening one selects its first host.
- **Click host row** → `selHost`; both panels and the two link curves update.
- **Hover host row** → row background `#131317`, its cluster→host link goes `#38bdf8` 2px.
- **Type in search** → dims non-matching hosts (hostname or technology substring), cluster
  counts update live.
- **⚠ toggle** → dims hosts with no exposed files and no CVEs.
- **Scan selected** → existing content-discovery endpoint.
- No transitions in the prototype; if you add them, keep them under 120ms — this is a tool.
- Keyboard: give the boxes `:focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px }`
  per the Industry system, and make cluster/host boxes real `<button>`s so tab order works.

## Assets

None. No images, no icon files. If you add icons, the Industry system specifies Lucide at
stroke-width 1.5.

## Files in this bundle

- `Aperture Graph.dc.html` — the design reference. Card `#1a` is this design; `#0a` is the
  recreation of today's view; `#1b` and `#1c` are the rejected options, kept for context.
