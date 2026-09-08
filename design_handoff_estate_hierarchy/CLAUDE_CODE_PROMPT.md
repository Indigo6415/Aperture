# How to build this with Claude Code

## 1. Put this folder in the repo

Unzip it at the root of your Aperture checkout so the path is:

```
aperture/design_handoff_estate_hierarchy/README.md
aperture/design_handoff_estate_hierarchy/Aperture Graph.dc.html
```

## 2. Open Claude Code in the repo root and paste this

---

Read `design_handoff_estate_hierarchy/README.md` in full before writing any code. It is a
high-fidelity design spec for replacing this app's full-page Graph view with a five-tier
"Estate Hierarchy" view: site → cluster → subdomain → technology → page group. The spec
carries exact geometry, colors, type sizes, state and interactions — follow it literally
rather than improvising a layout.

Also open `design_handoff_estate_hierarchy/Aperture Graph.dc.html` in a browser and look at
the card labelled `1a`. That is the target. The card labelled `0a` is a recreation of what the
app renders today, for comparison; `1b` and `1c` are rejected alternatives — ignore them.

Two things in that HTML file are artifacts of the tool that produced it and must NOT be copied:
it positions HTML `<div>`s over a transparent `<svg>` because its templating could not put
dynamic text inside `<text>`, and it inlines hex colors. In this codebase, draw the whole board
as SVG (`<rect>`, `<path>`, `<text>`) and use Tailwind classes consistent with the rest of
`web/src/components` — the README maps every hex value to the palette already in use.

Before you write anything, read these files so the new view matches existing conventions —
comment voice, hook patterns, Tailwind usage:

- `web/src/useScanGraph.ts`
- `web/src/components/GraphView.tsx`
- `web/src/components/GraphCanvas.tsx`
- `web/src/components/ScanView.tsx`
- `web/src/components/FacetFilterBar.tsx`
- `web/src/components/TechTable.tsx`
- `web/src/types.ts`, `web/src/statusColor.ts`, `web/src/extensions.ts`, `web/src/url.ts`

Then implement it in this order, and stop after each step to report what you changed:

1. `web/src/estate.ts` — new. Pure functions only: `clusterOf(host)` (group hosts by identical
   fingerprint signature, hostname prefix as fallback) and `riskOf(host)` (weights in the README).
   Unit-testable, no React.
2. `web/src/useScanGraph.ts` — extend. Add `'technology'` to `GraphNodeType` and emit technology
   nodes/edges from the `technologies` checks that `applyCheck` currently drops on the floor.
   Add a memo that buckets page findings into at most 9 path-pattern groups per host, keeping
   dangerous-extension 200 hits as their own rows. Do not break the existing consumers
   (`GraphView`, and `ScanView`'s Overview preview).
3. `web/src/useEstateModel.ts` — new. Builds the tiered model (apex → clusters → hosts →
   technologies → page groups) from the hook above. No new sockets: reuse the `watchScan` /
   `watchRun` subscriptions `useScanGraph` already opens.
4. `web/src/components/HierarchyView.tsx` — new. The view, to the geometry in the README.
   Cluster and host boxes must be real `<button>` elements with the accent `:focus-visible`
   ring so keyboard nav works.
5. `web/src/components/GraphView.tsx` — edit. Becomes a mode switch (`hierarchy | graph`) over
   one shared model, defaulting to `hierarchy`. Keep the existing `GraphCanvas` reachable as the
   `graph` mode; keep the current toolbar's search, facet filters and node counts working in both.

Constraints:

- No backend changes. No new Go code, no new endpoints, no schema changes. Everything the view
  needs is already in the checks and findings the frontend receives — the README has the table
  of exactly where each value comes from.
- No new npm dependencies. `d3-force` is already present and is not needed by this view (the
  tiers are positioned arithmetically); keep it only for the retained `graph` mode.
- "Scan selected" must call the existing `api.runContentDiscovery(scanId, targets)`.
- Filtering dims rows rather than removing them — see the README, this is deliberate.
- Run `npm run lint` and `npx tsc --noEmit` in `web/` and fix everything before you say you're done.

When it builds, run the app (`go run ./cmd/aperture` plus `cd web && npm run dev`), scan a
domain with several subdomains, and compare your view side by side with card `1a` in the HTML.
List any place you deviated from the spec and why.

---

## 3. If it goes off the rails

The two most likely drifts are (a) inventing its own force layout instead of the arithmetic
tiers, and (b) re-styling with values that aren't in the spec. Both are fixed by pointing it
back at a section: "re-read the Layout section of the README and correct the geometry" or
"re-read Design tokens — the panel ground is #0c0c0e, not neutral-900".
