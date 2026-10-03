package apienum

import (
	"context"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// PhaseEvent is one coarse progress update -- "spec", "graphql", "crawl",
// "bruteforce", or "characterize" -- so the UI can show something more
// useful than a spinner while a run works through its phases (spec/
// GraphQL discovery and the crawl are each a handful of requests and
// report Total: 1; brute forcing and characterization can mean hundreds
// and report real done/total counts as they go).
type PhaseEvent struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// RunScan runs a full enumeration against rawTarget with no progress
// streaming -- see RunScanStreaming.
func RunScan(ctx context.Context, rawTarget string, opts Options) (*Result, error) {
	return RunScanStreaming(ctx, rawTarget, opts, nil, nil)
}

// RunScanStreaming resolves rawTarget and works through every discovery
// source in turn -- spec, GraphQL, crawl (which also seeds JS mining),
// wordlist brute force -- merges everything into one route list, then
// characterizes each route concurrently. onPhase (when non-nil) reports
// coarse per-phase progress; onRoute (when non-nil) is called once per
// route as its characterization finishes, in completion order, so a caller
// can render the route tree filling in live instead of waiting for the
// whole run.
func RunScanStreaming(ctx context.Context, rawTarget string, opts Options, onPhase func(PhaseEvent), onRoute func(Route)) (*Result, error) {
	t := ResolveTarget(rawTarget)

	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}
	client := newClient(conc, newLimiter(opts.RateLimit), opts.Headers)

	phase := func(name string, done, total int) {
		if onPhase != nil {
			onPhase(PhaseEvent{Phase: name, Done: done, Total: total})
		}
	}

	phase("spec", 0, 1)
	schema, specRoutes := discoverSpec(ctx, client, t)
	phase("spec", 1, 1)

	phase("graphql", 0, 1)
	graphql, graphqlRoutes := discoverGraphQL(ctx, client, t)
	phase("graphql", 1, 1)

	phase("crawl", 0, 1)
	crawled := crawlSite(ctx, client, t, opts.CrawlDepth, opts.MaxPages)
	phase("crawl", 1, 1)

	jsRoutes := mineJS(crawled.Scripts, t)
	crawlRoutes := routesFromCrawl(crawled, t)

	merged := mergeRouteLists(specRoutes, graphqlRoutes, crawlRoutes, jsRoutes)

	phase("bruteforce", 0, 1)
	bfRoutes := bruteforcePaths(ctx, client, t, bruteforceRoots(merged), opts.ExtraWordlist, func(done, total int) {
		phase("bruteforce", done, total)
	})
	merged = mergeRouteLists(merged, bfRoutes)

	phase("characterize", 0, len(merged))
	characterized := characterizeAll(ctx, client, t, merged, scanprogress.Or(opts.Progress), func(done, total int, r Route) {
		phase("characterize", done, total)
		if onRoute != nil {
			onRoute(r)
		}
	})
	// graphqlRoutes were already characterized-equivalent at discovery time
	// (characterizeRoute passes them through unchanged) -- re-attach them
	// here so a caller relying solely on RunScan's returned Result (rather
	// than the onRoute stream) still sees them; onRoute above already fired
	// for them once via characterizeAll since they're included in merged.

	injectionPoints := collectInjectionPoints(characterized)

	return &Result{
		Target: t, Schema: schema, GraphQL: graphql, Routes: characterized,
		InjectionPoints: injectionPoints, Stats: computeStats(characterized, injectionPoints),
	}, nil
}

// routesFromCrawl turns a crawl's own page visits and form actions into
// Routes -- a page the crawler actually fetched (2xx, or it wouldn't be in
// Pages) is direct, confirmed evidence a path exists, and a <form action>
// is exactly the kind of route a crawl-only tool would otherwise miss (see
// crawl.go's doc comment).
func routesFromCrawl(cr crawlResult, t *Target) []Route {
	var routes []Route
	for _, p := range cr.Pages {
		path := pathOnly(p, t)
		if path == "" {
			continue
		}
		routes = append(routes, Route{
			ID: routeID("crawl", "GET "+path), Path: path, Group: pathGroup(path), Source: "crawl", Confirmed: true,
			Methods: []MethodProbe{{Method: "GET", Allowed: true}},
		})
	}
	for _, a := range cr.FormActions {
		path := pathOnly(a, t)
		if path == "" {
			continue
		}
		routes = append(routes, Route{
			ID: routeID("crawl", "POST "+path), Path: path, Group: pathGroup(path), Source: "crawl", Confirmed: true,
			Methods: []MethodProbe{{Method: "POST"}},
		})
	}
	return routes
}

func pathOnly(fullURL string, t *Target) string {
	trimmed := fullURL
	if len(trimmed) > len(t.URL) && trimmed[:len(t.URL)] == t.URL {
		trimmed = trimmed[len(t.URL):]
	}
	if trimmed == "" {
		return "/"
	}
	if trimmed[0] != '/' {
		return ""
	}
	return trimmed
}

// mergeRouteLists combines any number of Route slices into one, keyed by
// path alone (method support is still per-route detail, filled in -- or
// replaced outright -- by characterizeRoute later): a path both a spec
// describes and the crawl actually visited folds into one entry rather
// than showing it twice, with every source's methods and params merged in
// and Source/Confirmed upgraded to whichever contributing source is most
// authoritative (see sourceRank) rather than whichever happened to be
// seen first.
func mergeRouteLists(lists ...[]Route) []Route {
	var order []string
	byPath := map[string]Route{}
	for _, list := range lists {
		for _, r := range list {
			existing, ok := byPath[r.Path]
			if !ok {
				byPath[r.Path] = r
				order = append(order, r.Path)
				continue
			}
			existing.Params = mergeParams(existing.Params, r.Params)
			existing.Methods = mergeMethodStubs(existing.Methods, r.Methods)
			if r.Confirmed {
				existing.Confirmed = true
			}
			if sourceRank(r.Source) > sourceRank(existing.Source) {
				existing.Source = r.Source
			}
			byPath[r.Path] = existing
		}
	}
	out := make([]Route, 0, len(order))
	for _, k := range order {
		out = append(out, byPath[k])
	}
	return out
}

// mergeMethodStubs unions two routes' method lists by method name -- pre-
// characterization, a MethodProbe here is just "this source says this
// method applies", not yet a real probe result, so the only thing worth
// deduplicating on is the method name itself.
func mergeMethodStubs(existing, additions []MethodProbe) []MethodProbe {
	seen := make(map[string]bool, len(existing))
	for _, m := range existing {
		seen[m.Method] = true
	}
	for _, m := range additions {
		if seen[m.Method] {
			continue
		}
		seen[m.Method] = true
		existing = append(existing, m)
	}
	return existing
}

// sourceRank orders Route.Source by how authoritative it is -- a spec
// saying a route exists outranks the same path merely turning up in a JS
// bundle or a wordlist guess.
func sourceRank(s string) int {
	switch s {
	case "spec":
		return 4
	case "graphql":
		return 3
	case "crawl":
		return 2
	case "js":
		return 1
	default: // "bruteforce"
		return 0
	}
}

// computeStats tallies Result.Stats from the finished route/injection-point
// lists.
func computeStats(routes []Route, points []InjectionPoint) Stats {
	s := Stats{RoutesFound: len(routes), InjectionPoints: len(points)}
	for _, r := range routes {
		if r.Confirmed {
			s.ConfirmedRoutes++
		} else {
			s.UncertainRoutes++
		}
		s.RequestsSent += len(r.Methods)
	}
	return s
}
