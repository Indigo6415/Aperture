// Package xss tests input points -- URL query parameters, discovered
// <form> fields (submitted via that form's own GET/POST, exactly as a
// browser would), and a handful of commonly-echoed request headers -- for
// Cross-Site Scripting: a response that reflects operator-supplied input
// back into the page without encoding it for the context it lands in,
// letting an attacker craft a link/request that runs arbitrary JavaScript
// in another user's browser, in that user's own session.
//
// Unlike internal/probescan's much smaller injections.go check (a handful
// of payloads against the target's own query string plus a few scraped
// links), this scanner automatically builds its own candidate list of
// "every place user-controlled data may be displayed/used": it crawls the
// target same-origin (same breadth-first pattern as internal/csrf and
// internal/sstiscan), then for every page it visits collects every
// query-string parameter already in play, every field of every <form> it
// finds, and -- once, on the seed page -- a fixed set of request headers
// commonly rendered back somewhere (an access-log viewer, a "request
// details" debug page). See crawl.go's injectionPoint.
//
// This deliberately covers many different breakout techniques rather than
// one generic "<script>alert(1)</script>" probe, because the one thing
// that actually varies across real targets is *where* a filter/encoder
// falls short -- one app HTML-encodes "<" and ">" but not quotes, another
// blocks the literal string "script" case-sensitively, another encodes
// everything reflected into HTML body text but not what lands inside an
// already-open inline <script> block. See payloads.go's payloadModules doc
// comment for the full battery and what each one targets.
//
// One further module rounds this out beyond pure reflection:
// runDomSinkModule (checks.go) is a static heuristic over crawled pages'
// own inline scripts for a client-side (DOM) XSS pattern -- a tainted
// browser-side source (location.hash, document.referrer, ...) flowing into
// a dangerous rendering sink (innerHTML, document.write, eval, ...) -- that
// a pure request/response reflection check can never see, since nothing
// about it touches the server at all.
//
// Shaped like every other scanner in Aperture: a baseline plus a battery of
// check modules, each with fixed severity and findings present even when
// empty.
package xss

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"sort"
	"strings"
	"sync"
)

// Confidence levels for a Finding. "confirmed" means a headless browser ran the
// payload; "likely" means the static check matched; "heuristic" is a lead.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceHeuristic = "heuristic"
)

type Finding struct {
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Request is the exact request this finding's check sent (see
	// CapturedRequest in client.go) -- lets the frontend's "Send to Tester"
	// action replay precisely what triggered the finding.
	Request *CapturedRequest `json:"request,omitempty"`
	// Confidence is "confirmed" (browser-verified), "likely" (matched statically),
	// or "heuristic" (a lead to check by hand).
	Confidence string `json:"confidence,omitempty"`
}

type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration.
type Request struct {
	// URL is the seed page the crawl starts from.
	URL string `json:"url"`
	// Params are extra parameter names to fuzz directly onto URL's own query
	// string, in addition to every point the crawl itself discovers -- same
	// reasoning as sstiscan.Request.Params/ssrf.Request.Params.
	Params  []string          `json:"params,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// RecursionDepth is how many hops of same-origin <a href> links the
	// crawl follows beyond URL itself -- 0 scans just that one page.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides crawlDefaultMaxPages (capped at crawlMaxPagesCap).
	MaxPages int `json:"maxPages,omitempty"`
	// Progress, when set, receives one check per (payload module, injection
	// point) pair as it runs. Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

type Result struct {
	Baseline Baseline       `json:"baseline"`
	Modules  []ModuleResult `json:"modules"`
	// PagesScanned is every page the crawl actually fetched.
	PagesScanned []string `json:"pagesScanned"`
	// PointsTested is how many distinct injection points (query params,
	// form fields, headers) every module ran its payloads against.
	PointsTested int `json:"pointsTested"`
}

type runDeps struct {
	req    Request
	points []injectionPoint
	canary string
	sem    chan struct{}
	// rep receives one progress check per (payload module, point) pair.
	rep scanprogress.Reporter
	// confirmed holds the point keys an earlier module has already confirmed,
	// so later modules skip them. Modules run concurrently, so it is a sync.Map.
	confirmed *sync.Map
}

// maxBrowserChecks caps how many candidates are replayed in a headless browser
// in one run. Each check launches Chrome twice, so an uncapped run against a
// noisy target would spend most of its time there. Candidates past the cap stay
// at their static confidence.
const maxBrowserChecks = 20

// maxConcurrentRequests bounds how many requests this scanner has in
// flight at once, across every payload module combined -- fifteen payload
// modules each testing every discovered point (often several dozen between
// query params, form fields across every crawled page, and headers) would
// otherwise all fire at essentially the same instant. Same reasoning as
// sstiscan/ssrf/openredirect's own constant of the same name.
const maxConcurrentRequests = 16

// Run crawls req.URL to discover candidate injection points (see crawl.go),
// takes a plain baseline request, then runs every payload module (plus the
// DOM-sink module) concurrently against every point.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	client := newClient()
	rep.Phase("Sending baseline request")
	baselineRes := fetchPlain(ctx, client, seed.String(), req.Headers)
	if baselineRes.Err != nil {
		return nil, fmt.Errorf("xss: baseline request failed: %w", baselineRes.Err)
	}

	rep.Phase("Crawling pages for injection points")
	cr, err := crawl(ctx, client, seed, req)
	if err != nil {
		return nil, fmt.Errorf("xss: crawl failed: %w", err)
	}

	points := append([]injectionPoint{}, cr.Points...)
	seen := map[string]bool{}
	for _, p := range points {
		seen[pointKey(p)] = true
	}
	base := *seed
	base.RawQuery = ""
	base.Fragment = ""
	for _, name := range req.Params {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		p := injectionPoint{Kind: kindQuery, PageURL: seed.String(), URL: base.String(), Method: "GET", Param: name, Defaults: seed.Query()}
		if seen[pointKey(p)] {
			continue
		}
		seen[pointKey(p)] = true
		points = append(points, p)
	}

	rep.Phase(fmt.Sprintf("Testing %d injection point(s) with %d payload module(s)", len(points), len(payloadModules)))
	deps := runDeps{req: req, points: points, canary: newCanary(), sem: make(chan struct{}, maxConcurrentRequests), confirmed: &sync.Map{}, rep: rep}

	type moduleOutcome struct {
		id, name, severity string
		findings           []pointFinding
	}

	results := make([]moduleOutcome, len(payloadModules))
	allEscaped := make([][]escapedSighting, len(payloadModules))
	var wg sync.WaitGroup
	for i, m := range payloadModules {
		wg.Add(1)
		go func(i int, m payloadDef) {
			defer wg.Done()
			findings, escaped := runPayloadModule(ctx, deps, m)
			results[i] = moduleOutcome{id: m.id, name: m.name, severity: m.severity, findings: findings}
			allEscaped[i] = escaped
		}(i, m)
	}
	wg.Wait()

	modules := make([]ModuleResult, 0, len(payloadModules)+2)
	browserChecks := 0
	confirmedPoints := map[string]bool{}
	var escapedFlat []escapedSighting
	for i, m := range results {
		flat := make([]Finding, 0, len(m.findings))
		for _, pf := range m.findings {
			// Browser replay happens here, after every module has finished, so the
			// probing itself never waits on Chrome.
			if browserChecks < maxBrowserChecks {
				pf = verifyPointFinding(ctx, pf, deps.canary)
				browserChecks++
			}
			confirmedPoints[pf.key] = true
			flat = append(flat, pf.finding)
		}
		modules = append(modules, ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: flat})
		escapedFlat = append(escapedFlat, allEscaped[i]...)
	}
	modules = append(modules, aggregateEscapedModule(escapedFlat, confirmedPoints))
	modules = append(modules, ModuleResult{ID: "dom-xss-sink", Name: "DOM XSS sink (static heuristic)", Severity: "low", Findings: runDomSinkModule(cr.Pages)})

	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })

	return &Result{
		Baseline:     Baseline{URL: req.URL, StatusCode: baselineRes.StatusCode},
		Modules:      modules,
		PagesScanned: cr.PagesScanned,
		PointsTested: len(points),
	}, nil
}
