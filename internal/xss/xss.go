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
// comment for the single-payload techniques, and catalog.go for the families
// ported from dalfox's payload tables.
//
// Two modules go beyond pure reflection. runDomSinkModule (checks.go) looks
// for a client-side (DOM) XSS flow: a tainted browser-side source (location.hash,
// localStorage, postMessage data, ...) reaching a dangerous rendering sink
// (innerHTML, document.write, eval, ...). It abstractly interprets each page's
// script (domflow.go) and falls back to a regex heuristic only for a script that
// does not parse. blind.go stores callback payloads and waits for the callbacks,
// which finds stored XSS the scanner never sees rendered.
//
// Shaped like every other scanner in Aperture: a baseline plus a battery of
// check modules, each with fixed severity and findings present even when
// empty.
package xss

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/paramminer"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"sort"
	"strings"
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
	Params []string `json:"params,omitempty"`
	// MineParams, when true, runs parameter mining (internal/paramminer) against
	// the GET query of URL and folds every hidden parameter it finds into Params,
	// so the rest of the run tests them too. Off by default.
	MineParams bool              `json:"mineParams,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	// RecursionDepth is how many hops of same-origin <a href> links the
	// crawl follows beyond URL itself -- 0 scans just that one page.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides crawlDefaultMaxPages (capped at crawlMaxPagesCap).
	MaxPages int `json:"maxPages,omitempty"`
	// Progress, when set, receives one check per (payload module, injection
	// point) pair as it runs. Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
	// SkipBrowser turns off the headless-browser confirmation pass, so every
	// finding keeps its static confidence. The corpus test sets it: it runs
	// hundreds of scans and needs the static detector measured on its own.
	SkipBrowser bool `json:"-"`
	// PayloadBudget caps how many payloads one injection point is tried with.
	// Zero means defaultPayloadBudget; the value is capped at maxPayloadBudget.
	PayloadBudget int `json:"payloadBudget,omitempty"`
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

// runDeps is the state one run shares across its injection points.
type runDeps struct {
	req    Request
	points []injectionPoint
	canary string
	// families are the payload techniques in try order: the original modules,
	// then the dalfox catalog families (see catalog.go).
	families []payloadDef
	// budget is how many payloads one point is tried with, in total across families.
	budget int
	sem    chan struct{}
	// rep receives one progress check per injection point.
	rep scanprogress.Reporter
}

// maxBrowserChecks caps how many candidates are replayed in a headless browser
// in one run. Each check launches Chrome twice, so an uncapped run against a
// noisy target would spend most of its time there. Candidates past the cap stay
// at their static confidence.
const maxBrowserChecks = 20

// maxConcurrentRequests bounds how many requests this scanner has in flight at
// once, across every injection point. Same reasoning as sstiscan/ssrf/
// openredirect's own constant of the same name.
const maxConcurrentRequests = 16

// defaultPayloadBudget is how many payloads one injection point is tried with
// when the request does not set PayloadBudget. The budget is spent round-robin
// across the techniques, so each technique's best candidates come first. Forty
// matched the detection of a 200-payload budget on dalfox's corpus at a fifth of
// the requests, and each request is paced to the scan's rate, so the count matters.
const defaultPayloadBudget = 40

// maxPayloadBudget caps a caller-supplied PayloadBudget.
const maxPayloadBudget = 2000

// payloadBudgetFor resolves a request's budget to the value the run uses.
func payloadBudgetFor(requested int) int {
	switch {
	case requested <= 0:
		return defaultPayloadBudget
	case requested > maxPayloadBudget:
		return maxPayloadBudget
	}
	return requested
}

// Run crawls req.URL to discover candidate injection points (see crawl.go),
// takes a plain baseline request, then probes each point (see probe.go) and
// tries the payload techniques that survive the probe, in budget order. When oob
// names a callback listener, it also stores blind payloads at every point and
// waits for their callbacks (see blind.go).
func Run(ctx context.Context, req Request, oob OOBConfig) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	// Parameter mining folds hidden names into req.Params before anything
	// reads them, so every candidate-building path below picks them up.
	if req.MineParams {
		req.Params = append(append([]string{}, req.Params...), paramminer.Names(ctx, seed, req.Headers, newClient(), req.Params)...)
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

	canary := newCanary()
	// The original single-payload modules run first, then the dalfox catalog
	// families. Each keeps its own module in the result.
	families := append(append([]payloadDef{}, payloadModules...), buildCatalogFamilies(canary)...)

	rep.Phase(fmt.Sprintf("Testing %d injection point(s) with %d payload technique(s)", len(points), len(families)))
	deps := runDeps{
		req:      req,
		points:   points,
		canary:   canary,
		families: families,
		budget:   payloadBudgetFor(req.PayloadBudget),
		sem:      make(chan struct{}, maxConcurrentRequests),
		rep:      rep,
	}
	outcomes := scanPoints(ctx, deps)

	// Every technique gets a module, even one that found nothing, so the
	// result shape does not depend on what the target reflected.
	modules := make([]ModuleResult, len(families))
	for i, fam := range families {
		modules[i] = ModuleResult{ID: fam.id, Name: fam.name, Severity: fam.severity, Findings: []Finding{}}
	}

	browserChecks := 0
	confirmed := map[string]bool{}
	var escapedFlat []escapedSighting
	for _, o := range outcomes {
		if o.finding != nil {
			// Browser replay happens here, after every point has been probed, so the
			// probing itself never waits on Chrome.
			pf := *o.finding
			if browserChecks < maxBrowserChecks && !req.SkipBrowser {
				pf = verifyPointFinding(ctx, pf, deps.canary)
				browserChecks++
			}
			confirmed[pf.key] = true
			modules[o.family].Findings = append(modules[o.family].Findings, pf.finding)
		}
		if o.escaped != nil {
			escapedFlat = append(escapedFlat, *o.escaped)
		}
	}
	modules = append(modules, aggregateEscapedModule(escapedFlat, confirmed))
	if blindUsable(oob) {
		modules = append(modules, ModuleResult{ID: "blind-xss", Name: "Blind XSS (out-of-band callback)", Severity: "high", Findings: runBlindXSSModule(ctx, deps, oob)})
	}
	modules = append(modules, ModuleResult{ID: "dom-xss-sink", Name: "DOM XSS sink (static heuristic)", Severity: "low", Findings: runDomSinkModule(cr.Pages)})

	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })

	return &Result{
		Baseline:     Baseline{URL: req.URL, StatusCode: baselineRes.StatusCode},
		Modules:      modules,
		PagesScanned: cr.PagesScanned,
		PointsTested: len(points),
	}, nil
}
