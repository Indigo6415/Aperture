// Package sstiscan tests for Server-Side Template Injection: an endpoint
// that feeds operator-controlled input into a template engine (Jinja2,
// Twig, FreeMarker, Velocity, Smarty, ERB, Thymeleaf, Pug, ...) before
// rendering lets an attacker escape the data context and inject template
// *syntax* instead -- which the engine then evaluates, up to and including
// arbitrary remote code execution on the server (unlike XSS, the damage
// here is server-side, not confined to a victim's browser).
//
// Unlike internal/probescan's much smaller injections.go check (five
// payloads against the target's own query string plus up to ten scraped
// links), this scanner automatically builds its own candidate list of
// "every place user input may be displayed/used": it crawls the target
// same-origin (same breadth-first pattern as internal/csrf and
// internal/ssrf), then for every page it visits collects
//   - every query-string parameter already in play on that page's URL,
//   - every <input>/<select>/<textarea> field of every <form> it finds
//     (submitted via that form's own method, GET or POST, with every other
//     field left at a harmless default so the submission doesn't just 400),
//   - and, once per crawl (on the seed page), a fixed set of request
//     headers commonly echoed into an access-log viewer or debug page
//     (User-Agent, Referer, X-Forwarded-For, ...) -- a classic SSTI vector
//     entirely outside any visible form field.
//
// Four module categories, run concurrently against every discovered point:
//   - mathEvalModule: engine-tagged arithmetic payloads ({{1337*7331}},
//     ${1337*7331}, <%= 1337*7331 %>, ...) -- a response that contains the
//     evaluated result but not the literal payload text proves the engine
//     actually executed it, and which payload fired identifies the engine.
//     The multiplicands are deliberately large (product: 9801547) rather
//     than the classic 7*7=49, since 49 is common enough to already appear
//     in unrelated page content and cause a false positive. High precision.
//     Each probe is also sent from inside an existing template tag, with the
//     closing escape that tag needs (see engines.go, ported from tplmap's
//     per-engine context tables), so input that lands in {{ '...' }} or
//     ${ f(...) } is found as well as bare-text input.
//   - inBandRCEModule: the same engine-specific command payloads as the
//     OOB module, but the command only echoes a fresh random word back and
//     the word is checked in the response body (see inband.go). Proves
//     execution without any collaborator listener.
//   - errorSignatureModule: a single syntax-breaking polyglot, checked
//     against a table of engine-specific error/exception strings -- catches
//     a template engine that chokes on malformed syntax even when its
//     output is HTML-escaped or otherwise never reflects a clean evaluated
//     result.
//   - oobRCEModule: the actually-reliable confirmation for a genuinely
//     *blind* SSTI (no visible signal either way) -- sends well-documented,
//     engine-specific SSTI-to-RCE payloads that shell out to curl an
//     Aperture-controlled collaborator address, then checks whether the
//     target's own infrastructure ever reached back out. See
//     internal/collaborator's own doc comment for how the listener works,
//     and internal/ssrf's identical oobCallbackModule for the same pattern
//     applied to SSRF.
//
// Shaped like every other scanner in Aperture: a battery of check modules,
// each with fixed severity and findings present even when empty.
package sstiscan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/paramminer"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

type Finding struct {
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Confidence is "confirmed", "likely", or "heuristic".
	Confidence string `json:"confidence,omitempty"`
	// Callback is true when the target called back to Aperture's collaborator
	// listener, which proves the finding out-of-band. The frontend shows a
	// CALLBACK tag for it.
	Callback bool `json:"callback,omitempty"`
	// Request is the exact request this finding's check sent (see
	// CapturedRequest in client.go) -- lets the frontend's "Send to Tester"
	// action replay precisely what triggered the finding.
	Request *CapturedRequest `json:"request,omitempty"`
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
	// reasoning as ssrf.Request.Params/openredirect.Request.Params.
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
	// Progress, when set, receives one check per (module, injection point).
	Progress scanprogress.Reporter `json:"-"`
}

// OOBConfig is how Run reaches the shared out-of-band listener for
// oobRCEModule -- see internal/collaborator. The zero value (nil Registry)
// just reports that module as unavailable rather than failing the whole
// scan, since the other two modules work regardless.
type OOBConfig struct {
	Registry *collaborator.Registry
	// CallbackBaseURL is this Aperture instance's own externally-reachable
	// scheme://host[:port] -- used to build each token's HTTP callback
	// address. See internal/api.handleCollaboratorNew for the identical
	// construction.
	CallbackBaseURL string
	// SharedToken/SharedProvider, when set, name a callback server the
	// operator picked from their own Callback picker (see
	// collaborator.Ref) instead of this module minting one throwaway token
	// per candidate injection point. Every point's payloads then point at
	// the *same* token with a distinguishing Identifier, so a human can
	// watch the one listener in the Collaborator tab while this runs.
	// SharedProvider is "aperture" (poll via Registry) or "webhooksite"
	// (poll via collaborator.PollWebhookSite, SharedToken then being that
	// token's UUID). SharedToken=="" mints a fresh token per point instead.
	SharedToken    string
	SharedProvider string
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

// maxConcurrentRequests bounds how many requests this scanner has in
// flight at once, across every module combined -- same reasoning as
// ssrf.maxConcurrentRequests: three modules, each firing several payloads
// against potentially dozens of discovered points, would otherwise all fire
// at essentially the same instant.
const maxConcurrentRequests = 16

type runDeps struct {
	req    Request
	points []injectionPoint
	sem    chan struct{}
	// baseline is the seed page as served, before any payload. Checks use it to
	// ignore text the page already shows.
	baseline string
	// rep receives one progress check per (module, injection point).
	rep scanprogress.Reporter
}

// Run crawls req.URL to discover candidate injection points (see crawl.go),
// takes a plain baseline request, then runs every check module concurrently
// against every point.
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
	baselineRes := fetchPlain(ctx, client, seed.String(), req.Headers)
	if baselineRes.Err != nil {
		return nil, fmt.Errorf("sstiscan: baseline request failed: %w", baselineRes.Err)
	}

	cr, err := crawl(ctx, client, seed, req)
	if err != nil {
		return nil, fmt.Errorf("sstiscan: crawl failed: %w", err)
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

	rep.Phase(fmt.Sprintf("Testing %d injection point(s)", len(points)))
	deps := runDeps{req: req, points: points, sem: make(chan struct{}, maxConcurrentRequests), baseline: baselineRes.Body, rep: rep}

	type moduleRun struct {
		id, name, severity string
		run                func() []Finding
	}
	runs := []moduleRun{
		{mathEvalModule.id, mathEvalModule.name, mathEvalModule.severity, func() []Finding { return runMathEvalModule(ctx, deps) }},
		{errorSignatureModule.id, errorSignatureModule.name, errorSignatureModule.severity, func() []Finding { return runErrorSignatureModule(ctx, deps) }},
		{oobRCEModule.id, oobRCEModule.name, oobRCEModule.severity, func() []Finding { return runOOBRCEModule(ctx, deps, oob) }},
		{inBandRCEModule.id, inBandRCEModule.name, inBandRCEModule.severity, func() []Finding { return runInBandRCEModule(ctx, deps) }},
	}

	results := make([]ModuleResult, len(runs))
	var wg sync.WaitGroup
	for i, m := range runs {
		wg.Add(1)
		go func(i int, m moduleRun) {
			defer wg.Done()
			findings := m.run()
			if findings == nil {
				findings = []Finding{}
			}
			results[i] = ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: findings}
		}(i, m)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return &Result{
		Baseline:     Baseline{URL: req.URL, StatusCode: baselineRes.StatusCode},
		Modules:      results,
		PagesScanned: cr.PagesScanned,
		PointsTested: len(points),
	}, nil
}

// Confidence levels for a Finding. "confirmed" means the scanner proved the
// behavior (an evaluated result the page did not show otherwise, or a callback
// from the target); "likely" means a signature matched without that proof.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
)
