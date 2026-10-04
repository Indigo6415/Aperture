// Package csrf sweeps a site (via the same same-origin crawl pattern as
// internal/breach) for missing Cross-Site Request Forgery protection --
// internal/pwreset already checks one specific form (the password-reset
// request), this is the app-wide version: every state-changing form
// (POST/PUT/DELETE/PATCH, the last three usually discovered via a Rails/
// Laravel-style "_method" hidden field, since plain HTML forms only submit
// GET/POST natively) the crawl turns up gets checked for a CSRF-token-
// looking hidden field or page-level meta tag, and every cookie the site
// sets anywhere gets checked for the SameSite attribute that's the other
// half of CSRF defense (SameSite=Lax/Strict means the browser simply won't
// attach the cookie to a cross-site request in the first place, token or
// not).
//
// The crawl-derived modules above never submit a discovered form -- only
// fetch pages (GET) and read their markup/headers. Actually submitting an
// arbitrary crawled POST/PUT/DELETE form would mean performing whatever real
// side effect that form triggers (deleting something, changing a password,
// placing an order) against a target the operator may not want mutated by
// a scan; that's a materially different risk than pwreset's own request-
// reset submission, which is specifically the one action that flow is
// safe and idempotent to repeat.
//
// contentTypeBypassModule (checks.go) is the one exception: given an
// operator-supplied endpoint/method/body (Request.APIURL/APIMethod/APIBody),
// it actively replays that exact request under two different Content-Type
// headers to check whether a JSON API's Content-Type requirement is an
// actual server-side check or just an unenforced assumption -- the same
// assumption Chrome's sendBeacon() broke for years by letting a page send a
// non-CORS-safelisted Content-Type without a preflight (crbug.com/490015 /
// issues.chromium.org/40082106). This only ever runs against the one
// endpoint the operator explicitly names, never anything discovered by the
// crawl, for the same reason the form modules above don't submit forms.
//
// Shaped like every other scanner in Aperture: a battery of check modules,
// each with fixed severity and findings present even when empty.
package csrf

import (
	"context"
	"sort"
	"strings"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

type Finding struct {
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	// Request is the page this finding was found on, as a plain GET --
	// unlike corsscan/ssrf/openredirect's checks, these modules are static
	// analysis over an already-crawled page/cookie rather than a check that
	// fires its own distinguishing request, so there's no captured
	// method/headers/body to offer beyond "go look at this page" -- still
	// enough for "Send to Tester" (see web/src/components/
	// ScanModuleResults.tsx) to load it directly instead of the operator
	// copying the URL out of Label/Evidence by hand.
	Request *CapturedRequest `json:"request,omitempty"`
	// Confidence is "confirmed" (read from a response), "likely", or "heuristic"
	// (matched statically). Cookie findings are read from Set-Cookie headers.
	Confidence string `json:"confidence,omitempty"`
}

// CapturedRequest is the request a finding's page/cookie was seen on --
// same shape as corsscan.CapturedRequest; kept as its own type per-package,
// matching how Finding/ModuleResult are already duplicated across these
// scanners (see corsscan.Finding's doc comment). Headers/Body are only ever
// populated by contentTypeBypassModule, the one check here that actually
// issues a request of its own rather than reading back an already-crawled
// page/cookie -- see that module's doc comment.
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration -- same shape/reasoning as
// internal/breach.CrawlRequest.
type Request struct {
	URL string `json:"url"`
	// RecursionDepth is how many hops of same-origin <a href> links to
	// follow beyond the seed page -- 0 scans just the seed page.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides crawlDefaultMaxPages, capped at crawlMaxPagesCap.
	MaxPages int               `json:"maxPages,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	// Progress, when set, receives this run's per-check progress as it
	// happens (one check per POST form, per cookie, and the optional API
	// replay). Nil means nobody is watching. See internal/scanprogress.
	Progress scanprogress.Reporter `json:"-"`

	// APIURL, APIMethod, and APIBody optionally point this scan at one
	// specific state-changing API endpoint to actively replay, probing for
	// the Content-Type-based CSRF bypass contentTypeBypassModule checks for
	// -- entirely separate from the passive crawl above, since there's no
	// safe way to discover a JSON API endpoint (or its expected body) by
	// crawling. Skipped whenever APIURL/APIBody is blank. APIMethod
	// defaults to POST.
	APIURL    string `json:"apiUrl,omitempty"`
	APIMethod string `json:"apiMethod,omitempty"`
	APIBody   string `json:"apiBody,omitempty"`

	// TokenProbe optionally names one form endpoint whose anti-CSRF token
	// enforcement is tested by replaying it with the token missing, empty, or
	// wrong. Like APIURL it is operator-named only, never crawled. Nil skips the
	// check.
	TokenProbe *TokenProbe `json:"tokenProbe,omitempty"`
}

// TokenProbe describes one form submission whose token enforcement is tested.
// Body is the complete form-encoded body a legitimate submission sends, token
// field included. Field names the token field inside it. The check replays
// Body as is to establish a baseline, then with that field removed, emptied,
// and set to a wrong value. It makes state-changing requests, so the operator
// must name the endpoint.
type TokenProbe struct {
	URL    string `json:"url"`
	Method string `json:"method,omitempty"` // defaults to POST
	Body   string `json:"body"`
	Field  string `json:"field"`
}

type Result struct {
	PagesScanned []string       `json:"pagesScanned"`
	FormsFound   int            `json:"formsFound"`
	Modules      []ModuleResult `json:"modules"`
}

// Run crawls req.URL (see crawl) and builds every check module's findings
// from that single pass -- unlike Aperture's request-driven scanners, every
// module here is pure post-processing of data the crawl already gathered,
// so there's no further network I/O (and so no need to run them
// concurrently) once the crawl itself finishes.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	rep.Phase("Crawling pages")
	cr, err := crawl(ctx, newClient(), seed, req)
	if err != nil {
		return nil, err
	}

	rep.Phase("Checking forms and cookies")
	modules := []ModuleResult{
		formCSRFModule(cr, rep),
		cookieSameSiteModule(cr, rep),
	}
	if strings.TrimSpace(req.APIURL) != "" {
		apiID := "content-type-csrf-bypass|" + req.APIURL
		rep.Plan(scanprogress.Check{ID: apiID, Label: req.APIURL, Group: "Content-Type-based CSRF bypass"})
		rep.Start(apiID)
		mod := contentTypeBypassModule(ctx, req)
		rep.Done(apiID, len(mod.Findings), nil)
		modules = append(modules, mod)
	}
	if req.TokenProbe != nil && strings.TrimSpace(req.TokenProbe.URL) != "" {
		tokID := "token-validation|" + req.TokenProbe.URL
		rep.Plan(scanprogress.Check{ID: tokID, Label: req.TokenProbe.URL, Group: "CSRF token validation"})
		rep.Start(tokID)
		mod := tokenValidationModule(ctx, req.TokenProbe, req.Headers)
		rep.Done(tokID, len(mod.Findings), nil)
		modules = append(modules, mod)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })

	return &Result{PagesScanned: cr.PagesScanned, FormsFound: len(cr.Forms), Modules: modules}, nil
}

// Confidence levels for a Finding, shared with the other scanners.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceHeuristic = "heuristic"
)
