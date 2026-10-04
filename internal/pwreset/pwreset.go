// Package pwreset scans a "forgot password" flow for the class of issues
// covered in password-reset security writeups (see checks.go's per-module
// doc comments for exactly what each one inspects and why): user
// enumeration on the request-reset endpoint, Host-header-driven reset-link
// poisoning, a reset token/link leaking directly into the endpoint's own
// HTTP response, missing rate limiting on repeated requests, and -- when a
// separate form page is given -- a missing CSRF token or weak cookie/
// caching attributes on that form.
//
// Every check submits the exact request-reset request the operator points
// it at -- never a live token guess or an automated account takeover -- and
// groups its findings the same way internal/probescan does (see its
// module.go): a set of check "modules", each carrying its own fixed
// severity and a list of findings, present even when empty so the caller
// can tell "checked, found nothing" from "never ran".
package pwreset

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"net/http"
	"net/url"
	"sort"
	"sync"
)

// Finding is one thing a check module found. Shaped like probescan.Finding
// (Label/Detail for the always-visible summary, Evidence/Method/StatusCode
// for the "how was this found" detail a finding expands to) but kept as its
// own type rather than importing that package -- the two scanners' findings
// aren't otherwise related, and bypass403 makes the same call for its own
// Attempt type.
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
	// Confidence is "confirmed", "likely", or "heuristic" (see checks.go).
	Confidence string `json:"confidence,omitempty"`
}

// ModuleResult is one check category's outcome -- always present in
// Result.Modules (possibly with zero findings) so the UI can render
// "checked, nothing found" instead of a check having silently not run.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"` // info | low | medium | high | critical
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration: the request-reset endpoint plus
// enough about its request shape (method, body encoding, the field the
// identifier goes in) to actually submit it, and the optional inputs that
// unlock the checks that need more than just the endpoint itself.
type Request struct {
	// URL is the request-reset endpoint itself -- where "send me a reset
	// link/code" gets submitted. Must include a scheme.
	URL string `json:"url"`
	// Method is "POST" or "GET"; defaults to POST.
	Method string `json:"method,omitempty"`
	// ContentType is "form" or "json"; defaults to "form".
	ContentType string `json:"contentType,omitempty"`
	// IdentifierField is the request field the account identifier (email or
	// username) goes in; defaults to "email".
	IdentifierField string `json:"identifierField,omitempty"`
	// KnownIdentifier, when set, is an identifier the operator already knows
	// is a real, registered account -- unlocks the user-enumeration module
	// (comparing its response against an identifier that doesn't exist) and
	// is preferred over UnknownIdentifier as the request the leakage module
	// scans, since it's the one more likely to trigger the real "success"
	// flow. Never used for anything but those two checks.
	KnownIdentifier string `json:"knownIdentifier,omitempty"`
	// UnknownIdentifier is an identifier that does *not* exist -- generated
	// automatically when left blank (see unknownIdentifier below).
	UnknownIdentifier string `json:"unknownIdentifier,omitempty"`
	// ExtraFields are additional static fields sent with every request this
	// run makes -- a CSRF token pulled from the form page, a required
	// "action" field, an empty CAPTCHA field, and the like.
	ExtraFields map[string]string `json:"extraFields,omitempty"`
	// FormURL, when set, is the page that renders the reset-request form
	// itself (as opposed to URL, which is where it submits to) -- fetched
	// once to run the CSRF/cookie/caching checks. Left blank, those checks
	// are skipped entirely rather than reported as "nothing found".
	FormURL string            `json:"formUrl,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// Progress, when set, receives one check per module (or per attempt). Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// Baseline is the unmodified request-reset request's own result -- the
// request every check module's own requests are variations of.
type Baseline struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	StatusCode    int    `json:"statusCode"`
	ContentLength int    `json:"contentLength"`
}

// Result is one run's full output.
type Result struct {
	Baseline Baseline       `json:"baseline"`
	Modules  []ModuleResult `json:"modules"`
}

// moduleDef is one check category. run receives the shared client, the
// resolved target, the run's own Request (for whichever of its optional
// fields that module needs), the identifier value the baseline request used,
// and the baseline response itself -- reused rather than re-fetched by
// whichever module can make do with it (leakage, when no KnownIdentifier is
// given).
type moduleDef struct {
	id, name, severity string
	run                func(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, baseline *httpResult) []Finding
}

// registeredModules returns every check this run should actually perform --
// unlike probescan's fixed list, enumeration and the form checks only fire
// when the operator supplied the input they need (a known-good identifier,
// a separate form page), since running them without it would just be an
// extra unknown-vs-unknown comparison or a request to nothing.
func registeredModules(req Request) []moduleDef {
	mods := []moduleDef{hostHeaderModule, leakageModule, rateLimitModule}
	if req.KnownIdentifier != "" {
		mods = append(mods, enumerationModule)
	}
	if req.FormURL != "" {
		mods = append(mods, csrfModule, formSecurityModule)
	}
	return mods
}

// Run resolves req.URL, takes a baseline request-reset submission against
// it, then runs every applicable check module (see registeredModules)
// concurrently against the same endpoint.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	target, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	client := newClient()
	unknownID := req.unknownIdentifier()

	baselineFields := buildFields(req.identifierField(), unknownID, req.ExtraFields)
	baselineRes, err := submit(ctx, client, target, req.method(), req.contentType(), baselineFields, req.Headers, "")
	if err != nil {
		return nil, fmt.Errorf("pwreset: baseline request failed: %w", err)
	}
	baseline := Baseline{
		URL:           req.URL,
		Method:        req.method(),
		StatusCode:    baselineRes.StatusCode,
		ContentLength: len(baselineRes.Body),
	}

	mods := registeredModules(req)
	checks := make([]scanprogress.Check, len(mods))
	for i, m := range mods {
		checks[i] = scanprogress.Check{ID: m.id, Label: m.name}
	}
	rep.Plan(checks...)

	runModule := func(m moduleDef) ModuleResult {
		rep.Start(m.id)
		findings := m.run(ctx, client, target, req, unknownID, baselineRes)
		rep.Done(m.id, len(findings), nil)
		if findings == nil {
			// A nil slice would otherwise serialize to JSON `null` instead
			// of `[]`, which the frontend treats as an always-present array.
			findings = []Finding{}
		}
		return ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: findings}
	}

	var results []ModuleResult
	var concurrentDefs []moduleDef
	for _, m := range mods {
		// The enumeration module's own comparison depends on the endpoint
		// behaving consistently across its known-vs-unknown samples -- run
		// it alone, before the burst-style checks below start hammering the
		// same endpoint concurrently, so a shared rate limiter tripped by a
		// sibling module (rate-limit's own burst, or all five host-header
		// attempts firing at once) doesn't get mistaken for a real
		// per-identifier difference.
		if m.id == "enumeration" {
			results = append(results, runModule(m))
			continue
		}
		concurrentDefs = append(concurrentDefs, m)
	}

	concurrentResults := make([]ModuleResult, len(concurrentDefs))
	var wg sync.WaitGroup
	// Every remaining module fires its own independent batch of requests
	// against the same endpoint, so they all run concurrently -- a full
	// scan takes roughly as long as its slowest module, not the sum of
	// every module.
	for i, m := range concurrentDefs {
		wg.Add(1)
		go func(i int, m moduleDef) {
			defer wg.Done()
			concurrentResults[i] = runModule(m)
		}(i, m)
	}
	wg.Wait()
	results = append(results, concurrentResults...)

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	return &Result{Baseline: baseline, Modules: results}, nil
}
