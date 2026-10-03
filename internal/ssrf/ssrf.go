// Package ssrf tests URL-accepting parameters (a webhook target, an
// "import from URL"/avatar-from-URL field, a URL-preview fetcher, ...) for
// server-side request forgery: the server itself making an outbound request
// to a URL the operator supplies, which lets an attacker reach hosts the
// server can see but the attacker otherwise can't -- cloud metadata
// services (the single highest-value SSRF target: AWS/GCP/Azure/DO/Alibaba
// all expose instance credentials over plain HTTP to whatever can reach
// 169.254.169.254), the rest of an internal network behind a firewall, or
// the server's own loopback-bound admin interfaces.
//
// This is deliberately narrower than internal/probescan's own path-
// traversal/SSTI checks: those fuzz *any* discovered parameter with
// filesystem/template payloads, where this package only targets parameters
// that are actually URL-shaped (see ssrfParams in checks.go) with payloads
// that are only meaningful when the server fetches them server-side.
//
// Three module categories, run concurrently:
//   - cloudMetadataModule: signature-matches the response body against known
//     cloud-metadata-service content -- high precision, since a false
//     positive here would need the target to coincidentally already contain
//     AWS/GCP/Azure-shaped JSON.
//   - internalNetworkModule: compares each internal-IP payload's response
//     against a same-parameter "blackhole" control (a non-routable address
//     the server can never reach) -- lower precision than signature
//     matching, so findings are phrased as "possible", not confirmed.
//   - oobCallbackModule: the actually-reliable confirmation for a *blind*
//     SSRF (one whose response gives no visible signal either way) --
//     points a payload at an internal/collaborator token and checks whether
//     the target's own infrastructure ever reached back out to it. See that
//     package's doc comment for how the listener itself works.
//
// Shaped like every other scanner in Aperture: a baseline plus a battery of
// check modules, each with fixed severity and findings present even when
// empty.
package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
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
	// Confidence is "confirmed" for an out-of-band callback, "likely" for an
	// internal-network difference that reproduced.
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
	// URL is the endpoint under test. Any query parameters it already
	// carries are tested too, same reasoning as openredirect.Request.URL.
	URL string `json:"url"`
	// Params are extra parameter names to test beyond ssrfParams and
	// whatever URL's own query string already carries.
	Params  []string          `json:"params,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// AutoDiscover, when true, crawls URL same-origin first (see
	// discoverParams in crawl.go -- same same-origin breadth-first pattern
	// as internal/csrf's own crawler). Every parameter name it turns up
	// (query keys on same-origin <a href> links, form action query keys, and
	// <input>/<select>/<textarea> field names) is folded into the candidate
	// set alongside ssrfParams/Params/URL's own query, same as before --
	// but on top of that, each distinct <form> it finds is tested a second
	// time directly against its own action endpoint and method (see
	// formTarget in crawl.go), since a form's fields are only meaningful
	// against the URL it actually submits to, not necessarily the page it
	// was discovered on. Off by default: a request with AutoDiscover unset
	// behaves exactly as before.
	AutoDiscover bool `json:"autoDiscover,omitempty"`
	// RecursionDepth is how many hops of same-origin <a href> links the
	// AutoDiscover crawl follows beyond URL itself -- 0 scans just that one
	// page. Ignored when AutoDiscover is false.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides crawlDefaultMaxPages (capped at crawlMaxPagesCap)
	// for the AutoDiscover crawl. Ignored when AutoDiscover is false.
	MaxPages int `json:"maxPages,omitempty"`
	// Progress, when set, receives this run's per-check progress -- one
	// check per (target, module, parameter) -- as it happens. Nil means
	// nobody is watching. See internal/scanprogress.
	Progress scanprogress.Reporter `json:"-"`
}

// OOBConfig is how Run reaches the shared out-of-band listener for
// oobCallbackModule -- see internal/collaborator. The zero value (nil
// Registry) just reports that module as unavailable rather than failing the
// whole scan, since the other two modules work regardless.
type OOBConfig struct {
	Registry *collaborator.Registry
	// CallbackBaseURL is this Aperture instance's own externally-reachable
	// scheme://host[:port] -- used to build each token's HTTP callback
	// address. See internal/api.handleCollaboratorNew for the identical
	// construction.
	CallbackBaseURL string
	// DNSDomain, when set, additionally tests a DNS-hostname-shaped payload
	// per token -- catches a blind SSRF that only leaks via DNS resolution
	// (egress firewall blocks the actual TCP connection, but the lookup
	// that precedes it still escapes).
	DNSDomain string
	// SharedToken/SharedProvider, when set, name a callback server the
	// operator picked from their own Callback picker (see
	// collaborator.Ref) instead of this module minting one throwaway token
	// per candidate parameter. Every parameter's payload then points at the
	// *same* token with a distinguishing Identifier (see
	// runOOBCallbackModule), so a human can watch the one listener in the
	// Collaborator tab while this runs. SharedProvider is "aperture"
	// (poll via Registry) or "webhooksite" (poll via
	// collaborator.PollWebhookSite, SharedToken then being that token's
	// UUID). SharedToken=="" preserves today's per-parameter auto-mint
	// behavior untouched.
	SharedToken    string
	SharedProvider string
}

type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

type Result struct {
	Baseline     Baseline       `json:"baseline"`
	Modules      []ModuleResult `json:"modules"`
	ParamsTested []string       `json:"paramsTested"`
}

// maxConcurrentRequests bounds how many requests this scanner has in
// flight at once, across every module combined. Without it, the three
// modules' own fan-outs (cloud-metadata and internal-network alone can each
// run into the hundreds, tested against every candidate parameter) would
// all fire at essentially the same instant -- needlessly aggressive against
// the target (a burst indistinguishable from a small denial-of-service),
// and self-defeating for internal-network's own control-vs-payload
// comparison: a target that can't keep up with that burst starts erroring
// out across the board, which reads as "every payload looks anomalous"
// rather than any real signal. See fetchWithParamThrottled in client.go.
const maxConcurrentRequests = 16

type runDeps struct {
	target *url.URL
	// method is the HTTP method every check in this runDeps sends --
	// GET for req.URL itself and for a discovered <form method="get">, POST
	// for a discovered <form method="post"> (see fetchParam in client.go for
	// how a POST target's param is sent in the body rather than the query
	// string).
	method string
	req    Request
	params []string
	sem    chan struct{}
	// key identifies this runDeps' target across every check it plans, so
	// check IDs stay unique when a discovered form adds a second target to
	// the same run. label is the human-readable suffix shown on a check's
	// square for a non-primary target ("POST /login"); empty for req.URL.
	key   string
	label string
	rep   scanprogress.Reporter
}

// checkConcurrency bounds how many parameter checks a single module runs at
// once. Each check fans its own payloads out concurrently, and the shared
// request semaphore is what actually caps total in-flight requests -- this
// bound just keeps only a handful of checks "testing" at a time, so the
// progress grid moves steadily instead of every square flipping orange at
// once and then green all together.
const checkConcurrency = 8

// check builds the progress entry for mod's check against param on this
// runDeps' target. The label names the parameter; a non-primary target adds
// its own method and path so two forms that share a field name stay
// distinguishable.
func (d runDeps) check(mod moduleMeta, param string) scanprogress.Check {
	label := param
	if d.label != "" {
		label = param + " on " + d.label
	}
	return scanprogress.Check{ID: d.key + "|" + mod.id + "|" + param, Label: label, Group: mod.name}
}

// runParamChecks runs check once per parameter in deps.params, with at most
// checkConcurrency checks in flight, bracketing each with progress Start/Done
// reports. A check's square only turns "testing" once it actually gets a slot,
// so anything still waiting for one correctly reads as queued. Findings from
// every check are merged into one slice.
func runParamChecks(deps runDeps, mod moduleMeta, check func(param string) []Finding) []Finding {
	var mu sync.Mutex
	var out []Finding
	var wg sync.WaitGroup
	slots := make(chan struct{}, checkConcurrency)
	for _, param := range deps.params {
		wg.Add(1)
		go func(param string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			id := deps.check(mod, param).ID
			deps.rep.Start(id)
			found := check(param)
			deps.rep.Done(id, len(found), nil)

			mu.Lock()
			out = append(out, found...)
			mu.Unlock()
		}(param)
	}
	wg.Wait()
	return out
}

// Run resolves req.URL, takes a plain baseline request, then runs every
// check module concurrently -- once against req.URL itself, and (when
// AutoDiscover turns up any <form>) once more per distinct form action/
// method, each with its own fields folded into that form's candidate set.
// Findings from every target are merged into one ModuleResult per module
// (cloud-metadata, internal-network, oob-callback), so the result still
// reads as "the three modules this scan ran", just against more than one
// target under the hood.
func Run(ctx context.Context, req Request, oob OOBConfig) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	target, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	client := newClient()
	rep.Phase("Sending baseline request")
	baselineRes := fetchParam(ctx, client, target, http.MethodGet, "aperture-ssrf-baseline", "1", req.Headers)
	if baselineRes.Err != nil {
		return nil, fmt.Errorf("ssrf: baseline request failed: %w", baselineRes.Err)
	}
	baseline := Baseline{URL: req.URL, StatusCode: baselineRes.StatusCode}

	extraParams := req.Params
	var formTargets []formTarget
	if req.AutoDiscover {
		rep.Phase("Crawling same-origin pages for parameters")
		discovered, forms := discoverParams(ctx, client, target, req.MaxPages, req.RecursionDepth, req.Headers)
		extraParams = append(append([]string{}, req.Params...), discovered...)
		formTargets = forms
	}
	params := candidateParams(target, extraParams)
	sem := make(chan struct{}, maxConcurrentRequests)

	merged := map[string]*ModuleResult{}
	var order []string
	merge := func(results []ModuleResult) {
		for _, r := range results {
			if existing, ok := merged[r.ID]; ok {
				existing.Findings = append(existing.Findings, r.Findings...)
				continue
			}
			cp := r
			merged[r.ID] = &cp
			order = append(order, r.ID)
		}
	}

	merge(runModulesForTarget(ctx, runDeps{target: target, method: http.MethodGet, req: req, params: params, sem: sem, key: http.MethodGet + " " + target.String(), rep: rep}, oob))

	paramsTested := append([]string{}, params...)
	for _, ft := range formTargets {
		ftParams := candidateParams(ft.url, ft.params)
		ftDeps := runDeps{
			target: ft.url, method: ft.method, req: req, params: ftParams, sem: sem,
			key: ft.method + " " + ft.url.String(), label: ft.method + " " + ft.url.Path, rep: rep,
		}
		merge(runModulesForTarget(ctx, ftDeps, oob))
		for _, p := range ftParams {
			paramsTested = append(paramsTested, fmt.Sprintf("%s %s?%s", ft.method, ft.url.String(), p))
		}
	}

	results := make([]ModuleResult, 0, len(order))
	for _, id := range order {
		results = append(results, *merged[id])
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return &Result{Baseline: baseline, Modules: results, ParamsTested: paramsTested}, nil
}

// runModulesForTarget runs every check module concurrently against one
// runDeps -- factored out of Run so AutoDiscover can call it once per
// discovered form target, in addition to the operator-supplied URL itself.
func runModulesForTarget(ctx context.Context, deps runDeps, oob OOBConfig) []ModuleResult {
	type moduleRun struct {
		meta moduleMeta
		run  func() []Finding
	}
	runs := []moduleRun{
		{cloudMetadataModule, func() []Finding { return runCloudMetadataModule(ctx, deps) }},
		{internalNetworkModule, func() []Finding { return runInternalNetworkModule(ctx, deps) }},
		{oobCallbackModule, func() []Finding { return runOOBCallbackModule(ctx, deps, oob) }},
	}

	// Plan every check this target is about to run before any of them
	// starts, so the whole grid appears at once rather than filling in as
	// modules happen to begin. The OOB module is left out when no listener
	// is configured: it only reports a single "not configured" finding and
	// never runs its per-parameter checks, so planning them would leave
	// squares stuck grey forever.
	var checks []scanprogress.Check
	for _, m := range runs {
		if m.meta.id == oobCallbackModule.id && !oobConfigured(oob) {
			continue
		}
		for _, p := range deps.params {
			checks = append(checks, deps.check(m.meta, p))
		}
	}
	deps.rep.Plan(checks...)
	deps.rep.Phase(fmt.Sprintf("Testing %d parameter(s)", len(deps.params)))

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
			results[i] = ModuleResult{ID: m.meta.id, Name: m.meta.name, Severity: m.meta.severity, Findings: findings}
		}(i, m)
	}
	wg.Wait()
	return results
}

// oobConfigured reports whether oob names a usable callback listener -- the
// same condition runOOBCallbackModule uses to decide between running its
// checks and returning its "not configured" finding.
func oobConfigured(oob OOBConfig) bool {
	return oob.SharedToken != "" || (oob.Registry != nil && oob.CallbackBaseURL != "")
}

// candidateParams unions ssrfParams, target's own existing query keys, and
// whatever the operator supplied in extra (which, when AutoDiscover is set,
// already includes whatever discoverParams turned up) -- same reasoning as
// openredirect.candidateParams.
func candidateParams(target *url.URL, extra []string) []string {
	set := map[string]bool{}
	for _, p := range ssrfParams {
		set[p] = true
	}
	for k := range target.Query() {
		set[k] = true
	}
	for _, p := range extra {
		if p != "" {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Confidence levels for a Finding.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
)
