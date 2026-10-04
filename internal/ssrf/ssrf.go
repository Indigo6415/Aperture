// Package ssrf tests URL-accepting parameters (a webhook target, an
// "import from URL"/avatar-from-URL field, a URL-preview fetcher, ...) for
// server-side request forgery: the server itself making an outbound request
// to a URL the operator supplies, which lets an attacker reach hosts the
// server can see but the attacker otherwise can't -- cloud metadata
// services (the single highest-value SSRF target: AWS/GCP/Azure/DO/Alibaba/
// Oracle/OpenStack all expose instance credentials over plain HTTP to
// whatever can reach 169.254.169.254), the rest of an internal network behind
// a firewall, the local filesystem through a file:// URL, or the server's own
// loopback-bound admin interfaces.
//
// This is deliberately narrower than internal/probescan's own path-
// traversal/SSTI checks: those fuzz *any* discovered parameter with
// filesystem/template payloads, where this package only targets parameters
// that are actually URL-shaped (see ssrfParams in checks.go) with payloads
// that are only meaningful when the server fetches them server-side.
//
// Modules, run concurrently against every injection point:
//   - cloudMetadataModule: signature-matches the response body against known
//     cloud-metadata-service content. A signature counts only when the same
//     text is absent from the point's own non-routable controls and from the
//     normal response, so a page that merely documents metadata keys is not
//     reported. Includes same-origin redirect bounces, for filters that
//     allow the target's own host and then follow a redirect.
//   - internalNetworkModule: compares each internal-address payload's
//     response against non-routable controls, after scrubbing every echo of
//     the scanner's own payloads from both sides. It also runs against request
//     headers (Host, X-Forwarded-Host, ...), reported at heuristic confidence.
//     Findings are phrased as "possible", not confirmed.
//   - fileSchemeModule: reads a file:// URL and matches a known file's
//     content (/etc/passwd, win.ini), with the same control gating as the
//     cloud module.
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
	"github.com/Indigo6415/Aperture/internal/paramminer"
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
	// Confidence is "confirmed" for an out-of-band callback or a metadata/file
	// body that only the server could have produced, "likely" for an
	// internal-network difference that reproduced in a parameter, and
	// "heuristic" for a difference seen only through a request header.
	Confidence string `json:"confidence,omitempty"`
	// Callback is true when the target called back to Aperture's collaborator
	// listener, which proves the finding out-of-band. The frontend shows a
	// CALLBACK tag for it.
	Callback bool `json:"callback,omitempty"`
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
	// MineParams, when true, runs parameter mining (see internal/paramminer)
	// against URL before the candidate set is built. Any undocumented
	// parameter whose value changes the response, or is reflected back, is
	// folded into the candidates, so hidden fetch parameters are tested too.
	// Off by default.
	MineParams bool `json:"mineParams,omitempty"`
	// NoKnownEndpoints turns off the product-specific endpoint probes (see
	// knownEndpoints in endpoints.go). They are on by default: each one is
	// gated by an existence check, so a product that is not installed costs
	// one request.
	NoKnownEndpoints bool `json:"noKnownEndpoints,omitempty"`
	// RecursionDepth is how many hops of same-origin <a href> links the
	// AutoDiscover crawl follows beyond URL itself -- 0 scans just that one
	// page. Ignored when AutoDiscover is false.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides crawlDefaultMaxPages (capped at crawlMaxPagesCap)
	// for the AutoDiscover crawl. Ignored when AutoDiscover is false.
	MaxPages int `json:"maxPages,omitempty"`
	// Progress, when set, receives this run's per-check progress -- one
	// check per (target, module, injection point) -- as it happens. Nil means
	// nobody is watching. See internal/scanprogress.
	Progress scanprogress.Reporter `json:"-"`
}

// OOBConfig is how Run reaches the shared out-of-band listener for
// oobCallbackModule -- see internal/collaborator. The zero value (nil
// Registry) just reports that module as unavailable rather than failing the
// whole scan, since the other modules work regardless.
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
// flight at once, across every module combined. Without it, the modules'
// own fan-outs (cloud-metadata and internal-network alone can each run into
// the hundreds, tested against every candidate parameter) would all fire at
// essentially the same instant -- needlessly aggressive against the target
// (a burst indistinguishable from a small denial-of-service), and
// self-defeating for internal-network's own control-vs-payload comparison: a
// target that can't keep up with that burst starts erroring out across the
// board, which reads as "every payload looks anomalous" rather than any real
// signal. See fetchParamThrottled in client.go.
const maxConcurrentRequests = 16

// checkConcurrency bounds how many points a single module checks at once.
// Each check fans its own payloads out concurrently, and the shared request
// semaphore is what actually caps total in-flight requests -- this bound just
// keeps only a handful of checks "testing" at a time, so the progress grid
// moves steadily instead of every square flipping orange at once and then
// green all together.
const checkConcurrency = 8

// probePoint is one place a payload is written: a named request parameter
// (query string for GET, form field for POST) or a request header on a plain
// GET of the target. Header points only run in the modules that set headers
// (see moduleMeta).
type probePoint struct {
	name   string
	header bool
}

// headerProbeNames are the request headers the internal-network module injects
// a payload into. Each one is read by a common class of proxy or virtual-host
// router that builds its upstream URL or chooses its backend from a
// client-supplied host name, so the same loopback spellings used for
// parameters are tried here too.
var headerProbeNames = []string{"Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server"}

// paramPoints wraps names as parameter points.
func paramPoints(names []string) []probePoint {
	out := make([]probePoint, 0, len(names))
	for _, n := range names {
		out = append(out, probePoint{name: n})
	}
	return out
}

// headerPoints returns one header point per entry in headerProbeNames.
func headerPoints() []probePoint {
	out := make([]probePoint, 0, len(headerProbeNames))
	for _, h := range headerProbeNames {
		out = append(out, probePoint{name: h, header: true})
	}
	return out
}

// runDeps is what a module needs to test one target: the target and method,
// the injection points, the shared request semaphore, the client, and the
// normal responses used for control comparison.
type runDeps struct {
	target *url.URL
	// method is the HTTP method every parameter check in this runDeps sends
	// -- GET for req.URL itself and for a discovered <form method="get">,
	// POST for a discovered <form method="post"> (see fetchParam in client.go
	// for how a POST target's param is sent in the body rather than the query
	// string). Header points always use GET.
	method string
	req    Request
	points []probePoint
	sem    chan struct{}
	client *http.Client
	// key identifies this runDeps' target across every check it plans, so
	// check IDs stay unique when a discovered form adds a second target to
	// the same run. label is the human-readable suffix shown on a check's
	// square for a non-primary target ("POST /login"); empty for req.URL.
	key   string
	label string
	rep   scanprogress.Reporter
	// baseline is the body of the plain request to the primary target, used
	// to ignore text the page shows on every request. Empty for a form target,
	// since the primary baseline is a different endpoint.
	baseline string
	// echoes is every spelling of the scanner's own payload values that a
	// server might echo back (see echoesFor). Scrubbed from every body before
	// it is compared, so an echo of the payload is not mistaken for a response
	// from the internal address it names.
	echoes []string
	// controls holds each point's non-routable control responses, fetched once
	// and shared by every module that compares against them.
	controls *controlCache
}

// newRunDeps builds the runDeps for one target. Callers set label afterward
// when the target is a form action rather than req.URL itself.
func newRunDeps(target *url.URL, method string, req Request, points []probePoint, sem chan struct{}, rep scanprogress.Reporter, baseline string, client *http.Client) runDeps {
	return runDeps{
		target:   target,
		method:   method,
		req:      req,
		points:   points,
		sem:      sem,
		client:   client,
		key:      method + " " + target.String(),
		rep:      rep,
		baseline: baseline,
		echoes:   echoesFor(target),
		controls: newControlCache(),
	}
}

// pointsFor returns the points mod runs against: every point for a module
// that sets headers, and only parameter points otherwise.
func (d runDeps) pointsFor(mod moduleMeta) []probePoint {
	var out []probePoint
	for _, pt := range d.points {
		if pt.header && !mod.headers {
			continue
		}
		out = append(out, pt)
	}
	return out
}

// check builds the progress entry for mod's check against pt on this runDeps'
// target. The label names the point; a non-primary target adds its own method
// and path so two forms that share a field name stay distinguishable.
func (d runDeps) check(mod moduleMeta, pt probePoint) scanprogress.Check {
	label := pt.name
	idPart := "p:" + pt.name
	if pt.header {
		label = "header " + pt.name
		idPart = "h:" + pt.name
	}
	if d.label != "" {
		label = label + " on " + d.label
	}
	return scanprogress.Check{ID: d.key + "|" + mod.id + "|" + idPart, Label: label, Group: mod.name}
}

// controlCache holds, per injection point, the non-routable control responses
// for that point. Each point's controls are fetched exactly once, even when
// several modules ask for them at the same moment.
type controlCache struct {
	mu sync.Mutex
	m  map[probePoint]*controlEntry
}

// controlEntry is one point's cached controls, filled by its once.
type controlEntry struct {
	once sync.Once
	res  []*ssrfResult
}

// newControlCache returns an empty cache.
func newControlCache() *controlCache {
	return &controlCache{m: map[probePoint]*controlEntry{}}
}

// get returns the controls for pt, calling fetch only the first time pt is
// asked for. Concurrent callers for the same point all wait for that one fetch.
func (c *controlCache) get(pt probePoint, fetch func() []*ssrfResult) []*ssrfResult {
	c.mu.Lock()
	e, ok := c.m[pt]
	if !ok {
		e = &controlEntry{}
		c.m[pt] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { e.res = fetch() })
	return e.res
}

// controlsFor returns pt's scrubbed control responses, fetching them on first
// use. Each control is a non-routable address the server can never reach (see
// controlURLs), so a difference from it signals that the server acted on the
// value.
func (d runDeps) controlsFor(ctx context.Context, pt probePoint) []*ssrfResult {
	return d.controls.get(pt, func() []*ssrfResult {
		out := make([]*ssrfResult, len(controlURLs))
		var wg sync.WaitGroup
		for i, cu := range controlURLs {
			wg.Add(1)
			// Each control fills its own slot, so no lock is needed.
			go func(i int, cu string) {
				defer wg.Done()
				out[i] = scrubResult(fetchPointThrottled(ctx, d, pt, cu), d.echoes)
			}(i, cu)
		}
		wg.Wait()
		return out
	})
}

// Run resolves req.URL, takes a plain baseline request, then runs every check
// module concurrently -- once against req.URL itself (with the header points
// as well), and (when AutoDiscover turns up any <form>) once more per distinct
// form action/method, each with its own fields folded into that form's
// candidate set. Findings from every target are merged into one ModuleResult
// per module (cloud-metadata, internal-network, file-scheme, oob-callback), so
// the result still reads as "the modules this scan ran", just against more than
// one target under the hood.
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
	if req.MineParams {
		rep.Phase("Mining hidden parameters")
		mined, _ := paramminer.Mine(ctx, paramminer.Options{
			URL:     target,
			Headers: req.Headers,
			Client:  client,
			Known:   extraParams,
		})
		extraParams = append(append([]string{}, extraParams...), mined.Names...)
	}
	if !req.NoKnownEndpoints {
		rep.Phase("Checking known product endpoints")
		origin := &url.URL{Scheme: target.Scheme, Host: target.Host}
		formTargets = append(formTargets, endpointTargets(ctx, client, origin, req.Headers)...)
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

	// The primary target also gets the header points. A form target gets only
	// its own fields, since those are the only input its handler reads.
	primaryPoints := append(paramPoints(params), headerPoints()...)
	primary := newRunDeps(target, http.MethodGet, req, primaryPoints, sem, rep, baselineRes.Body, client)
	merge(runModulesForTarget(ctx, primary, oob))

	paramsTested := append([]string{}, params...)
	for _, h := range headerProbeNames {
		paramsTested = append(paramsTested, "header:"+h)
	}
	for _, ft := range formTargets {
		// A form target tests only its own fields. A known endpoint is the
		// same: its single parameter is the whole candidate set, so the
		// product's full ssrfParams list is not fired at it.
		ftParams := ft.params
		if ft.name == "" {
			ftParams = candidateParams(ft.url, ft.params)
		}
		ftDeps := newRunDeps(ft.url, ft.method, req, paramPoints(ftParams), sem, rep, "", client)
		ftDeps.label = ft.method + " " + ft.url.Path
		if ft.name != "" {
			ftDeps.label = ft.name + " (" + ft.url.Path + ")"
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
		{fileSchemeModule, func() []Finding { return runFileSchemeModule(ctx, deps) }},
		{protocolModule, func() []Finding { return runProtocolModule(ctx, deps) }},
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
		for _, pt := range deps.pointsFor(m.meta) {
			checks = append(checks, deps.check(m.meta, pt))
		}
	}
	deps.rep.Plan(checks...)
	deps.rep.Phase(fmt.Sprintf("Testing %d injection point(s)", len(deps.points)))

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
	ConfidenceHeuristic = "heuristic"
)
