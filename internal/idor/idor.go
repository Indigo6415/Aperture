// Package idor tests for insecure direct object references (CWE-639) and the
// broader broken-object-level-authorization class (OWASP API1): any place
// where the application takes an object reference from the client -- an id in
// the URL, body, cookie, or a header -- and returns the object without
// checking that the caller is allowed to see it.
//
// IDOR is fundamentally an authorization question, and authorization depends
// on an ownership model a scanner cannot know. So this scanner works the way
// the established tools (Burp's Autorize/AuthMatrix, Auth Analyzer) do, along
// two complementary lines, and it is honest about which line produced a
// finding:
//
//   - Differential testing across identities is the reliable one. When the
//     operator supplies a second credential, the cross-identity module replays
//     the request under that identity (and, when the request carries any auth,
//     under no identity at all). If the other identity receives the owner's
//     object -- and a deliberately non-existent reference under that same
//     identity does not -- access control is broken and the finding is
//     "confirmed".
//
//   - Reference enumeration is the single-identity fallback. The scanner finds
//     every point that carries something shaped like an object reference
//     (numeric id, UUID, Mongo ObjectId, hash/token, base64-wrapped id,
//     e-mail, slug) -- or whose name looks like one -- and mutates it: adjacent
//     ids, boundary and first-record values, parameter pollution, array and
//     NoSQL-operator wrapping, suffix and wildcard tricks, and encoding
//     bypasses. A mutation is reported only when it returns a distinct, real
//     object: a 2xx response that is neither the caller's own object (byte for
//     byte) nor the generic not-found page a negative control draws. Those are
//     "likely"/lead findings for an operator to confirm, since one identity
//     cannot prove the object belongs to someone else.
//
// Parameter mining (internal/paramminer) is genuinely useful here -- apps
// frequently honour an id parameter the UI never sends -- so it is offered as
// an option and folds any hidden names it finds into the query points.
//
// Shaped like the other scanners: a battery of check modules, each with a
// fixed severity and findings present even when empty, every probe captured so
// it can be replayed from "Send to Tester".
package idor

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Indigo6415/Aperture/internal/paramminer"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// maxConcurrentRequests bounds in-flight requests across every module and
// point, for the same reason as the other scanners: the module fan-out would
// otherwise fire hundreds of requests at once and read to the target as an
// outage rather than a scan.
const maxConcurrentRequests = 16

// Finding is one reported issue: a point whose reference could be mutated to
// reach another object (enumeration) or whose object another identity could
// read (cross-identity).
type Finding struct {
	Label      string           `json:"label"`
	Detail     string           `json:"detail,omitempty"`
	Evidence   string           `json:"evidence,omitempty"`
	Payload    string           `json:"payload,omitempty"`
	Method     string           `json:"method,omitempty"`
	StatusCode int              `json:"statusCode,omitempty"`
	Confidence string           `json:"confidence,omitempty"`
	Request    *CapturedRequest `json:"request,omitempty"`
}

// ModuleResult is one check module's outcome for this run.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Baseline is the seed request's unmodified response under the owner identity.
type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

// Result is one full run's outcome.
type Result struct {
	Baseline Baseline       `json:"baseline"`
	Modules  []ModuleResult `json:"modules"`
	// PointsTested is how many distinct reference-bearing points were found.
	PointsTested int `json:"pointsTested"`
	// TestsRun is the total number of probes sent across every module and
	// point -- the concrete count of individual tests this host received.
	TestsRun int64 `json:"testsRun"`
	// Identities names the alternate identities the cross-identity modules ran
	// under ("second credential", "no authentication"), or is empty when the
	// operator supplied none, so an empty cross-identity result is not read as
	// a clean one.
	Identities []string `json:"identities"`
}

// Request is one run's configuration.
type Request struct {
	// URL is the seed whose reference points are mutated. A POST endpoint is
	// tested through Body as well as its query string.
	URL string `json:"url"`
	// Method is GET or POST. Empty means POST when Body is set and GET otherwise.
	Method string `json:"method,omitempty"`
	// Body is the request body. JSON string/number leaves and form fields in it
	// that look like references become points.
	Body        string `json:"body,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	// Params are extra query-parameter names to try on URL, beyond the common
	// id-name list and whatever mining finds.
	Params []string `json:"params,omitempty"`
	// MineParams runs parameter mining against URL and folds hidden parameter
	// names into Params. Off by default.
	MineParams bool `json:"mineParams,omitempty"`
	// Headers is the owner identity: the credentials the legitimate user sends.
	Headers map[string]string `json:"headers,omitempty"`
	// AttackerHeaders is an optional second identity. When set, the
	// cross-identity module replays each request under it to prove or disprove
	// object-level authorization directly.
	AttackerHeaders map[string]string `json:"attackerHeaders,omitempty"`
	// Progress, when set, receives one check per (module, point).
	Progress scanprogress.Reporter `json:"-"`
}

// runDeps is what every module needs for one run.
type runDeps struct {
	client   *http.Client
	sem      chan struct{}
	baseline *sendResult
	points   []point
	rep      scanprogress.Reporter
	// tests counts every probe sent, so the result can report the total.
	tests *int64
}

// identity is an alternate set of credentials a request is replayed under by
// the cross-identity modules, carrying its own module metadata.
type identity struct {
	moduleID string
	module   string
	severity string
	// label names the identity in a finding's detail.
	label string
	// set are headers to apply (a second credential's cookie/headers).
	set map[string]string
	// strip removes the owner's auth headers before set is applied, so the
	// replay is a clean swap (or, with an empty set, fully unauthenticated).
	strip bool
}

// Run takes a baseline under the owner identity, discovers every
// reference-bearing point, then runs every module against them and returns one
// ModuleResult per module. It returns an error only when the seed cannot be
// parsed or its baseline cannot be fetched.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	client := newClient()

	// Parameter mining folds hidden names into req.Params before points are
	// built, so the query-point builder picks them up.
	if req.MineParams {
		req.Params = append(append([]string{}, req.Params...), paramminer.Names(ctx, seed, req.Headers, client, req.Params)...)
	}

	// Method defaults the same way the other body-aware scanners do.
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
		if req.Body != "" {
			method = http.MethodPost
		}
	}

	headers := cloneHeaders(req.Headers)
	contentType := req.ContentType
	if req.Body != "" {
		// Infer a content type from the body shape when none was given.
		if contentType == "" {
			trimmed := strings.TrimSpace(req.Body)
			if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				contentType = "application/json"
			} else {
				contentType = "application/x-www-form-urlencoded"
			}
		}
		if _, ok := headerValue(headers, "Content-Type"); !ok {
			headers["Content-Type"] = contentType
		}
	}

	base := requestSpec{Method: method, URL: seed.String(), Headers: headers, Body: req.Body}

	var tests int64
	// The baseline is the owner's own object; every verdict is relative to it.
	atomic.AddInt64(&tests, 1)
	baseline := send(ctx, client, nil, base)
	if baseline.Err != nil {
		return nil, fmt.Errorf("idor: baseline request failed: %w", baseline.Err)
	}

	ct, _ := headerValue(headers, "Content-Type")
	points := discover(seed, base, req.Body, ct, req.Params, baseline.SetCookies)

	deps := runDeps{
		client:   client,
		sem:      make(chan struct{}, maxConcurrentRequests),
		baseline: baseline,
		points:   points,
		rep:      rep,
		tests:    &tests,
	}

	identities := buildIdentities(headers, req.AttackerHeaders)

	rep.Phase(fmt.Sprintf("Testing %d reference point(s)", len(points)))

	// Every runner is one module plus the func that executes it, so value and
	// identity modules run through the same concurrent harness below.
	type runner struct {
		meta moduleMeta
		run  func() []Finding
	}
	var runners []runner
	for _, m := range valueModules {
		m := m
		runners = append(runners, runner{m.moduleMeta, func() []Finding { return runProbeModule(ctx, deps, m) }})
	}
	for _, id := range identities {
		id := id
		meta := moduleMeta{id: id.moduleID, name: id.module, severity: id.severity}
		runners = append(runners, runner{meta, func() []Finding { return runIdentityModule(ctx, deps, meta, id) }})
	}

	// Modules run concurrently; their probes share deps.sem, so the total
	// in-flight count stays bounded no matter how many modules there are.
	results := make([]ModuleResult, len(runners))
	var wg sync.WaitGroup
	for i, r := range runners {
		wg.Add(1)
		go func(i int, r runner) {
			defer wg.Done()
			results[i] = ModuleResult{ID: r.meta.id, Name: r.meta.name, Severity: r.meta.severity, Findings: r.run()}
		}(i, r)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	names := make([]string, 0, len(identities))
	for _, id := range identities {
		names = append(names, id.label)
	}

	return &Result{
		Baseline:     Baseline{URL: req.URL, StatusCode: baseline.StatusCode},
		Modules:      results,
		PointsTested: len(points),
		TestsRun:     atomic.LoadInt64(&tests),
		Identities:   names,
	}, nil
}

// buildIdentities derives the alternate identities to replay under: a second
// credential when the operator gave one, and an unauthenticated identity when
// the owner request carries any auth at all (replaying with no auth only means
// something if there was auth to drop).
func buildIdentities(ownerHeaders, attackerHeaders map[string]string) []identity {
	var out []identity
	// A second credential is the strongest test, so it is listed first and
	// rated critical.
	if len(attackerHeaders) > 0 {
		out = append(out, identity{
			moduleID: "cross-identity",
			module:   "Cross-identity access (2nd credential)",
			severity: "critical",
			label:    "a second credential",
			set:      cloneHeaders(attackerHeaders),
			strip:    true,
		})
	}
	// Dropping auth only tests anything when there was auth to drop.
	if hasAuth(ownerHeaders) {
		out = append(out, identity{
			moduleID: "unauth-replay",
			module:   "Unauthenticated access",
			severity: "high",
			label:    "no authentication",
			strip:    true,
		})
	}
	return out
}

// authHeaders are the request headers that carry a caller's identity, stripped
// when a replay must shed the owner's credentials.
var authHeaders = append([]string{"Cookie", "Authorization", "X-Api-Key", "X-Auth-Token", "X-Access-Token", "Proxy-Authorization"}, identityHeaders...)

// hasAuth reports whether headers carry any credential, so an unauthenticated
// replay is only scheduled when it would differ from the baseline.
func hasAuth(headers map[string]string) bool {
	// Any recognised auth header present means there is something to strip.
	for _, name := range authHeaders {
		if _, ok := headerValue(headers, name); ok {
			return true
		}
	}
	return false
}

// applyIdentity returns spec with the alternate identity applied: the owner's
// auth headers removed when the identity strips, then the identity's own
// headers set.
func applyIdentity(spec requestSpec, id identity) requestSpec {
	s := spec
	s.Headers = cloneHeaders(spec.Headers)
	if id.strip {
		// Remove every known auth header, case-insensitively, so no owner
		// credential leaks into the replay.
		for k := range s.Headers {
			for _, name := range authHeaders {
				if strings.EqualFold(k, name) {
					delete(s.Headers, k)
					break
				}
			}
		}
	}
	// The identity's own headers (a second credential) go on last.
	for k, v := range id.set {
		s.Headers[k] = v
	}
	return s
}

// probe sends one request and counts it toward the run's total.
func probe(ctx context.Context, deps runDeps, spec requestSpec) *sendResult {
	atomic.AddInt64(deps.tests, 1)
	return send(ctx, deps.client, deps.sem, spec)
}

// idxPoint pairs a point with its position, so concurrently-run points can
// store their findings back in point order.
type idxPoint struct {
	i  int
	pt point
}

// eachPoint runs fn once per point as its own progress check, with fn
// returning how many findings that point produced. It bounds nothing itself --
// probe's shared sem already caps concurrency -- so every point can report as
// running the moment it starts.
func eachPoint(deps runDeps, m moduleMeta, pts []point, fn func(i int, pt point) int) {
	items := make([]idxPoint, len(pts))
	// Pair each point with its index up front.
	for i, p := range pts {
		items[i] = idxPoint{i: i, pt: p}
	}
	scanprogress.Each(deps.rep, 0, items, func(it idxPoint) scanprogress.Check {
		return scanprogress.Check{ID: m.id + "|" + it.pt.id, Label: it.pt.label, Group: m.name}
	}, func(it idxPoint) (int, error) {
		return fn(it.i, it.pt), nil
	})
}
