// Package graphqlenum enumerates and probes a GraphQL endpoint for the
// class of issues covered in the standard GraphQL pentesting references --
// see checks.go's per-module doc comments for exactly what each one
// inspects and why. In order:
//
//   - confirms the URL is actually a GraphQL endpoint with a universal
//     "{__typename}" query (see HackTricks's GraphQL page, "Universal
//     queries") before running anything else against it;
//   - runs full schema introspection, trying the documented bypasses
//     (whitespace collapsing, a newline after "__schema", GET, form-
//     urlencoded) when a plain request doesn't get it -- see
//     introspection.go;
//   - fingerprints the GraphQL engine from distinguishing error text,
//     the same differential-fingerprinting idea as graphw00f;
//   - checks whether a mutation can be executed over GET (a GraphQL-over-
//     HTTP spec violation with real CSRF/caching consequences);
//   - looks for schema information leaking through verbose error messages
//     and "did you mean" field suggestions even when introspection itself
//     is blocked (the same signal tools like clairvoyance and InQL's
//     error-based schema bruteforcer rely on);
//   - probes for the three classic unauthenticated DoS surfaces covered in
//     HackTricks's "DoS in GraphQL" section and graphql-cop's test suite:
//     array-based query batching, alias overloading, and field/directive
//     duplication -- each tested at a small, clearly non-destructive scale
//     (single digits to a few dozen), enough to show the server accepts an
//     unbounded amount of that shape of work without actually attempting
//     to cause one;
//   - checks the two content types that make a GraphQL endpoint CSRF-
//     reachable without a CORS preflight (form-urlencoded POST, plain
//     GET);
//   - checks whether Automatic Persisted Queries is enabled, since it's
//     commonly mistaken for an operation safelist when it isn't one (see
//     HackTricks's "Persisted queries / APQ are not a security boundary").
//
// This tool never executes a real mutation, never floods a target at any
// meaningful scale, and never brute-forces credentials through batching --
// see bypass403's package doc for the same "authorized-testing tooling"
// posture this package follows.
package graphqlenum

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"net/http"
	"net/url"
	"sort"
	"sync"
)

// Finding is one thing a check found. Shaped like probescan.Finding/
// pwreset.Finding -- kept as its own type for the same reason those two
// give: this scanner's findings aren't otherwise related to either.
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
	// Confidence is "confirmed" when the behavior was reproduced, "likely" or
	// "heuristic" otherwise.
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

// Request is one run's configuration.
type Request struct {
	// URL is the GraphQL endpoint itself. Must include a scheme.
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// Progress, when set, receives one check per module (or per attempt). Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// Baseline is the universal-query check's own result -- the thing that
// decides whether this is even worth pointing a GraphQL scanner at.
type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
	// Confirmed is false when the target doesn't look like a GraphQL
	// endpoint in the first place -- Run returns immediately in that case
	// (see bypass403.Result.Baseline.Blocked's identical reasoning), since
	// every other check here assumes it's actually talking to one.
	Confirmed bool   `json:"confirmed"`
	TypeName  string `json:"typeName,omitempty"`
}

// Result is one run's full output.
type Result struct {
	Baseline Baseline `json:"baseline"`
	// Schema is only present when some introspection technique worked --
	// see introspection.go's Schema type and runIntrospectionModule.
	Schema  *Schema        `json:"schema,omitempty"`
	Modules []ModuleResult `json:"modules"`
}

// moduleDef is one check category. run receives the shared client, the
// resolved target, and the run's own headers (e.g. a saved credential's
// Authorization/Cookie) -- mirrors pwreset.moduleDef, minus the fields
// this package's checks don't need (there's no baseline response or
// per-run identifier to thread through here).
type moduleDef struct {
	id, name, severity string
	run                func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding
}

// registeredModules is every check Run performs through the generic
// concurrent battery below -- introspection is handled separately (see
// Run) since its real output is Result.Schema, not just a findings list.
func registeredModules() []moduleDef {
	return []moduleDef{
		engineFingerprintModule, mutationOverGETModule, verboseErrorsModule,
		batchingModule, dosOverloadModule, csrfModule, apqModule,
	}
}

// moduleOrder is Result.Modules' display order -- introspection first
// since it's the headline result, then roughly "what this endpoint is"
// before "what's wrong with it", matching the package doc's own ordering.
var moduleOrder = []string{
	"introspection", "engine-fingerprint", "mutation-over-get", "verbose-errors",
	"batching", "dos-overload", "csrf", "apq",
}

// Run resolves req.URL, confirms it's a GraphQL endpoint, then runs
// introspection followed by every other check module concurrently against
// it.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	target, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}
	client := newClient()

	baselineRes, err := postJSON(ctx, client, target, "{__typename}", nil, req.Headers)
	if err != nil {
		return nil, fmt.Errorf("graphqlenum: baseline request failed: %w", err)
	}
	env, _ := parseEnvelope(baselineRes.Body)
	typeName := env.typename()
	baseline := Baseline{
		URL:        req.URL,
		StatusCode: baselineRes.StatusCode,
		Confirmed:  env.hasData() && typeName != "",
		TypeName:   typeName,
	}
	if !baseline.Confirmed {
		// Nothing here can tell the operator anything useful about a
		// target that isn't a GraphQL endpoint in the first place.
		return &Result{Baseline: baseline}, nil
	}

	defs := registeredModules()
	checks := []scanprogress.Check{{ID: "introspection", Label: "Introspection"}}
	for _, m := range defs {
		checks = append(checks, scanprogress.Check{ID: m.id, Label: m.name})
	}
	rep.Plan(checks...)

	rep.Start("introspection")
	introFindings, schema := runIntrospectionModule(ctx, client, target, req.Headers)
	rep.Done("introspection", len(introFindings), nil)
	modules := []ModuleResult{{ID: "introspection", Name: "Introspection", Severity: "high", Findings: orEmpty(introFindings)}}

	concurrentResults := make([]ModuleResult, len(defs))
	var wg sync.WaitGroup
	// Every module fires its own independent batch of requests against the
	// same endpoint, so they all run concurrently -- a full scan takes
	// roughly as long as its slowest module, not the sum of every module.
	for i, m := range defs {
		wg.Add(1)
		go func(i int, m moduleDef) {
			defer wg.Done()
			rep.Start(m.id)
			findings := m.run(ctx, client, target, req.Headers)
			rep.Done(m.id, len(findings), nil)
			concurrentResults[i] = ModuleResult{ID: m.id, Name: m.name, Severity: m.severity, Findings: orEmpty(findings)}
		}(i, m)
	}
	wg.Wait()
	modules = append(modules, concurrentResults...)

	rank := make(map[string]int, len(moduleOrder))
	for i, id := range moduleOrder {
		rank[id] = i
	}
	sort.Slice(modules, func(i, j int) bool { return rank[modules[i].ID] < rank[modules[j].ID] })

	return &Result{Baseline: baseline, Schema: schema, Modules: modules}, nil
}

// orEmpty turns a nil findings slice into an empty (but non-nil) one -- a
// nil slice would otherwise serialize to JSON `null` instead of `[]`,
// which the frontend treats as an always-present array (same reasoning as
// pwreset.Run's identical helper).
func orEmpty(findings []Finding) []Finding {
	if findings == nil {
		return []Finding{}
	}
	return findings
}

// Confidence levels for a Finding.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceHeuristic = "heuristic"
)
