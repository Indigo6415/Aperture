// Package graphqlenum enumerates and probes a GraphQL endpoint for the
// class of issues covered in the standard GraphQL pentesting references --
// see checks.go's per-module doc comments for exactly what each one
// inspects and why. In order:
//
//   - confirms the URL is actually a GraphQL endpoint with a universal
//     "{__typename}" query (see HackTricks's GraphQL page, "Universal
//     queries") before running anything else against it. When the requested
//     URL doesn't answer that way, the well-known alternate GraphQL paths are
//     tried under the same origin (see discover.go), and the one that answers
//     becomes the endpoint for the rest of the run;
//   - runs full schema introspection, trying the documented bypasses
//     (whitespace collapsing, a newline after "__schema", GET, form-
//     urlencoded) when a plain request doesn't get it -- see
//     introspection.go;
//   - fingerprints the GraphQL engine from distinguishing error text,
//     the same differential-fingerprinting idea as graphw00f;
//   - checks whether a mutation can be executed over GET or via a form-
//     urlencoded POST (GraphQL-over-HTTP spec violations with real CSRF/
//     caching consequences);
//   - looks for schema information leaking through verbose error messages
//     and "did you mean" field suggestions even when introspection itself
//     is blocked (the same signal tools like clairvoyance and InQL's
//     error-based schema bruteforcer rely on). The suggestion walk is
//     iterative -- every name the server suggests is probed in turn -- and
//     is skipped entirely when introspection already returned the schema
//     (see suggestions.go);
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
// Skipped, when set, says why a module was deliberately not run at all.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"` // info | low | medium | high | critical
	Findings []Finding `json:"findings"`
	Skipped  string    `json:"skipped,omitempty"`
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
	// ResolvedURL is the endpoint every check actually ran against, set only
	// when it differs from URL -- the requested URL didn't answer as GraphQL,
	// and an alternate path under the same origin did (see discover.go).
	ResolvedURL string `json:"resolvedUrl,omitempty"`
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
		fieldSuggestionModule,
		batchingModule, dosOverloadModule, csrfModule, apqModule,
	}
}

// moduleOrder is Result.Modules' display order -- introspection first
// since it's the headline result, then roughly "what this endpoint is"
// before "what's wrong with it", matching the package doc's own ordering.
var moduleOrder = []string{
	"introspection", "engine-fingerprint", "mutation-over-get", "verbose-errors", "field-suggestions",
	"batching", "dos-overload", "csrf", "apq",
}

// Run resolves req.URL, confirms it's a GraphQL endpoint (trying alternate
// paths if it isn't at req.URL), then runs introspection followed by every
// other check module concurrently against it. The field-suggestion walk is
// skipped when introspection already returned the schema.
func Run(ctx context.Context, req Request) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	target, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}
	client := newClient()

	baseline, endpoint, err := confirmEndpoint(ctx, client, target, req.Headers)
	if err != nil {
		return nil, err
	}
	baseline.URL = req.URL
	if !baseline.Confirmed {
		// Nothing here can tell the operator anything useful about a
		// target that isn't a GraphQL endpoint in the first place.
		return &Result{Baseline: baseline}, nil
	}
	target = endpoint

	rep.Plan(scanprogress.Check{ID: "introspection", Label: "Introspection"})
	rep.Start("introspection")
	introFindings, schema := runIntrospectionModule(ctx, client, target, req.Headers)
	rep.Done("introspection", len(introFindings), nil)
	modules := []ModuleResult{{ID: "introspection", Name: "Introspection", Severity: "high", Findings: orEmpty(introFindings)}}

	// Everything still to run goes through the same concurrent battery; the
	// suggestion walk is dropped when the schema is already in hand, since it
	// would only rediscover names introspection just listed.
	var defs []moduleDef
	for _, m := range registeredModules() {
		if m.id == fieldSuggestionModule.id && schema != nil {
			modules = append(modules, ModuleResult{
				ID: m.id, Name: m.name, Severity: m.severity, Findings: []Finding{},
				Skipped: "introspection already returned the full schema",
			})
			continue
		}
		defs = append(defs, m)
	}
	checks := make([]scanprogress.Check, 0, len(defs))
	for _, m := range defs {
		checks = append(checks, scanprogress.Check{ID: m.id, Label: m.name})
	}
	rep.Plan(checks...)

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

// confirmEndpoint runs the universal-query check against the requested URL
// and, if that URL doesn't answer as GraphQL, against the alternate paths
// discover.go knows about. It returns the baseline (Confirmed reports whether
// any endpoint answered) and the endpoint every later check should use.
func confirmEndpoint(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (Baseline, *url.URL, error) {
	res, err := postJSON(ctx, client, target, "{__typename}", nil, headers)
	if err != nil {
		return Baseline{}, target, fmt.Errorf("graphqlenum: baseline request failed: %w", err)
	}
	env, _ := parseEnvelope(res.Body)
	if typeName := env.typename(); env.hasData() && typeName != "" {
		return Baseline{StatusCode: res.StatusCode, Confirmed: true, TypeName: typeName}, target, nil
	}

	// The requested URL isn't GraphQL. Try the usual alternate locations
	// before giving up, since a GraphQL API is often mounted at a path other
	// than the one the operator pasted in.
	if alt, altRes, ok := findAlternateEndpoint(ctx, client, target, headers); ok {
		altEnv, _ := parseEnvelope(altRes.Body)
		return Baseline{
			StatusCode: altRes.StatusCode, Confirmed: true, TypeName: altEnv.typename(),
			ResolvedURL: alt.String(),
		}, alt, nil
	}
	return Baseline{StatusCode: res.StatusCode}, target, nil
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
