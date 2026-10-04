package graphqlenum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// --- Engine fingerprint module ---
// Differential fingerprinting, the same idea graphw00f and InQL v6.1's
// engine fingerprinter use: send a query that's syntactically valid but
// semantically wrong in a way every server must reject, then identify the
// implementation from the exact wording of its error -- see hacktricks's
// "Error-based schema reconstruction & engine fingerprinting" section.
var engineFingerprintModule = moduleDef{
	id: "engine-fingerprint", name: "Engine fingerprint", severity: "info",
	run: runEngineFingerprintModule,
}

// engineSignature is one (probe, matcher) pair. Checked in order --
// earlier entries are more specific and should win over a later, more
// generic bucket that would otherwise also match.
type engineSignature struct {
	name  string
	match func(errText string, header http.Header) bool
}

var engineSignatures = []engineSignature{
	{name: "Hasura", match: func(e string, h http.Header) bool {
		return strings.Contains(e, "_root'") || headerContains(h, "hasura")
	}},
	{name: "graphql-java (Spring Boot / Netflix DGS / Atlassian)", match: func(e string, _ http.Header) bool {
		return strings.Contains(e, "validation error of type fieldundefined")
	}},
	{name: "HotChocolate (.NET)", match: func(e string, _ http.Header) bool {
		return strings.Contains(e, "does not exist on the type")
	}},
	{name: "GraphQL Ruby", match: func(e string, _ http.Header) bool {
		return strings.Contains(e, "can't be applied to queries")
	}},
	{name: "Apollo Server / graphql-js", match: func(e string, _ http.Header) bool {
		return strings.Contains(e, "may not be used on query")
	}},
	{name: "graphql-js-based (unspecific -- Apollo Server, GraphQL Yoga, or another Node server)", match: func(e string, _ http.Header) bool {
		return strings.Contains(e, "cannot query field") && strings.Contains(e, "on type")
	}},
}

// headerContains reports whether any response header name or value contains
// needle (case-insensitively).
func headerContains(h http.Header, needle string) bool {
	// Both header names and values are checked -- Hasura's own telltale is
	// a response *header name* (X-Hasura-...), not its value.
	for k, values := range h {
		if strings.Contains(strings.ToLower(k), needle) {
			return true
		}
		for _, v := range values {
			if strings.Contains(strings.ToLower(v), needle) {
				return true
			}
		}
	}
	return false
}

// runEngineFingerprintModule sends two deliberately invalid queries and matches
// the combined error text against engineSignatures. The result is a heuristic:
// error wording changes between versions, so it is reported as one.
func runEngineFingerprintModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	directiveRes, directiveErr := postJSON(ctx, client, target, "query @deprecated { __typename }", nil, headers)
	fieldRes, fieldErr := postJSON(ctx, client, target, "{ apertureNonexistentFieldXyz }", nil, headers)

	var errText string
	var header http.Header
	var statusCode int
	var capturedReq *CapturedRequest
	// The first response that came back supplies the headers and status
	// for the finding; both probes' error text is searched.
	if directiveErr == nil {
		if env, ok := parseEnvelope(directiveRes.Body); ok {
			errText += env.errorText() + " "
		}
		header, statusCode, capturedReq = directiveRes.Header, directiveRes.StatusCode, &directiveRes.Request
	}
	if fieldErr == nil {
		if env, ok := parseEnvelope(fieldRes.Body); ok {
			errText += env.errorText()
		}
		if header == nil {
			header, statusCode, capturedReq = fieldRes.Header, fieldRes.StatusCode, &fieldRes.Request
		}
	}
	if errText == "" {
		return nil
	}

	// The first signature whose wording matches names the engine. Order in
	// engineSignatures already puts the most specific wording first.
	for _, sig := range engineSignatures {
		if sig.match(errText, header) {
			return []Finding{{
				Label:      fmt.Sprintf("Engine identified as %s", sig.name),
				Detail:     "Identified from the wording of a validation error, the same differential-fingerprinting approach graphw00f uses -- treat as a strong hint, not a certainty.",
				Evidence:   errText,
				Method:     "POST",
				StatusCode: statusCode,
				Request:    capturedReq,
				Confidence: ConfidenceHeuristic,
			}}
		}
	}
	return nil
}

// --- Mutation-over-GET module ---
// The GraphQL-over-HTTP spec requires servers to reject mutations sent as
// a GET request -- GET requests can be triggered cross-site without a
// CORS preflight (an <img> tag, a top-level navigation) and are eligible
// for caching by intermediate proxies/browsers, neither of which a
// state-changing operation should ever be exposed to. The probe only ever
// asks for "__typename" -- it never invokes a real mutation field -- so a
// server that does accept it just echoes back its Mutation root type's
// name, with no side effect.
var mutationOverGETModule = moduleDef{
	id: "mutation-over-get", name: "Mutations over GET", severity: "high",
	run: runMutationOverGETModule,
}

// runMutationOverGETModule sends mutation{__typename} as a GET and reports
// only when the Mutation root itself answers, twice.
func runMutationOverGETModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	res, err := getQuery(ctx, client, target, "mutation{__typename}", headers, maxBodyBytes)
	if err != nil {
		return nil
	}
	// The answer must come from the Mutation root. A server that ignores the
	// operation keyword runs the selection against the query root instead and
	// answers "Query", which is not a mutation running; reporting that was a
	// false positive.
	if !mutationRootAnswered(res.Body) {
		return nil
	}
	// Replay once before reporting: a single response is not enough to call
	// the behavior consistent.
	again, err := getQuery(ctx, client, target, "mutation{__typename}", headers, maxBodyBytes)
	if err != nil || !mutationRootAnswered(again.Body) {
		return nil
	}
	return []Finding{{
		Label:      "Mutation operation executed via GET",
		Detail:     "The GraphQL-over-HTTP spec requires servers to reject mutations sent as GET -- this one executed a (side-effect-free, __typename-only) mutation operation anyway, which means a real mutation could be triggered cross-site without a CORS preflight, or served from a cache. The same answer came back on a second request.",
		Evidence:   "mutation{__typename} via GET -> Mutation (twice)",
		Method:     "GET",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: ConfidenceConfirmed,
	}}
}

// mutationRootAnswered reports whether a GraphQL response's __typename is the
// Mutation root type.
func mutationRootAnswered(body []byte) bool {
	env, ok := parseEnvelope(body)
	return ok && env.hasData() && isMutationRootName(env.typename())
}

// isMutationRootName reports whether a __typename answer names a mutation
// root: "Mutation", or a custom root name ending in it (for example
// "RootMutation"), which some schemas use.
func isMutationRootName(typeName string) bool {
	return typeName == "Mutation" || strings.HasSuffix(typeName, "Mutation")
}

// --- Verbose-errors module ---
// When introspection is blocked, a server's error output can leak more than
// field names: a stack trace or an on-disk source path shows a debug/verbose
// error mode that exposes implementation details. This module sends the three
// malformed queries hacktricks's "Basic Enumeration" section lists and looks
// for that. The field-name side of the same signal (did-you-mean suggestions)
// lives in suggestions.go, where it is walked iteratively.
var verboseErrorsModule = moduleDef{
	id: "verbose-errors", name: "Verbose errors", severity: "low",
	run: runVerboseErrorsModule,
}

// malformedQueries are the three probes hacktricks's "Basic Enumeration"
// section lists for checking whether detailed errors are returned at all.
var malformedQueries = []string{"{__schema}", "{}", "{thisdefinitelydoesnotexist}"}

// stackTraceRe matches an on-disk source path with a line number, or a
// Python/.NET-style trace header -- generic across languages rather than
// tied to one framework's exact format.
var stackTraceRe = regexp.MustCompile(`(?i)(traceback \(most recent call last\)|at [\w.$]+\([^)]*:\d+:\d+\)|/[\w./-]+\.(go|rb|py|js|ts|java|php):\d+|system\.\w*exception)`)

// runVerboseErrorsModule sends each malformed query and reports the first
// stack trace or source path it finds in an error message.
func runVerboseErrorsModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	var stackEvidence string
	var stackRequest *CapturedRequest
	for _, q := range malformedQueries {
		res, err := postJSON(ctx, client, target, q, nil, headers)
		if err != nil {
			continue
		}
		env, ok := parseEnvelope(res.Body)
		if !ok {
			continue
		}
		if m := stackTraceRe.FindString(env.errorText()); m != "" {
			stackEvidence = m
			stackRequest = &res.Request
			break
		}
	}
	if stackEvidence == "" {
		return nil
	}
	return []Finding{{
		Label:      "Error responses leak a stack trace / on-disk path",
		Detail:     "At least one malformed query's error output included what looks like a source file path or exception trace -- a debug/verbose error mode that's leaking implementation details beyond GraphQL's own schema information.",
		Evidence:   stackEvidence,
		Method:     "POST",
		Request:    stackRequest,
		Confidence: ConfidenceLikely,
	}}
}

// --- Batching module ---
// A GraphQL server that accepts an array of operations in one HTTP
// request lets each batched entry bypass any rate limiter keyed on
// requests-per-second rather than operations-per-second -- see
// hacktricks's "Array-based Query Batching" (credited there to
// graphql-cop) and the Wallarm writeup on batching-based credential
// brute-forcing. This probe only ever batches five identical, side-
// effect-free "{__typename}" queries -- enough to prove batching is
// accepted, not a real brute-force or DoS attempt.
var batchingModule = moduleDef{
	id: "batching", name: "Query batching", severity: "medium",
	run: runBatchingModule,
}

const batchSize = 5

// minBatchSuccesses is how many batched entries must come back with real
// data before batching counts as accepted. One success could be a server that
// runs only the first element and rejects the rest, which proves nothing.
const minBatchSuccesses = 2

// runBatchingModule sends batchSize identical __typename queries as one JSON
// array and reports when at least minBatchSuccesses of them execute.
func runBatchingModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	batch := make([]map[string]string, batchSize)
	for i := range batch {
		batch[i] = map[string]string{"query": "{__typename}"}
	}
	buf, err := json.Marshal(batch)
	if err != nil {
		return nil
	}
	res, err := postRawJSON(ctx, client, target, buf, headers)
	if err != nil {
		return nil
	}

	var envs []gqlEnvelope
	if err := json.Unmarshal(res.Body, &envs); err != nil || len(envs) == 0 {
		return nil
	}
	succeeded := 0
	for _, e := range envs {
		// An entry only counts when it actually resolved the root typename, not
		// merely when some unrelated "data" key came back.
		if e.hasData() && e.typename() != "" {
			succeeded++
		}
	}
	if succeeded < minBatchSuccesses {
		return nil
	}
	return []Finding{{
		Label:      "Array-based query batching accepted",
		Detail:     fmt.Sprintf("A single HTTP request containing %d batched operations executed %d of them -- a request-count-based rate limiter can be bypassed by packing more operations into each batch.", batchSize, succeeded),
		Evidence:   fmt.Sprintf("%d/%d batched operations returned data", succeeded, batchSize),
		Method:     "POST",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: ConfidenceConfirmed,
	}}
}

// --- DoS-surface module ---
// Bundles the three query-shape DoS probes from hacktricks's "DoS in
// GraphQL" section (credited there to graphql-cop) into one module, the
// same way pwreset's host-header module bundles several header variants:
// each is checked independently and reported on its own, but they share a
// category since they're all "does this server cap how much of one shape
// of work a single query can ask for". Every probe here uses a count in
// the tens, not the thousands graphql-cop's own PoCs use -- enough to
// show the server doesn't reject it, not enough to be a real DoS attempt
// against the target.
var dosOverloadModule = moduleDef{
	id: "dos-overload", name: "Unbounded query shape (DoS surface)", severity: "medium",
	run: runDOSOverloadModule,
}

const overloadCount = 25
const directiveOverloadCount = 10

// limitErrorRe matches the wording servers use when they refuse an over-large
// query. An error like that means a limit exists, so the probe is not a finding.
var limitErrorRe = regexp.MustCompile(`(?i)(too many|exceed|maximum|complexity|depth|limit|cost|not allowed)`)

// acceptedWithoutLimit reports whether a response shows the server executed an
// over-large query in full: it returned data containing every expected key,
// and no error that reads like a limit.
func acceptedWithoutLimit(res *httpResult, keys []string) bool {
	env, ok := parseEnvelope(res.Body)
	if !ok || !env.hasData() {
		return false
	}
	if limitErrorRe.MatchString(env.errorText()) {
		return false
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return false
	}
	for _, k := range keys {
		if _, present := data[k]; !present {
			return false
		}
	}
	return true
}

// runDOSOverloadModule sends three over-large query shapes (aliases, repeated
// fields, repeated directives) and reports each one the server executes in full.
func runDOSOverloadModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	type probe struct {
		label, detail, query string
		wantKeys             []string
	}
	var b strings.Builder
	aliasKeys := make([]string, 0, overloadCount)
	for i := 0; i < overloadCount; i++ {
		fmt.Fprintf(&b, "a%d:__typename ", i)
		aliasKeys = append(aliasKeys, fmt.Sprintf("a%d", i))
	}
	aliasQuery := "{ " + b.String() + "}"

	fieldQuery := "{ " + strings.Repeat("__typename ", overloadCount) + "}"

	directiveQuery := "{ __typename" + strings.Repeat(" @include(if:true)", directiveOverloadCount) + " }"

	probes := []probe{
		{label: "alias overloading", detail: fmt.Sprintf("A query aliasing the same field %d times was executed in full with no alias-count limit -- at real scale (thousands of aliases) this forces the resolver to run once per alias.", overloadCount), query: aliasQuery, wantKeys: aliasKeys},
		{label: "field duplication", detail: fmt.Sprintf("A query requesting the same field %d times (no aliasing) was executed with no field-repetition limit.", overloadCount), query: fieldQuery, wantKeys: []string{"__typename"}},
		{label: "directive duplication", detail: fmt.Sprintf("A query with the same directive repeated %d times on one field was executed with no per-field directive limit.", directiveOverloadCount), query: directiveQuery, wantKeys: []string{"__typename"}},
	}

	var findings []Finding
	for _, p := range probes {
		res, err := postJSON(ctx, client, target, p.query, nil, headers)
		if err != nil {
			continue
		}
		if !acceptedWithoutLimit(res, p.wantKeys) {
			continue
		}
		findings = append(findings, Finding{
			Label:      "No limit enforced on " + p.label,
			Detail:     p.detail,
			Method:     "POST",
			StatusCode: res.StatusCode,
			Request:    &res.Request,
			Confidence: ConfidenceConfirmed,
		})
	}
	return findings
}

// --- CSRF module ---
// GraphQL requests are normally sent as an application/json POST, which
// requires a CORS preflight cross-site. A server that also accepts a
// form-urlencoded POST or a plain GET is reachable through a CORS-simple
// request instead -- no preflight, so no chance for the browser to block
// it before it's already been sent. See hacktricks's "CSRF in GraphQL".
//
// Reachability alone isn't the finding -- what matters is whether a mutation
// is reachable that way. So the form-urlencoded probe also sends
// mutation{__typename}, which runs no field and only reports the root type.
var csrfModule = moduleDef{
	id: "csrf", name: "CSRF-reachable content types", severity: "medium",
	run: runCSRFModule,
}

// runCSRFModule checks which CORS-simple request shapes the endpoint accepts,
// and whether a mutation root answers through them.
func runCSRFModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	var findings []Finding

	if res, err := postForm(ctx, client, target, "{__typename}", headers); err == nil {
		if env, ok := parseEnvelope(res.Body); ok && env.hasData() && env.typename() != "" {
			findings = append(findings, Finding{
				Label:      "Accepts queries via application/x-www-form-urlencoded",
				Detail:     "A form-urlencoded POST body is a CORS-simple request -- it's sent cross-site without a preflight, so any page can submit one carrying the victim's cookies.",
				Method:     "POST",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
				Confidence: ConfidenceConfirmed,
			})
		}
	}
	if res, err := getQuery(ctx, client, target, "{__typename}", headers, maxBodyBytes); err == nil {
		if env, ok := parseEnvelope(res.Body); ok && env.hasData() && env.typename() != "" {
			findings = append(findings, Finding{
				Label:      "Accepts queries via plain GET with no custom-header requirement",
				Detail:     "A GET request needs no preflight either, and can be triggered by a top-level navigation or an <img>-style cross-site request -- worth confirming no state-changing operation is reachable the same way.",
				Method:     "GET",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
				Confidence: ConfidenceConfirmed,
			})
		}
	}
	if f, ok := formMutationFinding(ctx, client, target, headers); ok {
		findings = append(findings, f)
	}
	return findings
}

// formMutationFinding checks whether a mutation root answers through a
// form-urlencoded POST, the CSRF-reachable form of the mutation-over-GET spec
// violation. The probe is __typename only, and it is replayed once so a single
// flaky answer cannot produce the finding.
func formMutationFinding(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (Finding, bool) {
	res, err := postForm(ctx, client, target, "mutation{__typename}", headers)
	if err != nil || !mutationRootAnswered(res.Body) {
		return Finding{}, false
	}
	again, err := postForm(ctx, client, target, "mutation{__typename}", headers)
	if err != nil || !mutationRootAnswered(again.Body) {
		return Finding{}, false
	}
	return Finding{
		Label:      "Mutation operation executed via form-urlencoded POST (CSRF-able)",
		Detail:     "A mutation root answered a form-urlencoded POST -- a CORS-simple request, so a cross-site page could submit a real mutation carrying the victim's cookies. This probe only asked for __typename and executed no field; the same answer came back on a second request.",
		Evidence:   "mutation{__typename} via form-urlencoded POST -> Mutation (twice)",
		Method:     "POST",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: ConfidenceConfirmed,
	}, true
}

// --- Automatic Persisted Queries module ---
// APQ is a bandwidth optimization, not a safelist: a client can still send
// arbitrary operations on the first request when the server doesn't
// recognize the hash. Operators sometimes conflate "APQ is on" with
// "arbitrary queries are blocked", so this is reported purely as
// informational context alongside whatever else this run found -- see
// hacktricks's "Persisted queries / APQ are not a security boundary".
var apqModule = moduleDef{
	id: "apq", name: "Automatic Persisted Queries", severity: "info",
	run: runAPQModule,
}

// runAPQModule sends an APQ request with an all-zero hash. A server with APQ
// on answers PersistedQueryNotFound, which is what it says for a hash it doesn't
// know.
func runAPQModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	payload := map[string]any{
		"operationName": "AperturePersistedQueryProbe",
		"variables":     nil,
		"extensions": map[string]any{
			"persistedQuery": map[string]any{
				"version":    1,
				"sha256Hash": strings.Repeat("0", 64),
			},
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	res, err := postRawJSON(ctx, client, target, buf, headers)
	if err != nil {
		return nil
	}
	env, ok := parseEnvelope(res.Body)
	if !ok || !strings.Contains(env.errorText(), "persistedquerynotfound") {
		return nil
	}
	return []Finding{{
		Label:      "Automatic Persisted Queries (APQ) is enabled",
		Detail:     "Not a vulnerability by itself, but not a safelist either: a client that gets PersistedQueryNotFound back can just resend the request with a full query string, so APQ alone doesn't block arbitrary operations (including introspection, aliases, or brute-forced mutations) from reaching the server.",
		Method:     "POST",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: ConfidenceConfirmed,
	}}
}
