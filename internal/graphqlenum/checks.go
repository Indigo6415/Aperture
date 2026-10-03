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

func runEngineFingerprintModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	directiveRes, directiveErr := postJSON(ctx, client, target, "query @deprecated { __typename }", nil, headers)
	fieldRes, fieldErr := postJSON(ctx, client, target, "{ apertureNonexistentFieldXyz }", nil, headers)

	var errText string
	var header http.Header
	var statusCode int
	var capturedReq *CapturedRequest
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

	for _, sig := range engineSignatures {
		if sig.match(errText, header) {
			return []Finding{{
				Label:      fmt.Sprintf("Engine identified as %s", sig.name),
				Detail:     "Identified from the wording of a validation error, the same differential-fingerprinting approach graphw00f uses -- treat as a strong hint, not a certainty.",
				Evidence:   errText,
				Method:     "POST",
				StatusCode: statusCode,
				Request:    capturedReq,
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
	return ok && env.hasData() && env.typename() == "Mutation"
}

// --- Verbose-errors module ---
// When introspection is blocked, the server's own error messages are
// often enough to reconstruct parts of the schema anyway -- the same
// signal tools like clairvoyance and InQL's error-based schema
// bruteforcer are built around (see hacktricks's "GraphQL Without
// Introspection" and "Error-based schema reconstruction" sections). This
// module runs two lightweight, non-exhaustive versions of that idea: it
// checks whether "did you mean" suggestions leak real field names, and
// whether error output carries a stack trace or on-disk path (a separate,
// simpler information-disclosure signal). A full wordlist-driven schema
// bruteforce is a different scale of tool (see clairvoyance/InQL) and
// deliberately out of scope here.
var verboseErrorsModule = moduleDef{
	id: "verbose-errors", name: "Verbose errors", severity: "low",
	run: runVerboseErrorsModule,
}

// malformedQueries are the three probes hacktricks's "Basic Enumeration"
// section lists for checking whether detailed errors are returned at all.
var malformedQueries = []string{"{__schema}", "{}", "{thisdefinitelydoesnotexist}"}

// fieldGuesses is a small, generic set of common root-field names -- not a
// real brute-force wordlist, just enough to occasionally trip a "did you
// mean" suggestion against a real field on an endpoint that happens to use
// one of these common names.
var fieldGuesses = []string{
	"user", "users", "me", "viewer", "account", "accounts", "profile",
	"search", "node", "nodes", "product", "products", "order", "orders",
	"login", "health", "status", "ping",
}

var suggestionRe = regexp.MustCompile(`(?i)did you mean[^?]*\?`)
var suggestionNameRe = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*)"`)

// stackTraceRe matches an on-disk source path with a line number, or a
// Python/.NET-style trace header -- generic across languages rather than
// tied to one framework's exact format.
var stackTraceRe = regexp.MustCompile(`(?i)(traceback \(most recent call last\)|at [\w.$]+\([^)]*:\d+:\d+\)|/[\w./-]+\.(go|rb|py|js|ts|java|php):\d+|system\.\w*exception)`)

func runVerboseErrorsModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	var findings []Finding
	var combinedErrText string
	suggested := map[string]bool{}
	var stackEvidence string
	var stackRequest, suggestedRequest *CapturedRequest

	probe := func(query string) {
		res, err := postJSON(ctx, client, target, query, nil, headers)
		if err != nil {
			return
		}
		env, ok := parseEnvelope(res.Body)
		if !ok {
			return
		}
		combinedErrText += env.errorText() + " "
		if stackEvidence == "" {
			if m := stackTraceRe.FindString(env.errorText()); m != "" {
				stackEvidence = m
				stackRequest = &res.Request
			}
		}
		if suggestionRe.MatchString(env.errorText()) && suggestedRequest == nil {
			suggestedRequest = &res.Request
		}
		for _, sentence := range suggestionRe.FindAllString(env.errorText(), -1) {
			for _, m := range suggestionNameRe.FindAllStringSubmatch(sentence, -1) {
				suggested[m[1]] = true
			}
		}
	}

	// The three baseline malformed queries, then the small field-name
	// guess list -- all independent single requests against the same
	// endpoint, so there's no reason to serialize them.
	for _, q := range malformedQueries {
		probe(q)
	}
	for _, guess := range fieldGuesses {
		probe("{ " + guess + " }")
	}

	if stackEvidence != "" {
		findings = append(findings, Finding{
			Label:    "Error responses leak a stack trace / on-disk path",
			Detail:   "At least one malformed query's error output included what looks like a source file path or exception trace -- a debug/verbose error mode that's leaking implementation details beyond GraphQL's own schema information.",
			Evidence: stackEvidence,
			Method:   "POST",
			Request:  stackRequest,
		})
	}
	if len(suggested) > 0 {
		names := make([]string, 0, len(suggested))
		for n := range suggested {
			names = append(names, n)
		}
		findings = append(findings, Finding{
			Label:    fmt.Sprintf("%d field/type name(s) inferred from \"did you mean\" suggestions", len(names)),
			Detail:   "Even with a wrong field name, the server's error suggested a real one -- the same field-stuffing signal clairvoyance/InQL use to rebuild a schema without introspection. This was a small generic guess list, not an exhaustive wordlist run.",
			Evidence: strings.Join(names, ", "),
			Method:   "POST",
			Request:  suggestedRequest,
		})
	}
	return findings
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
		if e.hasData() {
			succeeded++
		}
	}
	if succeeded == 0 {
		return nil
	}
	return []Finding{{
		Label:      "Array-based query batching accepted",
		Detail:     fmt.Sprintf("A single HTTP request containing %d batched operations executed %d of them -- a request-count-based rate limiter can be bypassed by packing more operations into each batch.", batchSize, succeeded),
		Evidence:   fmt.Sprintf("%d/%d batched operations returned data", succeeded, batchSize),
		Method:     "POST",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
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

func runDOSOverloadModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	type probe struct {
		label, detail, query string
	}
	var b strings.Builder
	for i := 0; i < overloadCount; i++ {
		fmt.Fprintf(&b, "a%d:__typename ", i)
	}
	aliasQuery := "{ " + b.String() + "}"

	fieldQuery := "{ " + strings.Repeat("__typename ", overloadCount) + "}"

	directiveQuery := "{ __typename" + strings.Repeat(" @include(if:true)", directiveOverloadCount) + " }"

	probes := []probe{
		{label: "alias overloading", detail: fmt.Sprintf("A query aliasing the same field %d times was accepted with no alias-count limit -- at real scale (thousands of aliases) this forces the resolver to run once per alias.", overloadCount), query: aliasQuery},
		{label: "field duplication", detail: fmt.Sprintf("A query requesting the same field %d times (no aliasing) was accepted with no field-repetition limit.", overloadCount), query: fieldQuery},
		{label: "directive duplication", detail: fmt.Sprintf("A query with the same directive repeated %d times on one field was accepted with no per-field directive limit.", directiveOverloadCount), query: directiveQuery},
	}

	var findings []Finding
	for _, p := range probes {
		res, err := postJSON(ctx, client, target, p.query, nil, headers)
		if err != nil {
			continue
		}
		env, ok := parseEnvelope(res.Body)
		if !ok || !env.hasData() {
			continue
		}
		findings = append(findings, Finding{
			Label:      "No limit enforced on " + p.label,
			Detail:     p.detail,
			Method:     "POST",
			StatusCode: res.StatusCode,
			Request:    &res.Request,
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
var csrfModule = moduleDef{
	id: "csrf", name: "CSRF-reachable content types", severity: "medium",
	run: runCSRFModule,
}

func runCSRFModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	var findings []Finding

	if res, err := postForm(ctx, client, target, "{__typename}", headers); err == nil {
		if env, ok := parseEnvelope(res.Body); ok && env.hasData() {
			findings = append(findings, Finding{
				Label:      "Accepts queries via application/x-www-form-urlencoded",
				Detail:     "A form-urlencoded POST body is a CORS-simple request -- it's sent cross-site without a preflight, so any page can submit one carrying the victim's cookies.",
				Method:     "POST",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
			})
		}
	}
	if res, err := getQuery(ctx, client, target, "{__typename}", headers, maxBodyBytes); err == nil {
		if env, ok := parseEnvelope(res.Body); ok && env.hasData() {
			findings = append(findings, Finding{
				Label:      "Accepts queries via plain GET with no custom-header requirement",
				Detail:     "A GET request needs no preflight either, and can be triggered by a top-level navigation or an <img>-style cross-site request -- worth confirming no state-changing operation is reachable the same way.",
				Method:     "GET",
				StatusCode: res.StatusCode,
				Request:    &res.Request,
			})
		}
	}
	return findings
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
	}}
}
