package graphqlenum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// queryOf extracts the GraphQL query text from a request, whichever of the
// three shapes this package sends it in: a JSON POST, a form POST, or a GET.
func queryOf(r *http.Request) string {
	if r.Method == http.MethodGet {
		return r.URL.Query().Get("query")
	}
	if strings.Contains(r.Header.Get("Content-Type"), "form-urlencoded") {
		_ = r.ParseForm()
		return r.PostForm.Get("query")
	}
	body, _ := io.ReadAll(r.Body)
	var payload struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(body, &payload)
	return payload.Query
}

// gqlFake serves answer's body for every GraphQL request, whatever its shape.
// answer receives the query text and returns the JSON response body.
func gqlFake(t *testing.T, answer func(query string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, answer(queryOf(r)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// typenameOnly answers the universal query and nothing else, the shape of a
// server with introspection and every other probe turned off.
func typenameOnly(query, typename string) (string, bool) {
	if strings.TrimSpace(query) == "{__typename}" || strings.TrimSpace(query) == "{ __typename }" {
		return fmt.Sprintf(`{"data":{"__typename":%q}}`, typename), true
	}
	return "", false
}

// mustTarget parses a server URL for direct calls into one module.
func mustTarget(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// findLabel returns the finding whose label starts with prefix, failing the
// test if none does.
func findLabel(t *testing.T, findings []Finding, prefix string) Finding {
	t.Helper()
	for _, f := range findings {
		if strings.HasPrefix(f.Label, prefix) {
			return f
		}
	}
	t.Fatalf("no finding starting with %q in %+v", prefix, findings)
	return Finding{}
}

// TestAlternateEndpointIsFound: the requested path is the wrong one, and the
// real endpoint sits at a well-known alternate under the same origin. The run
// must confirm it and report where it resolved.
func TestAlternateEndpointIsFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/graphql" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "404 page not found")
			return
		}
		body, ok := typenameOnly(queryOf(r), "Query")
		if !ok {
			body = `{"errors":[{"message":"Cannot query field \"x\" on type \"Query\"."}]}`
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/graphql"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Baseline.Confirmed {
		t.Fatal("expected the alternate endpoint to confirm")
	}
	if want := srv.URL + "/api/graphql"; res.Baseline.ResolvedURL != want {
		t.Errorf("ResolvedURL = %q, want %q", res.Baseline.ResolvedURL, want)
	}
}

// TestAlternateEndpointUnderParentDirectory: a GraphQL endpoint mounted next to
// the requested URL (here /shop/graphql for a request to /shop/gql) is found
// by the parent-directory search.
func TestAlternateEndpointUnderParentDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shop/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := typenameOnly(queryOf(r), "Query")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	target := mustTarget(t, srv.URL+"/shop/gql")
	alt, res, ok := findAlternateEndpoint(context.Background(), newClient(), target, nil)
	if !ok {
		t.Fatal("expected /shop/graphql to be found from /shop/gql")
	}
	if alt.Path != "/shop/graphql" || res == nil {
		t.Errorf("found %q, want /shop/graphql", alt.Path)
	}
}

// TestSPACatchAllIsNotGraphQL is the first false positive: a host that serves
// an HTML shell (containing the word "data" in its scripts) for every path must
// not be reported as a GraphQL endpoint, at the requested URL or any alternate.
func TestSPACatchAllIsNotGraphQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body><script>var data = {"data": 1};</script></body></html>`)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/graphql"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Baseline.Confirmed || res.Baseline.ResolvedURL != "" {
		t.Errorf("HTML shell confirmed as GraphQL: %+v", res.Baseline)
	}
	if len(res.Modules) != 0 {
		t.Errorf("modules ran against a non-GraphQL target: %d", len(res.Modules))
	}
}

// TestJSONEnvelopeWithoutTypenameIsNotGraphQL: a JSON API that wraps every
// answer in a data envelope has the shape the old check accepted, but no
// __typename, so it must not confirm.
func TestJSONEnvelopeWithoutTypenameIsNotGraphQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"status":"ok"}}`)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/api/items"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Baseline.Confirmed {
		t.Error("a JSON data envelope without __typename was confirmed as GraphQL")
	}
}

// TestSuggestionWalkFollowsHints is the positive case for schema recovery:
// `ledger` is never a seed name and is reachable only through a hint the server
// attaches to `invoices`, so the walk has to follow a hint from a probe that
// itself proved a field exists.
func TestSuggestionWalkFollowsHints(t *testing.T) {
	nameRe := regexp.MustCompile(`^\{ (\w+) \}$`)
	srv := gqlFake(t, func(query string) string {
		if body, ok := typenameOnly(query, "Query"); ok {
			return body
		}
		m := nameRe.FindStringSubmatch(strings.TrimSpace(query))
		if m == nil {
			return `{"errors":[{"message":"syntax"}]}`
		}
		switch m[1] {
		case "accounts":
			return `{"data":{"accounts":[]}}`
		case "ledger":
			return `{"data":{"ledger":[]}}`
		case "invoices":
			return `{"errors":[{"message":"Field \"invoices\" argument \"id\" of type \"ID!\" is required, but it was not provided. Did you mean \"ledger\"?"}]}`
		}
		// Any other name is unknown: the server offers the two fields it does have.
		return fmt.Sprintf(`{"errors":[{"message":"Cannot query field \"%s\" on type \"Query\". Did you mean \"accounts\" or \"invoices\"?"}]}`, m[1])
	})

	findings := runFieldSuggestionModule(context.Background(), newClient(), mustTarget(t, srv.URL), nil)
	proven := findLabel(t, findings, "3 root field(s) proven")
	if proven.Confidence != ConfidenceConfirmed {
		t.Errorf("proven-field finding confidence = %q, want confirmed", proven.Confidence)
	}
	for _, want := range []string{"accounts", "invoices", "ledger"} {
		if !strings.Contains(proven.Evidence, want) {
			t.Errorf("evidence %q is missing %q", proven.Evidence, want)
		}
	}
}

// TestSuggestionWalkIgnoresGenericErrors is the negative case: errors that name
// no field and prove nothing must produce no finding.
func TestSuggestionWalkIgnoresGenericErrors(t *testing.T) {
	srv := gqlFake(t, func(query string) string {
		if body, ok := typenameOnly(query, "Query"); ok {
			return body
		}
		return `{"errors":[{"message":"Something went wrong"}]}`
	})
	if got := runFieldSuggestionModule(context.Background(), newClient(), mustTarget(t, srv.URL), nil); len(got) != 0 {
		t.Errorf("findings = %+v, want none", got)
	}
}

// TestSuggestionWalkHonorsBudget: a server that invents a new name in every
// hint never runs out of suggestions, so the budget is the only thing that
// stops the walk.
func TestSuggestionWalkHonorsBudget(t *testing.T) {
	counter := regexp.MustCompile(`n(\d+)`)
	srv := gqlFake(t, func(query string) string {
		if body, ok := typenameOnly(query, "Query"); ok {
			return body
		}
		m := counter.FindStringSubmatch(query)
		n := 0
		if m != nil {
			fmt.Sscanf(m[1], "%d", &n)
		}
		return fmt.Sprintf(`{"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"n%d\"?"}]}`, n+1)
	})
	rec := recoverRootFields(context.Background(), newClient(), mustTarget(t, srv.URL), nil, []string{"n0"}, 12)
	if rec.Probes > 12 {
		t.Errorf("sent %d probes, budget was 12", rec.Probes)
	}
	if rec.Probes == 0 {
		t.Error("walk sent no probes")
	}
}

// TestSchemaInHandSkipsSuggestionWalk: once introspection has returned the
// schema, the suggestion walk has nothing new to find and is recorded as skipped.
func TestSchemaInHandSkipsSuggestionWalk(t *testing.T) {
	srv := gqlFake(t, func(query string) string {
		if body, ok := typenameOnly(query, "Query"); ok {
			return body
		}
		if strings.Contains(query, "__schema") {
			return `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[],"directives":[]}}}`
		}
		return `{"errors":[{"message":"nope"}]}`
	})
	res, err := Run(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Schema == nil {
		t.Fatal("introspection did not return a schema")
	}
	for _, m := range res.Modules {
		if m.ID != "field-suggestions" {
			continue
		}
		if m.Skipped == "" {
			t.Error("field-suggestions ran even though the schema was already in hand")
		}
		if len(m.Findings) != 0 {
			t.Errorf("skipped module carried findings: %+v", m.Findings)
		}
		return
	}
	t.Fatal("field-suggestions module missing from the result")
}

// TestBatchingNeedsTwoResolvedEntries: a server that executes the whole batch
// is a finding; a server that runs only one entry of it is not, since one
// success proves nothing about batching.
func TestBatchingNeedsTwoResolvedEntries(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"every entry executed", `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`, 1},
		{"only one entry executed", `[{"data":{"__typename":"Query"}},{"errors":[{"message":"batch limit"}]}]`, 0},
		{"array rejected", `{"errors":[{"message":"batching is not supported"}]}`, 0},
		{"entries answer without a typename", `[{"data":{"x":1}},{"data":{"x":2}},{"data":{"x":3}}]`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			got := runBatchingModule(context.Background(), newClient(), mustTarget(t, srv.URL), nil)
			if len(got) != tc.want {
				t.Errorf("findings = %d, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

// TestOverloadNeedsFullExecutionAndNoLimitError: the three over-large probes
// are findings only when the server executed every part of them. A limit error
// (even alongside partial data) is a limit, not a finding.
func TestOverloadNeedsFullExecutionAndNoLimitError(t *testing.T) {
	aliasRe := regexp.MustCompile(`a(\d+):__typename`)
	open := gqlFake(t, func(query string) string {
		if aliases := aliasRe.FindAllStringSubmatch(query, -1); len(aliases) > 0 {
			parts := make([]string, 0, len(aliases))
			for _, m := range aliases {
				parts = append(parts, fmt.Sprintf("%q:%q", "a"+m[1], "Query"))
			}
			return `{"data":{` + strings.Join(parts, ",") + `}}`
		}
		return `{"data":{"__typename":"Query"}}`
	})
	got := runDOSOverloadModule(context.Background(), newClient(), mustTarget(t, open.URL), nil)
	if len(got) != 3 {
		t.Fatalf("findings = %d, want 3 (alias, field, directive): %+v", len(got), got)
	}
	findLabel(t, got, "No limit enforced on alias overloading")

	limited := gqlFake(t, func(query string) string {
		return `{"data":{"__typename":"Query"},"errors":[{"message":"Query exceeds maximum complexity of 100"}]}`
	})
	if got := runDOSOverloadModule(context.Background(), newClient(), mustTarget(t, limited.URL), nil); len(got) != 0 {
		t.Errorf("a server reporting a limit produced %d findings, want 0", len(got))
	}
}

// TestCSRFFormPostMutation: a mutation root answering a form-urlencoded POST is
// a CSRF-reachable mutation. The same server answering the query root must not be.
func TestCSRFFormPostMutation(t *testing.T) {
	mutating := gqlFake(t, func(query string) string {
		if strings.Contains(query, "mutation") {
			return `{"data":{"__typename":"Mutation"}}`
		}
		return `{"data":{"__typename":"Query"}}`
	})
	got := runCSRFModule(context.Background(), newClient(), mustTarget(t, mutating.URL), nil)
	f := findLabel(t, got, "Mutation operation executed via form-urlencoded POST")
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}

	queryOnly := gqlFake(t, func(query string) string {
		return `{"data":{"__typename":"Query"}}`
	})
	for _, f := range runCSRFModule(context.Background(), newClient(), mustTarget(t, queryOnly.URL), nil) {
		if strings.Contains(f.Label, "Mutation") {
			t.Errorf("query-only server reported a mutation: %+v", f)
		}
	}
}

// TestCSRFIgnoresForeignJSON: a non-GraphQL API that answers any POST with a
// data object must not be reported as accepting GraphQL over form or GET.
func TestCSRFIgnoresForeignJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"ok":true}}`)
	}))
	defer srv.Close()
	if got := runCSRFModule(context.Background(), newClient(), mustTarget(t, srv.URL), nil); len(got) != 0 {
		t.Errorf("foreign JSON produced %d CSRF findings, want 0: %+v", len(got), got)
	}
}

// TestHotChocolateSignatureIsHeuristic: the new engine signature matches its
// own error wording, is reported as a heuristic, and doesn't match an unrelated
// error.
func TestHotChocolateSignatureIsHeuristic(t *testing.T) {
	hc := gqlFake(t, func(query string) string {
		return "{\"errors\":[{\"message\":\"The field `apertureNonexistentFieldXyz` does not exist on the type `Query`.\"}]}"
	})
	got := runEngineFingerprintModule(context.Background(), newClient(), mustTarget(t, hc.URL), nil)
	f := findLabel(t, got, "Engine identified as HotChocolate")
	if f.Confidence != ConfidenceHeuristic {
		t.Errorf("confidence = %q, want heuristic", f.Confidence)
	}

	other := gqlFake(t, func(query string) string {
		return `{"errors":[{"message":"bad request"}]}`
	})
	if got := runEngineFingerprintModule(context.Background(), newClient(), mustTarget(t, other.URL), nil); len(got) != 0 {
		t.Errorf("unrelated error fingerprinted as %+v", got)
	}
}

// TestMutationRootNameSuffix: a custom mutation root name counts as the
// mutation root, a query root does not.
func TestMutationRootNameSuffix(t *testing.T) {
	cases := map[string]bool{"Mutation": true, "RootMutation": true, "Query": false, "MutationPayload": false}
	for name, want := range cases {
		if got := isMutationRootName(name); got != want {
			t.Errorf("isMutationRootName(%q) = %v, want %v", name, got, want)
		}
	}
}
