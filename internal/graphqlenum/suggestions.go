package graphqlenum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// --- Field-suggestion schema recovery module ---
// With introspection disabled, the server's own validation errors still name
// real fields: a "Did you mean "users"?" hint leaks a name that exists, and an
// error about a missing argument or a missing selection set proves a field
// exists even when the server gives no name at all. This is the signal
// clairvoyance and InQL's error-based bruteforcer are built on (see hacktricks's
// "GraphQL Without Introspection" section).
//
// Unlike a fixed guess list, this walks the hints: every suggested name is
// probed in turn, and the names those probes suggest are probed too, until
// the queue is empty or the probe budget is spent. The probes are bare
// root-level selections of query-root fields -- never a mutation field, since
// a mutation with no arguments could execute.
var fieldSuggestionModule = moduleDef{
	id: "field-suggestions", name: "Field-suggestion schema recovery", severity: "low",
	run: runFieldSuggestionModule,
}

// fieldSeedNames is where the walk starts: common root-field names across public
// and private GraphQL APIs. Suggestions widen the set from here.
var fieldSeedNames = []string{
	"me", "viewer", "node", "nodes", "user", "users", "account", "accounts", "profile", "profiles",
	"currentUser", "current_user", "getUser", "getUsers", "listUsers", "allUsers", "searchUsers",
	"search", "query", "queries", "lookup", "find", "get", "list", "all", "fetch",
	"product", "products", "item", "items", "cart", "carts", "order", "orders", "invoice", "invoices",
	"payment", "payments", "transaction", "transactions", "customer", "customers", "subscription", "subscriptions",
	"post", "posts", "comment", "comments", "article", "articles", "page", "pages", "category", "categories",
	"tag", "tags", "feed", "timeline", "message", "messages", "notification", "notifications", "event", "events",
	"organization", "organizations", "team", "teams", "member", "members", "group", "groups", "role", "roles",
	"permission", "permissions", "project", "projects", "file", "files", "upload", "media", "report", "reports",
	"stats", "analytics", "dashboard", "settings", "setting", "config", "session", "sessions", "token", "tokens",
	"login", "logout", "health", "status", "ping", "version", "info", "schema", "types", "debug", "admin",
	"hello", "echo", "test",
}

// maxSuggestionProbes bounds how many probes one run's walk sends, counting
// the seeds. Each probe is one read-only request, so this caps the cost of a
// target that suggests names endlessly.
const maxSuggestionProbes = 100

// suggestionRe and suggestionNameRe pull a "Did you mean ...?" sentence and then
// the quoted identifiers inside it out of an error message.
var suggestionRe = regexp.MustCompile(`(?i)did you mean[^?]*\?`)
var suggestionNameRe = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*)"`)

// fieldNameRe validates a name the server suggested before it is probed, so a
// hint carrying punctuation can't turn into a malformed query.
var fieldNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// existenceMarkers are error messages only a real field produces. A probe that
// returns one has proven the field is in the schema, whether or not it returned data.
var existenceMarkers = []string{
	"must have a selection of subfields",   // an object-typed field sent without a selection set
	"is required, but it was not provided", // a field whose required argument was left out
	"non-nullable",                         // a field that resolved but returned null where none is allowed
}

// fieldProbe is what one bare `{ name }` probe revealed.
type fieldProbe struct {
	exists    bool     // the server proved the field exists
	suggested []string // names the server offered in a "did you mean" hint
}

// fieldRecovery is the outcome of one suggestion walk.
type fieldRecovery struct {
	Exists    []string         // names proven to be root fields
	Suggested []string         // names offered in hints but never proven by a probe
	Probes    int              // how many requests the walk sent
	Request   *CapturedRequest // the first probe that proved a field exists
}

// runFieldSuggestionModule runs the suggestion walk and reports the names it
// recovered: proven ones as confirmed, hint-only ones as likely.
func runFieldSuggestionModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) []Finding {
	rec := recoverRootFields(ctx, client, target, headers, fieldSeedNames, maxSuggestionProbes)
	var out []Finding
	if len(rec.Exists) > 0 {
		out = append(out, Finding{
			Label:      fmt.Sprintf("%d root field(s) proven to exist without introspection", len(rec.Exists)),
			Detail:     fmt.Sprintf("Introspection did not return the schema, but %d bare root-level probes showed these fields exist: each one either executed or failed with the error only a real field produces (a missing required argument or a missing selection set). The walk followed the server's own \"did you mean\" hints to find them.", rec.Probes),
			Evidence:   strings.Join(rec.Exists, ", "),
			Method:     "POST",
			Request:    rec.Request,
			Confidence: ConfidenceConfirmed,
		})
	}
	if len(rec.Suggested) > 0 {
		out = append(out, Finding{
			Label:      fmt.Sprintf("%d more root field name(s) offered in \"did you mean\" hints", len(rec.Suggested)),
			Detail:     "The server's own suggestion text named these, but no probe confirmed them as a field. Treat each as a lead to verify rather than a schema fact.",
			Evidence:   strings.Join(rec.Suggested, ", "),
			Method:     "POST",
			Confidence: ConfidenceLikely,
		})
	}
	return out
}

// recoverRootFields probes the seed names, and every name the server suggests
// in response, until both queues are empty or budget probes have been sent. A
// name is probed at most once. Probe errors are skipped, not fatal: a single
// bad response shouldn't end the walk.
//
// Suggested names go to their own queue, which is always drained before the
// seeds. A hint is a name the server has already said is real, so it is worth
// more than an untested seed, and a long seed list must not use up the budget
// before the hints it produces are reached.
func recoverRootFields(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string, seeds []string, budget int) fieldRecovery {
	pending := append([]string(nil), seeds...)
	var hints []string
	seen := map[string]bool{}
	exists := map[string]bool{}
	suggested := map[string]bool{}
	var rec fieldRecovery

	// Each pass takes the next name: a waiting hint if there is one, otherwise
	// the next seed. The loop ends when both queues are empty or the budget is spent.
	for (len(hints) > 0 || len(pending) > 0) && rec.Probes < budget {
		if ctx.Err() != nil {
			break
		}
		var name string
		if len(hints) > 0 {
			name, hints = hints[0], hints[1:]
		} else {
			name, pending = pending[0], pending[1:]
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		res, err := postJSON(ctx, client, target, "{ "+name+" }", nil, headers)
		rec.Probes++
		if err != nil {
			continue
		}
		probe, ok := classifyFieldProbe(name, res)
		if !ok {
			continue
		}
		if probe.exists {
			exists[name] = true
			// Keep the first proving request as the finding's evidence.
			if rec.Request == nil {
				rec.Request = &res.Request
			}
		}
		// Hints are followed whether or not this probe itself proved anything;
		// only well-formed identifiers are worth a request.
		for _, s := range probe.suggested {
			if !fieldNameRe.MatchString(s) {
				continue
			}
			suggested[s] = true
			if !seen[s] {
				hints = append(hints, s)
			}
		}
	}

	rec.Exists = sortedKeys(exists)
	for _, s := range sortedKeys(suggested) {
		if !exists[s] {
			rec.Suggested = append(rec.Suggested, s)
		}
	}
	return rec
}

// classifyFieldProbe reads one `{ name }` response. It reports exists when the
// response resolved the name as a field, or returned one of the errors only a
// real field produces, and it collects any names in a "did you mean" hint. The
// boolean is false when the body isn't a GraphQL response at all.
func classifyFieldProbe(name string, res *httpResult) (fieldProbe, bool) {
	env, ok := parseEnvelope(res.Body)
	if !ok {
		return fieldProbe{}, false
	}
	var out fieldProbe
	// A successful probe answers under the field's own key. Requiring that key,
	// rather than any "data", keeps a JSON API that wraps everything in a data
	// envelope from reading as a field for every name.
	if dataHasKey(env.Data, name) {
		out.exists = true
	}
	raw := rawErrorText(env)
	lower := strings.ToLower(raw)
	for _, marker := range existenceMarkers {
		if strings.Contains(lower, marker) {
			out.exists = true
		}
	}
	for _, sentence := range suggestionRe.FindAllString(raw, -1) {
		for _, m := range suggestionNameRe.FindAllStringSubmatch(sentence, -1) {
			if m[1] != name {
				out.suggested = append(out.suggested, m[1])
			}
		}
	}
	return out, true
}

// rawErrorText joins every error message in env with their original casing
// intact. Suggestion names are case-sensitive, unlike errorText's lowercase.
func rawErrorText(env gqlEnvelope) string {
	msgs := make([]string, len(env.Errors))
	for i, e := range env.Errors {
		msgs[i] = e.Message
	}
	return strings.Join(msgs, " | ")
}

// dataHasKey reports whether raw is a JSON object with a key named key.
func dataHasKey(raw []byte, key string) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// sortedKeys returns a set's members in sorted order, so output is stable across runs.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
