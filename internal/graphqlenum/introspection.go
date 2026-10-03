package graphqlenum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// typeRefFragment requests a type reference six wrappers deep -- enough for
// any realistic nesting of NON_NULL/LIST (e.g. "[[Int!]!]!"); GraphQL
// schemas deeper than that are vanishingly rare and every introspection
// client in common use (graphiql, Apollo, InQL) hits the same limit.
const typeRefFragment = `
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}`

// introspectionQuery is the standard, modern introspection query (compare
// hacktricks's version, which still carries the pre-2015 onOperation/
// onFragment/onField directive fields it notes as "often needs to be
// deleted to run" -- this one is written without them so it doesn't hit
// that problem on any current server in the first place).
const introspectionQuery = `
query ApertureIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args { ...InputValue }
        type { ...TypeRef }
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}
fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}` + typeRefFragment

// introspectionQueryCompact is the same query with all insignificant
// whitespace collapsed to single spaces -- some introspection-blocking
// middleware matches a literal substring like "__schema {" and the
// formatted query above already happens to dodge that, so this compact
// form is what actually gets sent as the naive first attempt.
var introspectionQueryCompact = collapseWhitespace(introspectionQuery)

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// introspectionNewlineBypass is the compact query with a newline forced in
// right after "__schema" -- the documented bypass for a WAF/regex rule
// that blocks the literal substring "__schema{" or "__schema " without
// accounting for GraphQL treating a newline the same as any other
// insignificant whitespace there. See hacktricks's "Bypassing GraphQL
// introspection defences".
var introspectionNewlineBypass = strings.Replace(introspectionQueryCompact, "__schema {", "__schema\n{", 1)

// --- introspection response shape ---

type introSchema struct {
	QueryType        *introNamedRef   `json:"queryType"`
	MutationType     *introNamedRef   `json:"mutationType"`
	SubscriptionType *introNamedRef   `json:"subscriptionType"`
	Types            []introType      `json:"types"`
	Directives       []introDirective `json:"directives"`
}

type introNamedRef struct {
	Name string `json:"name"`
}

type introDirective struct {
	Name string `json:"name"`
}

type introType struct {
	Kind        string       `json:"kind"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Fields      []introField `json:"fields"`
}

type introField struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	IsDeprecated bool          `json:"isDeprecated"`
	Args         []introArg    `json:"args"`
	Type         *introTypeRef `json:"type"`
}

type introArg struct {
	Name string        `json:"name"`
	Type *introTypeRef `json:"type"`
}

// introTypeRef is naturally recursive via OfType -- how deep it actually
// unmarshals is bounded by typeRefFragment's own nesting, not by this type.
type introTypeRef struct {
	Kind   string        `json:"kind"`
	Name   string        `json:"name"`
	OfType *introTypeRef `json:"ofType"`
}

// render turns a type reference back into GraphQL's own shorthand, e.g.
// "[Episode!]!" -- how every client-facing summary in this package
// displays a field or argument's type.
func (t *introTypeRef) render() string {
	if t == nil {
		return ""
	}
	switch t.Kind {
	case "NON_NULL":
		return t.OfType.render() + "!"
	case "LIST":
		return "[" + t.OfType.render() + "]"
	default:
		return t.Name
	}
}

// --- public schema summary ---

// FieldSummary is one query/mutation/subscription root field, or one
// argument rendered as a single "name: Type" string.
type FieldSummary struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Args         []string `json:"args,omitempty"`
	ReturnType   string   `json:"returnType,omitempty"`
	IsDeprecated bool     `json:"isDeprecated,omitempty"`
}

// TypeSummary is one browsable entry in Schema.Types -- deliberately just
// a name/kind/field count rather than every field, so a schema with
// hundreds of types stays a skimmable list; the operator drills into the
// three root field lists (Queries/Mutations/Subscriptions) for the actual
// call shapes.
type TypeSummary struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
	FieldCount  int    `json:"fieldCount"`
}

// maxSchemaEntries caps how many root fields/types this package reports --
// a pathologically large federated schema can carry thousands of types;
// past this point the summary is still representative, just not
// exhaustive, and the operator has the introspection technique/query on
// hand to pull the rest with a dedicated tool (InQL, GraphQL Voyager) if
// they need the whole thing.
const maxSchemaEntries = 500

// Schema is the reconstructed schema this run's introspection query
// returned -- present only when some technique got introspection to run
// (see Result.Schema).
type Schema struct {
	// Via names which technique unlocked introspection -- "standard",
	// "compact", "newline-bypass", "get", or "form-urlencoded" -- so the
	// operator knows whether this needed a bypass at all.
	Via              string         `json:"via"`
	QueryType        string         `json:"queryType,omitempty"`
	MutationType     string         `json:"mutationType,omitempty"`
	SubscriptionType string         `json:"subscriptionType,omitempty"`
	TypeCount        int            `json:"typeCount"`
	Queries          []FieldSummary `json:"queries"`
	Mutations        []FieldSummary `json:"mutations"`
	Subscriptions    []FieldSummary `json:"subscriptions"`
	Types            []TypeSummary  `json:"types"`
	// Truncated is set when Types/Queries/Mutations/Subscriptions were cut
	// off at maxSchemaEntries rather than reflecting the full schema.
	Truncated bool `json:"truncated,omitempty"`
}

// buildSchema reduces a raw introspection response into the summary shape
// the API/UI actually consumes.
func buildSchema(s *introSchema, via string) *Schema {
	byName := make(map[string]introType, len(s.Types))
	for _, t := range s.Types {
		byName[t.Name] = t
	}

	out := &Schema{Via: via}
	if s.QueryType != nil {
		out.QueryType = s.QueryType.Name
		out.Queries, out.Truncated = fieldSummaries(byName[s.QueryType.Name].Fields)
	}
	if s.MutationType != nil {
		out.MutationType = s.MutationType.Name
		var truncated bool
		out.Mutations, truncated = fieldSummaries(byName[s.MutationType.Name].Fields)
		out.Truncated = out.Truncated || truncated
	}
	if s.SubscriptionType != nil {
		out.SubscriptionType = s.SubscriptionType.Name
		var truncated bool
		out.Subscriptions, truncated = fieldSummaries(byName[s.SubscriptionType.Name].Fields)
		out.Truncated = out.Truncated || truncated
	}

	// Introspection's own "__"-prefixed meta-types (__Schema, __Type, and
	// so on) are the same on every GraphQL server and never worth showing
	// as part of *this* API's schema.
	var appTypes []introType
	for _, t := range s.Types {
		if !strings.HasPrefix(t.Name, "__") {
			appTypes = append(appTypes, t)
		}
	}
	sort.Slice(appTypes, func(i, j int) bool { return appTypes[i].Name < appTypes[j].Name })
	out.TypeCount = len(appTypes)
	if len(appTypes) > maxSchemaEntries {
		out.Truncated = true
		appTypes = appTypes[:maxSchemaEntries]
	}
	for _, t := range appTypes {
		out.Types = append(out.Types, TypeSummary{Name: t.Name, Kind: t.Kind, Description: t.Description, FieldCount: len(t.Fields)})
	}

	return out
}

func fieldSummaries(fields []introField) (out []FieldSummary, truncated bool) {
	sort.Slice(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	if len(fields) > maxSchemaEntries {
		truncated = true
		fields = fields[:maxSchemaEntries]
	}
	for _, f := range fields {
		var args []string
		for _, a := range f.Args {
			args = append(args, fmt.Sprintf("%s: %s", a.Name, a.Type.render()))
		}
		out = append(out, FieldSummary{
			Name: f.Name, Description: f.Description, Args: args,
			ReturnType: f.Type.render(), IsDeprecated: f.IsDeprecated,
		})
	}
	return out, truncated
}

// --- the introspection module itself ---

// introspectionAttempt is one way of getting the introspection query past
// the server (and past anything sitting in front of it). Every attempt is
// independent -- unlike bypass403's short-circuit-on-first-block posture,
// there's real value in knowing *which* techniques work, not just whether
// any does, so every attempt in this list runs regardless of whether an
// earlier one already succeeded.
type introspectionAttempt struct {
	id   string
	send func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*httpResult, error)
}

var introspectionAttempts = []introspectionAttempt{
	{id: "standard", send: func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*httpResult, error) {
		return postJSON(ctx, client, target, introspectionQuery, nil, headers)
	}},
	{id: "compact", send: func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*httpResult, error) {
		return postJSON(ctx, client, target, introspectionQueryCompact, nil, headers)
	}},
	{id: "newline-bypass", send: func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*httpResult, error) {
		return postJSON(ctx, client, target, introspectionNewlineBypass, nil, headers)
	}},
	{id: "get", send: func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*httpResult, error) {
		return getQuery(ctx, client, target, introspectionQueryCompact, headers, maxIntrospectionBytes)
	}},
	{id: "form-urlencoded", send: func(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*httpResult, error) {
		return postForm(ctx, client, target, introspectionQueryCompact, headers)
	}},
}

// runIntrospectionModule tries every introspectionAttempts technique (the
// plain request first, then the documented ways of getting past something
// that specifically blocks it) and, for whichever ones succeed, parses the
// full schema. It returns both the module's findings and the reconstructed
// Schema from the first attempt that worked -- unlike every other module
// here, this one's real output isn't the findings list but Result.Schema,
// so it's called directly from Run instead of through registeredModules'
// generic battery.
func runIntrospectionModule(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) ([]Finding, *Schema) {
	var findings []Finding
	var schema *Schema

	for _, attempt := range introspectionAttempts {
		res, err := attempt.send(ctx, client, target, headers)
		if err != nil {
			continue
		}
		env, ok := parseEnvelope(res.Body)
		if !ok || !env.hasData() {
			continue
		}
		var wrapper struct {
			Schema *introSchema `json:"__schema"`
		}
		if err := json.Unmarshal(env.Data, &wrapper); err != nil || wrapper.Schema == nil {
			continue
		}

		built := buildSchema(wrapper.Schema, attempt.id)
		findings = append(findings, Finding{
			Label:      fmt.Sprintf("Introspection succeeded via %s", describeAttempt(attempt.id)),
			Detail:     fmt.Sprintf("Full schema recovered: %d application type(s), %d root quer%s, %d mutation(s), %d subscription(s).", built.TypeCount, len(built.Queries), plural(len(built.Queries), "y", "ies"), len(built.Mutations), len(built.Subscriptions)),
			Evidence:   introspectionEvidence(built),
			Method:     methodFor(attempt.id),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		})
		if schema == nil {
			schema = built
		}
	}

	return findings, schema
}

func describeAttempt(id string) string {
	switch id {
	case "standard":
		return "a standard formatted query"
	case "compact":
		return "a whitespace-collapsed query (bypasses a naive \"__schema {\" substring filter)"
	case "newline-bypass":
		return "a query with a newline forced after __schema (bypasses a regex anchored on that exact substring)"
	case "get":
		return "a GET request (bypasses a check that only inspects POST bodies)"
	case "form-urlencoded":
		return "a form-urlencoded POST body (bypasses a check that only inspects application/json bodies)"
	default:
		return id
	}
}

func methodFor(attemptID string) string {
	if attemptID == "get" {
		return "GET"
	}
	return "POST"
}

func introspectionEvidence(s *Schema) string {
	names := make([]string, 0, len(s.Queries))
	for _, q := range s.Queries {
		names = append(names, q.Name)
	}
	if len(names) > 15 {
		names = names[:15]
	}
	return "queries: " + strings.Join(names, ", ")
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
