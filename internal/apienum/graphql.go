package apienum

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
)

// graphqlPaths is every well-known location a GraphQL endpoint turns up at
// -- the same candidate list probescan's api_endpoints.go and graphqlenum's
// alternate paths check, kept in sync by hand since the packages serve
// different enough purposes (probescan reports a misconfiguration finding;
// this package wants to fold the endpoint into the unified route list) not to
// share a type.
var graphqlPaths = []string{
	"/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/api/v1/graphql", "/api/v2/graphql",
	"/graphql/v1", "/graphql/api", "/gql", "/api/gql", "/graph", "/api/graph", "/query", "/graphql.php",
	"/graphiql", "/playground", "/graphql/console",
}

// graphqlErrorRe matches the wording GraphQL servers use in their own errors. A
// response carrying a data object with __typename is confirmation on its own;
// a bare error object needs one of these phrases, since many JSON APIs answer
// with an "errors" key too.
var graphqlErrorRe = regexp.MustCompile(`(?i)(graphql|cannot query field|syntax error|must provide a query|unknown type|must have a selection|unknown argument)`)

// introspectionQuery asks for just enough to list queries/mutations with
// their arguments -- a deliberately shallow query compared to
// internal/graphqlenum's own full-schema introspection (which also walks
// every nested type), since this package only needs enough to fold GraphQL
// operations into the unified route list, not to reconstruct the schema.
const introspectionQuery = `{"query":"{__schema{queryType{name fields{name args{name}}} mutationType{name fields{name args{name}}} types{name}}}"}`

type introspectionEnvelope struct {
	Data struct {
		Schema struct {
			QueryType    *introspectionType `json:"queryType"`
			MutationType *introspectionType `json:"mutationType"`
			Types        []struct {
				Name string `json:"name"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

type introspectionType struct {
	Name   string `json:"name"`
	Fields []struct {
		Name string `json:"name"`
		Args []struct {
			Name string `json:"name"`
		} `json:"args"`
	} `json:"fields"`
}

// looksLikeGraphQLResponse reports whether a response is a GraphQL answer: a
// JSON object with a data object carrying __typename, or an error object
// worded the way GraphQL servers word their own errors. Anything else -- an
// HTML shell, a generic JSON envelope -- is not.
func looksLikeGraphQLResponse(res *apiResult) bool {
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusBadRequest {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(res.Body, &m) != nil {
		return false
	}
	if data, ok := m["data"]; ok {
		var d map[string]json.RawMessage
		if json.Unmarshal(data, &d) == nil {
			if _, hasTypename := d["__typename"]; hasTypename {
				return true
			}
		}
	}
	if errs, ok := m["errors"]; ok {
		return graphqlErrorRe.Match(errs)
	}
	return false
}

// discoverGraphQL checks every well-known GraphQL path with a universal
// "{__typename}" query (same confirmation technique as
// graphqlenum.Run -- see its doc comment for why that's the right first
// move) and, once an endpoint confirms, attempts introspection. Every
// confirmed query/mutation becomes its own synthetic POST route in the
// returned slice, with its arguments enumerated as body params -- so a
// GraphQL API shows up in the same tree the REST routes do, rather than
// being invisible to this tool entirely.
func discoverGraphQL(ctx context.Context, c *apiClient, t *Target) (*GraphQLSummary, []Route) {
	for _, p := range graphqlPaths {
		if ctx.Err() != nil {
			return nil, nil
		}
		url := t.URL + p
		res, err := c.do(ctx, http.MethodPost, url, map[string]string{"Content-Type": "application/json"}, false, []byte(`{"query":"{__typename}"}`))
		if err != nil || !looksLikeGraphQLResponse(res) {
			continue
		}
		summary := &GraphQLSummary{Found: true, URL: url}

		introRes, err := c.do(ctx, http.MethodPost, url, map[string]string{"Content-Type": "application/json"}, false, []byte(introspectionQuery))
		if err != nil {
			return summary, nil
		}
		var env introspectionEnvelope
		if err := json.Unmarshal(introRes.Body, &env); err != nil || env.Data.Schema.QueryType == nil {
			return summary, nil
		}
		summary.IntrospectionOn = true
		summary.TypeCount = len(env.Data.Schema.Types)

		var routes []Route
		if env.Data.Schema.QueryType != nil {
			for _, f := range env.Data.Schema.QueryType.Fields {
				summary.Queries = append(summary.Queries, f.Name)
				routes = append(routes, graphqlOperationRoute(url, f.Name, f.Args))
			}
		}
		if env.Data.Schema.MutationType != nil {
			for _, f := range env.Data.Schema.MutationType.Fields {
				summary.Mutations = append(summary.Mutations, f.Name)
				routes = append(routes, graphqlOperationRoute(url, f.Name, f.Args))
			}
		}
		return summary, routes
	}
	return &GraphQLSummary{Found: false}, nil
}

// graphqlOperationRoute turns one introspected query/mutation field into a
// synthetic Route -- path is the endpoint itself (every GraphQL operation
// rides the same URL), Group is the operation's own name so the tree view
// still shows one entry per operation instead of collapsing every
// query/mutation into a single "/graphql" leaf.
func graphqlOperationRoute(endpoint, opName string, args []struct {
	Name string `json:"name"`
}) Route {
	route := Route{
		ID: routeID("graphql", endpoint+"#"+opName), Path: endpoint + " (" + opName + ")",
		Group: "/graphql", Source: "graphql", Confirmed: true,
		Methods: []MethodProbe{{Method: "POST", Allowed: true}},
	}
	for _, a := range args {
		route.Params = append(route.Params, flagParam(Param{Name: a.Name, Location: LocationBody}))
	}
	return route
}
