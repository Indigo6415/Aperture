package probescan

import (
	"context"
	"regexp"
)

// apiEndpointChecks ports api.py's CHECKS table (GraphQL, REST roots,
// sensitive REST paths, debug/trace endpoints, JSON-RPC) and adds the
// framework debug and health endpoints that are common on exposed hosts.
// Each check parses the shape its endpoint should return: a substring such as
// "ok" or "data" matches too much on an ordinary page, so these do not use one.
var apiEndpointChecks = []pathCheck{
	// A GraphQL server answers a bare GET with a JSON envelope holding data or errors.
	{"/graphql", "GraphQL endpoint", validJSONKeys("data", "errors")},
	{"/graphiql", "GraphiQL interface", containsAny("graphiql")},
	{"/playground", "GraphQL playground", containsAll("graphql", "playground")},
	{"/api/graphql", "GraphQL endpoint", validJSONKeys("data", "errors")},
	{"/api", "API root", validJSONBody},
	{"/api/v1", "API v1 root", validJSONBody},
	{"/api/v2", "API v2 root", validJSONBody},
	{"/api/v3", "API v3 root", validJSONBody},
	{"/rest", "REST API root", validJSONBody},
	{"/rest/v1", "REST API v1 root", validJSONBody},
	{"/api/v1/users", "User list endpoint", validJSONBody},
	{"/api/v1/admin", "Admin API endpoint", validJSONBody},
	{"/api/v1/config", "Config API endpoint", validJSONBody},
	{"/api/v1/keys", "API keys endpoint", validJSONBody},
	{"/api/v1/secrets", "Secrets endpoint", validJSONBody},
	{"/api/v1/tokens", "Tokens endpoint", validJSONBody},
	{"/api/v1/credentials", "Credentials endpoint", validJSONBody},
	{"/api/v1/logs", "Logs endpoint", validJSONBody},
	{"/api/v1/debug", "Debug endpoint", validJSONBody},
	{"/api/v1/env", "Environment API endpoint", validJSONBody},
	{"/api/v2/users", "User list endpoint", validJSONBody},
	{"/api/v2/admin", "Admin API endpoint", validJSONBody},
	{"/api/debug", "API debug endpoint", validJSONBody},
	{"/api/test", "API test endpoint", validJSONBody},
	{"/api/health", "API health endpoint", validHealthBody},
	{"/api/v1/health", "API health endpoint", validHealthBody},
	{"/api/status", "API status endpoint", validHealthBody},
	{"/api/info", "API info endpoint", validJSONBody},
	{"/api/version", "API version endpoint", validJSONBody},
	{"/api/env", "API environment endpoint", validJSONBody},
	{"/api/config", "API config endpoint", validJSONBody},
	{"/api/user", "User endpoint", validJSONBody},
	{"/api/me", "Current user endpoint", validJSONBody},
	{"/api/profile", "Profile endpoint", validJSONBody},
	{"/api/users", "User list endpoint", validJSONBody},
	{"/api/admin", "Admin API endpoint", validJSONBody},
	{"/api/keys", "API keys endpoint", validJSONBody},
	{"/api/tokens", "Tokens endpoint", validJSONBody},
	{"/api/secrets", "Secrets endpoint", validJSONBody},
	{"/api/logs", "Logs endpoint", validJSONBody},
	{"/healthz", "Health check endpoint", validHealthBody},
	{"/readyz", "Readiness check endpoint", validHealthBody},
	// Go's expvar page: a JSON object carrying the command line and memory stats.
	{"/debug/vars", "Go expvar debug endpoint", validJSONKeys("cmdline", "memstats")},
	{"/rpc", "JSON-RPC endpoint", validJSONKeys("jsonrpc")},
	{"/jsonrpc", "JSON-RPC endpoint", validJSONKeys("jsonrpc")},
	{"/api/rpc", "JSON-RPC endpoint", validJSONKeys("jsonrpc")},
}

// graphQLIntrospectionData matches the introspection payload's data member: a
// "__schema" key followed by an object. A bare "__schema" word in an error
// message, which a server returns when introspection is off, does not match.
var graphQLIntrospectionData = regexp.MustCompile(`"__schema"\s*:\s*\{`)

// apiEndpointsModule ports modules/api.py, including its separate GraphQL
// introspection probe (a POST carrying an introspection query, checked
// against /graphql, /api/graphql, /graphiql regardless of whether the plain
// GET check above already found something there).
var apiEndpointsModule = moduleDef{
	id:       "api_endpoints",
	name:     "API Endpoints",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		findings := runPathChecks(ctx, c, t.URL, apiEndpointChecks, false, "accessible at")

		introspection := []byte(`{"query": "{__schema { queryType { name } } }"}`)
		for _, path := range []string{"/graphql", "/api/graphql", "/graphiql"} {
			url := t.URL + path
			r, err := c.post(ctx, url, "application/json", introspection)
			// Only a JSON answer whose data holds a __schema object proves
			// introspection ran; the word alone can appear in an error.
			if err == nil && r.StatusCode == 200 && !looksHTML(r) && graphQLIntrospectionData.MatchString(r.Text) && !c.isCatchAll(r) {
				findings = append(findings, Finding{
					Label: "GraphQL introspection enabled at " + url, URL: url, Method: "POST", StatusCode: r.StatusCode,
					Detail:  "POSTed a `{ __schema { queryType { name } } }` introspection query; the response's body echoed back schema data instead of rejecting it",
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    string(introspection),
				})
			}
		}
		return findings
	},
}
