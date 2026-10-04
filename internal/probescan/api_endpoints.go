package probescan

import "context"

func looksLikeJSON(r *httpResult) bool { return containsCase("{", "[")(r) }

// apiEndpointChecks ports api.py's CHECKS table (GraphQL, REST roots,
// sensitive REST paths, debug/trace endpoints, JSON-RPC).
var apiEndpointChecks = []pathCheck{
	{"/graphql", "GraphQL endpoint", containsAny("data", "errors")},
	{"/graphiql", "GraphiQL interface", containsAny("graphiql")},
	{"/playground", "GraphQL playground", containsAny("playground")},
	{"/api/graphql", "GraphQL endpoint", containsAny("data", "errors")},
	{"/api", "API root", looksLikeJSON},
	{"/api/v1", "API v1 root", looksLikeJSON},
	{"/api/v2", "API v2 root", looksLikeJSON},
	{"/api/v3", "API v3 root", looksLikeJSON},
	{"/rest", "REST API root", looksLikeJSON},
	{"/rest/v1", "REST API v1 root", looksLikeJSON},
	{"/api/v1/users", "User list endpoint", looksLikeJSON},
	{"/api/v1/admin", "Admin API endpoint", looksLikeJSON},
	{"/api/v1/config", "Config API endpoint", looksLikeJSON},
	{"/api/v1/keys", "API keys endpoint", looksLikeJSON},
	{"/api/v1/secrets", "Secrets endpoint", looksLikeJSON},
	{"/api/v1/tokens", "Tokens endpoint", looksLikeJSON},
	{"/api/v1/credentials", "Credentials endpoint", looksLikeJSON},
	{"/api/v1/logs", "Logs endpoint", looksLikeJSON},
	{"/api/v1/debug", "Debug endpoint", looksLikeJSON},
	{"/api/v2/users", "User list endpoint", looksLikeJSON},
	{"/api/v2/admin", "Admin API endpoint", looksLikeJSON},
	{"/api/debug", "API debug endpoint", looksLikeJSON},
	{"/api/test", "API test endpoint", looksLikeJSON},
	{"/api/health", "API health endpoint", containsAny("status", "ok")},
	{"/api/status", "API status endpoint", containsAny("status", "ok")},
	{"/api/info", "API info endpoint", looksLikeJSON},
	{"/api/version", "API version endpoint", looksLikeJSON},
	{"/api/env", "API environment endpoint", looksLikeJSON},
	{"/api/config", "API config endpoint", looksLikeJSON},
	{"/api/user", "User endpoint", looksLikeJSON},
	{"/api/me", "Current user endpoint", looksLikeJSON},
	{"/api/profile", "Profile endpoint", looksLikeJSON},
	{"/rpc", "JSON-RPC endpoint", containsAny("jsonrpc")},
	{"/jsonrpc", "JSON-RPC endpoint", containsAny("jsonrpc")},
	{"/api/rpc", "JSON-RPC endpoint", containsAny("jsonrpc")},
}

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
			if err == nil && r.StatusCode == 200 && containsCase("__schema")(r) {
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
