package graphqlenum

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// alternateGraphQLPaths are the locations a GraphQL endpoint is commonly
// mounted at besides /graphql itself -- versioned API prefixes, the gql/graph
// short forms, and the PHP and bare "query" variants. They're only tried after
// the requested URL fails to answer as GraphQL, so an endpoint that is already
// correct never pays for them. Kept in step with apienum's graphqlPaths.
var alternateGraphQLPaths = []string{
	"/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/api/v1/graphql", "/api/v2/graphql",
	"/graphql/v1", "/graphql/api", "/gql", "/api/gql", "/graph", "/api/graph", "/query", "/graphql.php",
}

// findAlternateEndpoint tries each alternate path under the requested URL's
// origin, and under its parent directory when it has one, skipping the path it
// already tried. The first one that answers the universal query with a typed
// data object wins. It returns that endpoint and its response.
func findAlternateEndpoint(ctx context.Context, client *http.Client, target *url.URL, headers map[string]string) (*url.URL, *httpResult, bool) {
	origin := target.Scheme + "://" + target.Host
	bases := []string{origin}
	if parent := parentPath(target.Path); parent != "" {
		bases = append(bases, origin+parent)
	}

	tried := map[string]bool{target.Path: true}
	for _, base := range bases {
		for _, p := range alternateGraphQLPaths {
			// Stop as soon as the run is cancelled rather than sending the rest.
			if ctx.Err() != nil {
				return nil, nil, false
			}
			candidate := strings.TrimRight(base, "/") + p
			u, err := url.Parse(candidate)
			if err != nil || tried[u.Path] {
				continue
			}
			tried[u.Path] = true

			res, err := postJSON(ctx, client, u, "{__typename}", nil, headers)
			if err != nil {
				continue
			}
			// The same confirmation rule as the requested URL (see
			// confirmFromResponse): a typed data object, or -- for an endpoint
			// that refuses the probe query -- a GraphQL-shaped error response.
			// A JSON API that answers every POST with its own data envelope, or
			// with a non-GraphQL error, satisfies neither.
			if _, ok := confirmFromResponse(res); ok {
				return u, res, true
			}
		}
	}
	return nil, nil, false
}

// parentPath returns the directory above p with no trailing slash -- "/shop" for
// "/shop/gql" -- or "" when p has no parent worth searching (the root, or a
// single segment).
func parentPath(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	dir := path.Dir(p)
	if dir == "/" || dir == "." {
		return ""
	}
	return dir
}
