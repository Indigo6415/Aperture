package apienum

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// wadlFixture: one application-level method referenced by href, a nested
// resource with a path parameter, and a query parameter on a method.
const wadlFixture = `<?xml version="1.0"?>
<application xmlns="http://wadl.dev.java.net/2009/02">
  <method id="listUsers" name="GET"/>
  <resources base="https://api.example.com/api/v1">
    <resource path="users">
      <method href="#listUsers"/>
      <resource path="{id}">
        <param name="id" style="template" type="xs:int"/>
        <method name="DELETE"/>
        <method name="GET">
          <request><param name="fields" style="query" type="xs:string"/></request>
        </method>
      </resource>
    </resource>
  </resources>
</application>`

// TestParseWADL checks the WADL reader: base path from the resources element,
// application-level method references, nested resources, and typed params.
func TestParseWADL(t *testing.T) {
	routes, kind := parseWADL([]byte(wadlFixture))
	if kind != "wadl" {
		t.Fatalf("kind = %q, want wadl", kind)
	}
	byPath := map[string]Route{}
	for _, r := range routes {
		byPath[r.Path] = r
	}
	users, ok := byPath["/api/v1/users"]
	if !ok {
		t.Fatalf("missing /api/v1/users in %v", keys(byPath))
	}
	if len(users.Methods) != 1 || users.Methods[0].Method != "GET" {
		t.Errorf("/api/v1/users methods = %+v, want GET via the href", users.Methods)
	}
	item, ok := byPath["/api/v1/users/{id}"]
	if !ok {
		t.Fatalf("missing nested /api/v1/users/{id} in %v", keys(byPath))
	}
	var sawDelete, sawGet bool
	for _, m := range item.Methods {
		sawDelete = sawDelete || m.Method == "DELETE"
		sawGet = sawGet || m.Method == "GET"
	}
	if !sawDelete || !sawGet {
		t.Errorf("nested methods = %+v, want GET and DELETE", item.Methods)
	}
	var idParam, fieldsParam *Param
	for i := range item.Params {
		switch item.Params[i].Name {
		case "id":
			idParam = &item.Params[i]
		case "fields":
			fieldsParam = &item.Params[i]
		}
	}
	if idParam == nil || idParam.Location != LocationPath || idParam.TypeGuess != "numeric-id" {
		t.Errorf("id param = %+v, want a numeric path param", idParam)
	}
	if fieldsParam == nil || fieldsParam.Location != LocationQuery {
		t.Errorf("fields param = %+v, want a query param", fieldsParam)
	}
}

// TestParseWADLRejectsOtherXML: a well-formed XML document that isn't a WADL
// application must not be read as one.
func TestParseWADLRejectsOtherXML(t *testing.T) {
	if routes, kind := parseWADL([]byte(`<html><body>not wadl</body></html>`)); kind != "" || routes != nil {
		t.Errorf("non-WADL XML parsed as %q with %d routes", kind, len(routes))
	}
}

// ramlFixture: baseUri carries a path, a nested resource sits under another, and
// methods appear at several depths.
const ramlFixture = `#%RAML 1.0
title: Sample
baseUri: https://api.example.com/v1
/users:
  get:
    description: list users
  post:
  /{userId}:
    get:
    delete:
/orders:
  get:
`

// TestParseRAML checks the RAML reader: baseUri path prefix, nesting by
// indentation, and methods attached to the right resource.
func TestParseRAML(t *testing.T) {
	routes, kind := parseRAML([]byte(ramlFixture))
	if kind != "raml" {
		t.Fatalf("kind = %q, want raml", kind)
	}
	want := map[string][]string{
		"/v1/users":          {"GET", "POST"},
		"/v1/users/{userId}": {"GET", "DELETE"},
		"/v1/orders":         {"GET"},
	}
	got := map[string][]string{}
	for _, r := range routes {
		var ms []string
		for _, m := range r.Methods {
			ms = append(ms, m.Method)
		}
		got[r.Path] = ms
	}
	for path, methods := range want {
		if strings.Join(got[path], ",") != strings.Join(methods, ",") {
			t.Errorf("%s methods = %v, want %v (all: %v)", path, got[path], methods, got)
		}
	}
}

// TestParseRAMLNeedsHeader: a page that happens to contain a resource-looking
// line must not be read as RAML without the "#%RAML" header.
func TestParseRAMLNeedsHeader(t *testing.T) {
	if _, kind := parseRAML([]byte("<html>\n/users:\n  get:\n</html>")); kind != "" {
		t.Errorf("headerless body parsed as %q", kind)
	}
}

// TestOpenAPIServerBasePathPrefixesRoutes: an OpenAPI 3 document whose server
// URL carries a path must place every route under that path.
func TestOpenAPIServerBasePathPrefixesRoutes(t *testing.T) {
	doc := map[string]any{
		"openapi": "3.0.0",
		"servers": []any{map[string]any{"url": "https://api.example.com/api/v2/"}},
		"paths": map[string]any{
			"/users": map[string]any{"get": map[string]any{}},
		},
	}
	routes, kind := parseOpenAPIDoc(doc)
	if kind != "openapi" || len(routes) != 1 {
		t.Fatalf("kind=%q routes=%d, want openapi with one route", kind, len(routes))
	}
	if routes[0].Path != "/api/v2/users" {
		t.Errorf("path = %q, want /api/v2/users", routes[0].Path)
	}
}

// TestSpecFoundFromSwaggerUILink: no spec at any direct path, but the Swagger UI
// page names one at an unusual URL. Discovery must follow the link.
func TestSpecFoundFromSwaggerUILink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/swagger-ui/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script>const ui = SwaggerUIBundle({ url: "/internal/openapi-spec.json", dom_id: "#swagger-ui" })</script>`)
		case "/internal/openapi-spec.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"openapi":"3.0.1","paths":{"/ping":{"get":{}}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	info, routes := discoverSpec(ctx, newClient(0, newLimiter(0), nil), ResolveTarget(srv.URL))
	if info == nil || !info.Found || info.Kind != "openapi" {
		t.Fatalf("spec = %+v, want an openapi spec found through the UI link", info)
	}
	if !strings.HasSuffix(info.URL, "/internal/openapi-spec.json") {
		t.Errorf("spec URL = %q", info.URL)
	}
	if len(routes) != 1 || routes[0].Path != "/ping" {
		t.Errorf("routes = %+v, want the /ping route", routes)
	}
}

// TestSpecLinkOffHostIgnored: a UI page naming a spec on another host must not be
// fetched, since discovery stays on the target.
func TestSpecLinkOffHostIgnored(t *testing.T) {
	seed := mustParseURL(t, "https://target.example.com")
	page := mustParseURL(t, "https://target.example.com/swagger-ui/")
	links := specLinksFrom(page, seed, `SwaggerUIBundle({ url: "https://evil.example.org/openapi.json" })`)
	if len(links) != 0 {
		t.Errorf("off-host spec link followed: %v", links)
	}
}

// TestJSMinesNewCallShapes covers the JS call shapes added here: a base-URL
// variable, a generic typed HTTP client, the Request constructor, sendBeacon,
// and the axios params object.
func TestJSMinesNewCallShapes(t *testing.T) {
	script := []byte("this.http.get<User[]>(`${API_URL}/users?page=1`, { params: { sort: 'name', q: 'x' } });\n" +
		"fetch(`${this.base}/orders/${id}`, { method: 'PATCH', body: JSON.stringify({ status: 1 }) });\n" +
		"new Request('/api/v2/profile', { method: 'PUT' });\n" +
		"navigator.sendBeacon('/api/telemetry');\n")
	routes := mineJS([]scriptFile{{URL: "https://app.example.com/app.js", Body: script}}, ResolveTarget("https://app.example.com"))

	byKey := map[string]Route{}
	for _, r := range routes {
		byKey[r.Methods[0].Method+" "+r.Path] = r
	}
	for _, want := range []string{"GET /users", "PATCH /orders/{id}", "PUT /api/v2/profile", "POST /api/telemetry"} {
		if _, ok := byKey[want]; !ok {
			t.Errorf("missing %q; mined %v", want, keys(byKey))
		}
	}
	if users, ok := byKey["GET /users"]; ok {
		queryNames := map[string]bool{}
		for _, p := range users.Params {
			if p.Location == LocationQuery {
				queryNames[p.Name] = true
			}
		}
		if !queryNames["page"] {
			t.Errorf("query param from the URL missing: %+v", users.Params)
		}
		if !queryNames["sort"] || !queryNames["q"] {
			t.Errorf("axios-style params missing: %+v", users.Params)
		}
	}
}

// mustParseURL parses raw for a direct call into a helper, failing the test on error.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// keys returns a map's keys for failure messages.
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
