package apienum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// specPaths is every well-known location an OpenAPI/Swagger document (or a
// UI that links to one) turns up at in practice -- checked in order, first
// one that parses as a usable spec wins. This is JSON-only: Aperture has no
// YAML dependency, and every framework that serves a YAML spec (FastAPI,
// Springdoc, ...) serves the same document as JSON at one of these paths
// too.
var specPaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/v3/api-docs",
	"/v2/api-docs",
	"/api-docs",
	"/api-docs.json",
	"/api-docs/swagger.json",
	"/api/api-docs",
	"/api/v2/api-docs",
	"/api/v3/api-docs",
	"/api/openapi.json",
	"/api/swagger.json",
	"/api/v1/openapi.json",
	"/api/v1/swagger.json",
	"/api/v2/openapi.json",
	"/api/v2/swagger.json",
	"/api/v3/openapi.json",
	"/v1/openapi.json",
	"/v2/openapi.json",
	"/v3/openapi.json",
	"/v2/swagger.json",
	"/v3/swagger.json",
	"/.well-known/openapi.json",
	"/docs/openapi.json",
	"/docs/swagger.json",
	"/openapi/swagger.json",
	"/openapi/v3/openapi.json",
	"/swagger/swagger.json",
	"/swagger/v1/swagger.json",
	"/swagger/v2/swagger.json",
	"/swagger/v3/swagger.json",
	"/api/swagger/v1/swagger.json",
	"/api/docs/openapi.json",
	"/spec.json",
	"/api/spec.json",
}

// wadlPaths are the places a WADL (Web Application Description Language)
// document is served. The last one is the query-string form some JAX-RS
// stacks answer to, which is why it's relative to the site root rather than
// a path of its own.
var wadlPaths = []string{
	"/application.wadl",
	"/api/application.wadl",
	"/rest/application.wadl",
	"/?_wadl",
}

// ramlPaths are the places a RAML 1.0 API definition is served.
var ramlPaths = []string{
	"/api.raml",
	"/api/api.raml",
	"/api/v1/api.raml",
	"/raml/api.raml",
}

// specUIPaths are the API-documentation pages (Swagger UI, Redoc, RapiDoc, and
// the initializer scripts they load) that name their spec in a configuration
// URL. They are read only once no spec was found at a direct path, and the
// spec URLs they name are followed.
var specUIPaths = []string{
	"/swagger-ui/",
	"/swagger-ui/index.html",
	"/swagger-ui.html",
	"/swagger/index.html",
	"/swagger-initializer.js",
	"/api-docs/",
	"/api/docs",
	"/docs",
	"/redoc",
	"/rapidoc",
	"/apidocs/",
	"/api/swagger-ui.html",
}

// maxSpecLinks caps how many spec URLs named on one run's UI pages are fetched.
const maxSpecLinks = 4

// specLinkPattern finds a configuration value naming a URL -- Swagger UI's
// "url:", Redoc's and RapiDoc's spec-url="..." attribute, and "specUrl" in
// the wrappers -- in a page or script body.
var specLinkPattern = regexp.MustCompile(`(?i)(?:spec-url|specurl|url)\s*[:=]\s*["']([^"'\s]+)["']`)

// discoverSpec looks for an API description document and, on the first one that
// parses, returns both a summary (for Result.Schema) and every route the
// document itself describes -- the highest-signal source when present, so a run
// that finds one doesn't need to guess at routes the spec already answers for.
//
// Direct paths are tried first, in format order: JSON (OpenAPI/Swagger), then
// WADL, then RAML. Only when none of them answers does it read the API-docs UI
// pages and follow the spec URLs they name, so a site whose spec lives at an
// unexpected path is still found.
func discoverSpec(ctx context.Context, c *apiClient, t *Target) (*SchemaInfo, []Route) {
	for _, p := range specPaths {
		if ctx.Err() != nil {
			return nil, nil
		}
		if info, routes, ok := fetchSpec(ctx, c, t.URL+p, parseJSONSpec); ok {
			return info, routes
		}
	}
	for _, p := range wadlPaths {
		if ctx.Err() != nil {
			return nil, nil
		}
		if info, routes, ok := fetchSpec(ctx, c, t.URL+p, parseWADL); ok {
			return info, routes
		}
	}
	for _, p := range ramlPaths {
		if ctx.Err() != nil {
			return nil, nil
		}
		if info, routes, ok := fetchSpec(ctx, c, t.URL+p, parseRAML); ok {
			return info, routes
		}
	}

	seed, err := url.Parse(t.URL)
	if err != nil {
		return &SchemaInfo{Found: false}, nil
	}
	seen := map[string]bool{}
	for _, p := range specUIPaths {
		if ctx.Err() != nil {
			break
		}
		pageURL, err := url.Parse(t.URL + p)
		if err != nil {
			continue
		}
		page, err := c.get(ctx, pageURL.String())
		if err != nil || page.StatusCode != 200 {
			continue
		}
		for _, link := range specLinksFrom(pageURL, seed, page.Text) {
			if seen[link] {
				continue
			}
			seen[link] = true
			if info, routes, ok := fetchSpec(ctx, c, link, parseAnySpec); ok {
				return info, routes
			}
		}
	}
	return &SchemaInfo{Found: false}, nil
}

// fetchSpec requests one candidate document and parses it with parse. ok is
// false when the URL didn't answer 200 or parse didn't recognize the body.
func fetchSpec(ctx context.Context, c *apiClient, u string, parse func([]byte) ([]Route, string)) (*SchemaInfo, []Route, bool) {
	res, err := c.get(ctx, u)
	if err != nil || res.StatusCode != 200 {
		return nil, nil, false
	}
	routes, kind := parse(res.Body)
	if kind == "" {
		return nil, nil, false
	}
	return &SchemaInfo{Found: true, Kind: kind, URL: u, RouteCount: len(routes)}, routes, true
}

// parseJSONSpec parses an OpenAPI or Swagger JSON document.
func parseJSONSpec(body []byte) ([]Route, string) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, ""
	}
	return parseOpenAPIDoc(doc)
}

// parseAnySpec recognizes a document in whichever supported format its body
// is, for spec URLs found on a UI page where the format isn't known. RAML is
// only accepted with its "#%RAML" header, so an HTML page can't pass for one.
func parseAnySpec(body []byte) ([]Route, string) {
	trimmed := strings.TrimSpace(string(body))
	switch {
	case strings.HasPrefix(trimmed, "{"):
		return parseJSONSpec(body)
	case strings.HasPrefix(trimmed, "<"):
		return parseWADL(body)
	case strings.HasPrefix(trimmed, "#%RAML"):
		return parseRAML(body)
	}
	return nil, ""
}

// specLinksFrom returns the spec-looking URLs a UI page or script names, resolved
// against the page and limited to the target's own host, up to maxSpecLinks.
func specLinksFrom(page, seed *url.URL, body string) []string {
	var out []string
	for _, m := range specLinkPattern.FindAllStringSubmatch(body, -1) {
		if len(out) >= maxSpecLinks {
			break
		}
		if !looksLikeSpecURL(m[1]) {
			continue
		}
		resolved, err := page.Parse(m[1])
		if err != nil || !inScope(seed, resolved) {
			continue
		}
		out = append(out, resolved.String())
	}
	return out
}

// looksLikeSpecURL reports whether a configuration URL is worth fetching as an
// API description: it names one of the spec families, or ends in one of their
// file extensions.
func looksLikeSpecURL(raw string) bool {
	lower := strings.ToLower(raw)
	for _, kw := range []string{"api-docs", "openapi", "swagger", "wadl", "raml", "spec"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	for _, ext := range []string{".json", ".yaml", ".yml", ".raml", ".wadl"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// parseOpenAPIDoc extracts every path+method+parameter OpenAPI 3.x or
// Swagger 2.0 describes. Both formats share the same top-level "paths"
// object shape closely enough to parse with one pass, branching only on
// where a parameter's type lives (Swagger 2.0 puts it directly on the
// parameter; OpenAPI 3.x nests it under "schema") and where a JSON request
// body's fields live (OpenAPI 3.x's "requestBody"; Swagger 2.0 has no
// equivalent -- a body parameter there is just another entry in
// "parameters" with in: "body", already covered by the shared path).
func parseOpenAPIDoc(doc map[string]any) ([]Route, string) {
	kind := ""
	if v, ok := doc["openapi"].(string); ok && strings.HasPrefix(v, "3") {
		kind = "openapi"
	} else if v, ok := doc["swagger"].(string); ok && strings.HasPrefix(v, "2") {
		kind = "swagger"
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || kind == "" {
		return nil, ""
	}

	// The base path every route sits under: Swagger 2.0's "basePath", or the
	// path of the first OpenAPI 3.x server URL (see openAPIServerPath).
	basePath := ""
	if bp, ok := doc["basePath"].(string); ok {
		basePath = strings.TrimSuffix(bp, "/")
	}
	if kind == "openapi" {
		basePath = openAPIServerPath(doc)
	}

	var routes []Route
	// Sorted so output order is stable across runs of the same spec, rather
	// than Go's randomized map iteration order.
	rawPaths := make([]string, 0, len(paths))
	for p := range paths {
		rawPaths = append(rawPaths, p)
	}
	sort.Strings(rawPaths)

	for _, rawPath := range rawPaths {
		item, ok := paths[rawPath].(map[string]any)
		if !ok {
			continue
		}
		fullPath := basePath + rawPath
		route := Route{ID: routeID("spec", fullPath), Path: fullPath, Group: pathGroup(fullPath), Source: "spec", Confirmed: true}

		// A path-item-level "parameters" array applies to every method
		// under it (both specs agree on this) -- collected once and merged
		// into each method's own below.
		sharedParams := parseOpenAPIParams(item["parameters"])

		for _, method := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
			op, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			route.Methods = append(route.Methods, MethodProbe{Method: strings.ToUpper(method), Allowed: true})
			params := append(append([]Param{}, sharedParams...), parseOpenAPIParams(op["parameters"])...)
			params = append(params, parseRequestBodyParams(op["requestBody"])...)
			route.Params = mergeParams(route.Params, params)
		}
		if len(route.Methods) == 0 {
			continue
		}
		routes = append(routes, route)
	}
	return routes, kind
}

// openAPIServerPath returns the path of an OpenAPI 3 document's first server
// URL -- "/api/v2" for "https://host/api/v2/" -- which every path in the
// document is relative to. It returns "" when the server is the root or the
// document names none. The server URL may be a template with variables; its
// path is what matters, and that parses fine.
func openAPIServerPath(doc map[string]any) string {
	servers, _ := doc["servers"].([]any)
	if len(servers) == 0 {
		return ""
	}
	first, _ := servers[0].(map[string]any)
	raw, _ := first["url"].(string)
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(u.Path, "/")
}

// parseOpenAPIParams reads an OpenAPI/Swagger "parameters" array into
// Params, skipping an "in": "body" entry (Swagger 2.0's way of describing a
// JSON body, which doesn't carry a useful single name/type the way a query/
// path/header parameter does -- parseRequestBodyParams is OpenAPI 3.x's
// equivalent and the one actually worth enumerating field-by-field).
func parseOpenAPIParams(raw any) []Param {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []Param
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if name == "" || in == "" || in == "body" {
			continue
		}
		loc := ParamLocation(in)
		if in == "formData" {
			loc = LocationBody
		}
		typeGuess := "free-text"
		if schema, ok := m["schema"].(map[string]any); ok {
			typeGuess = guessTypeFromOpenAPIType(schema["type"])
		} else {
			typeGuess = guessTypeFromOpenAPIType(m["type"])
		}
		out = append(out, flagParam(Param{Name: name, Location: loc, TypeGuess: typeGuess}))
	}
	return out
}

// parseRequestBodyParams reads OpenAPI 3.x's "requestBody" ->
// "content" -> "application/json" -> "schema" -> "properties" into body
// Params -- the JSON-body counterpart to parseOpenAPIParams.
func parseRequestBodyParams(raw any) []Param {
	rb, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	content, ok := rb["content"].(map[string]any)
	if !ok {
		return nil
	}
	for _, mediaType := range []string{"application/json", "application/x-www-form-urlencoded"} {
		media, ok := content[mediaType].(map[string]any)
		if !ok {
			continue
		}
		schema, ok := media["schema"].(map[string]any)
		if !ok {
			continue
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			continue
		}
		var out []Param
		names := make([]string, 0, len(props))
		for n := range props {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			propSchema, _ := props[name].(map[string]any)
			out = append(out, flagParam(Param{Name: name, Location: LocationBody, TypeGuess: guessTypeFromOpenAPIType(propSchema["type"])}))
		}
		return out
	}
	return nil
}

// guessTypeFromOpenAPIType maps an OpenAPI/Swagger scalar type to the
// package's type guess.
func guessTypeFromOpenAPIType(v any) string {
	s, _ := v.(string)
	switch s {
	case "integer", "number":
		return "numeric-id"
	case "boolean":
		return "boolean"
	default:
		return "free-text"
	}
}

// routeID derives a stable, URL-safe identifier for a route so the frontend
// can key on it across streamed events without the backend handing out an
// incrementing counter.
func routeID(source, path string) string {
	return fmt.Sprintf("%s:%s", source, path)
}
