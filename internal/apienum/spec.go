package apienum

import (
	"context"
	"encoding/json"
	"fmt"
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
	"/api/openapi.json",
	"/api/swagger.json",
	"/api/v1/openapi.json",
	"/api-docs",
	"/api-docs.json",
	"/.well-known/openapi.json",
	"/docs/openapi.json",
	"/swagger/v1/swagger.json",
}

// discoverSpec checks every well-known spec path and, on the first one that
// parses as OpenAPI/Swagger, returns both a summary (for Result.Schema) and
// every route the spec itself describes -- the highest-signal source when
// present, so a run that finds one doesn't need to guess at routes the spec
// already answers for (see the package doc comment).
func discoverSpec(ctx context.Context, c *apiClient, t *Target) (*SchemaInfo, []Route) {
	for _, p := range specPaths {
		if ctx.Err() != nil {
			return nil, nil
		}
		url := t.URL + p
		res, err := c.get(ctx, url)
		if err != nil || res.StatusCode != 200 {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(res.Body, &doc); err != nil {
			continue
		}
		routes, kind := parseOpenAPIDoc(doc)
		if kind == "" {
			continue
		}
		return &SchemaInfo{Found: true, Kind: kind, URL: url, RouteCount: len(routes)}, routes
	}
	return &SchemaInfo{Found: false}, nil
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

	// basePath (Swagger 2.0) prefixes every path in the document -- OpenAPI
	// 3.x instead carries full server URLs under "servers", which are
	// already absolute and not worth re-deriving a prefix from here.
	basePath := ""
	if bp, ok := doc["basePath"].(string); ok {
		basePath = strings.TrimSuffix(bp, "/")
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
