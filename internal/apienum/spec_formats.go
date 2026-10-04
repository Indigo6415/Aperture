package apienum

import (
	"encoding/xml"
	"net/url"
	"regexp"
	"strings"
)

// wadlApplication mirrors the parts of a WADL document this package reads.
// XMLName makes Unmarshal reject any document whose root isn't <application>.
type wadlApplication struct {
	XMLName   xml.Name        `xml:"application"`
	Methods   []wadlMethod    `xml:"method"`
	Resources []wadlResources `xml:"resources"`
}

// wadlResources is one <resources base="..."> block, whose base URL prefixes
// every resource inside it.
type wadlResources struct {
	Base      string         `xml:"base,attr"`
	Resources []wadlResource `xml:"resource"`
}

// wadlResource is one <resource path="..."> with its own parameters, methods,
// and nested resources.
type wadlResource struct {
	Path      string         `xml:"path,attr"`
	Params    []wadlParam    `xml:"param"`
	Methods   []wadlMethod   `xml:"method"`
	Resources []wadlResource `xml:"resource"`
}

// wadlMethod is one <method>. A method defined once at application level is
// referenced from a resource by href="#id".
type wadlMethod struct {
	ID     string      `xml:"id,attr"`
	Name   string      `xml:"name,attr"`
	Href   string      `xml:"href,attr"`
	Params []wadlParam `xml:"request>param"`
}

// wadlParam is one <param>. Style says where it goes: template (a path
// placeholder), query, header, or plain (a body field on a write method).
type wadlParam struct {
	Name  string `xml:"name,attr"`
	Style string `xml:"style,attr"`
	Type  string `xml:"type,attr"`
}

// parseWADL reads a WADL document into routes, one per resource, each carrying
// its methods and parameters. It returns kind "wadl" on success, or "" when the
// body isn't an application document with at least one resource.
func parseWADL(body []byte) ([]Route, string) {
	var app wadlApplication
	if err := xml.Unmarshal(body, &app); err != nil {
		return nil, ""
	}
	shared := map[string]wadlMethod{}
	for _, m := range app.Methods {
		if m.ID != "" {
			shared[m.ID] = m
		}
	}
	var routes []Route
	for _, rs := range app.Resources {
		base := pathOfURL(rs.Base)
		for _, r := range rs.Resources {
			routes = append(routes, wadlRoutes(base, r, shared)...)
		}
	}
	if len(routes) == 0 {
		return nil, ""
	}
	return routes, "wadl"
}

// wadlRoutes turns one resource, and recursively every resource nested under
// it, into Routes. Each nested resource's path extends its parent's.
func wadlRoutes(prefix string, r wadlResource, shared map[string]wadlMethod) []Route {
	full := joinPath(prefix, r.Path)
	route := Route{ID: routeID("spec", full), Path: full, Group: pathGroup(full), Source: "spec", Confirmed: true}

	var params []Param
	for _, p := range r.Params {
		if param, ok := wadlParamOf(p); ok {
			params = append(params, param)
		}
	}
	for _, m := range r.Methods {
		// A reference to an application-level method takes that method's own name and params.
		if m.Href != "" {
			if def, ok := shared[strings.TrimPrefix(m.Href, "#")]; ok {
				m.Name, m.Params = def.Name, def.Params
			}
		}
		if m.Name == "" {
			continue
		}
		route.Methods = append(route.Methods, MethodProbe{Method: strings.ToUpper(m.Name), Allowed: true})
		for _, p := range m.Params {
			if param, ok := wadlParamOf(p); ok {
				params = append(params, param)
			}
		}
	}
	route.Params = mergeParams(nil, params)

	routes := []Route{route}
	for _, child := range r.Resources {
		routes = append(routes, wadlRoutes(full, child, shared)...)
	}
	return routes
}

// wadlParamOf converts one WADL parameter to a Param. It returns false for a
// style this package doesn't model.
func wadlParamOf(p wadlParam) (Param, bool) {
	if p.Name == "" {
		return Param{}, false
	}
	var loc ParamLocation
	switch p.Style {
	case "template":
		loc = LocationPath
	case "query":
		loc = LocationQuery
	case "header":
		loc = LocationHeader
	case "plain":
		loc = LocationBody
	default:
		return Param{}, false
	}
	typeGuess := "free-text"
	switch {
	case strings.Contains(p.Type, "int"), strings.Contains(p.Type, "long"), strings.Contains(p.Type, "decimal"), strings.Contains(p.Type, "double"):
		typeGuess = "numeric-id"
	case strings.Contains(p.Type, "boolean"):
		typeGuess = "boolean"
	}
	return flagParam(Param{Name: p.Name, Location: loc, TypeGuess: typeGuess}), true
}

// ramlResourcePattern matches a RAML resource key such as "/users/{id}:" at any
// indentation. The captured indent tells the parser how deeply it's nested.
var ramlResourcePattern = regexp.MustCompile(`^(\s*)(/[^:\s]*):\s*$`)

// ramlMethodPattern matches a RAML method key under a resource.
var ramlMethodPattern = regexp.MustCompile(`^(\s*)(get|post|put|patch|delete|head|options|trace|connect):\s*(#.*)?$`)

// ramlBaseURIPattern matches the top-level baseUri declaration.
var ramlBaseURIPattern = regexp.MustCompile(`^baseUri:\s*(\S+)`)

// parseRAML reads a RAML 1.0 API definition into routes. RAML is indentation-
// scoped, so this walks the lines with a stack of open resources rather than a
// YAML parser: a resource key opens a level, a method key attaches to the
// innermost open resource, and a child resource's path extends its parent's.
//
// Only the "#%RAML" header is accepted as proof of format, so an HTML page that
// happens to contain a "/x:" line can't pass for one. The result is kind "raml",
// or "" when no resources were found.
func parseRAML(body []byte) ([]Route, string) {
	text := string(body)
	if !strings.HasPrefix(strings.TrimSpace(text), "#%RAML") {
		return nil, ""
	}

	base := ""
	var routes []Route
	// frame is one open resource: its indent, its full path, and where its route sits.
	type frame struct {
		indent int
		full   string
		idx    int
	}
	var stack []frame

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if m := ramlBaseURIPattern.FindStringSubmatch(line); m != nil && indent == 0 {
			base = pathOfURL(m[1])
			continue
		}

		if m := ramlResourcePattern.FindStringSubmatch(line); m != nil {
			// A resource at this indent or deeper closes the resources above it.
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				stack = stack[:len(stack)-1]
			}
			prefix := base
			if len(stack) > 0 {
				prefix = stack[len(stack)-1].full
			}
			full := joinPath(prefix, m[2])
			routes = append(routes, Route{ID: routeID("spec", full), Path: full, Group: pathGroup(full), Source: "spec", Confirmed: true})
			stack = append(stack, frame{indent: indent, full: full, idx: len(routes) - 1})
			continue
		}

		if m := ramlMethodPattern.FindStringSubmatch(line); m != nil && len(stack) > 0 {
			// A method belongs to the innermost resource above it, so anything
			// at or past its indent is a sibling that has already closed.
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				continue
			}
			idx := stack[len(stack)-1].idx
			routes[idx].Methods = append(routes[idx].Methods, MethodProbe{Method: strings.ToUpper(m[2]), Allowed: true})
		}
	}
	if len(routes) == 0 {
		return nil, ""
	}
	return routes, "raml"
}

// joinPath joins a path prefix and a relative segment with exactly one slash
// between them, and always returns a path starting with "/". An empty prefix or
// segment contributes nothing.
func joinPath(prefix, rel string) string {
	p := strings.TrimSuffix(prefix, "/")
	r := strings.TrimPrefix(rel, "/")
	if r == "" {
		if p == "" {
			return "/"
		}
		return p
	}
	return p + "/" + r
}

// pathOfURL returns the path of a base URL with any trailing slash removed --
// "/api/v1" for "https://host/api/v1/" and for "/api/v1/" alike. A value that
// doesn't parse yields "".
func pathOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(u.Path, "/")
}
