package apienum

import (
	"net/url"
	"regexp"
	"strings"
)

// JS mining patterns -- regex-based rather than a real JS/AST parser (no
// such dependency exists in this module, and a bundled/minified file would
// defeat most of what an AST walk buys anyway): each pattern targets one
// common call shape, with a path captured as either a string literal or a
// template literal. Template-literal interpolations (`${id}`) inside a path
// are normalized into a "{id}" path-param placeholder by
// normalizeTemplatePath below, rather than discarded.
var (
	fetchCallPattern    = regexp.MustCompile("(?s)fetch\\(\\s*[`'\"]([^`'\"]+)[`'\"]\\s*(,\\s*\\{(.{0,600}?)\\})?\\s*\\)")
	axiosMethodPattern  = regexp.MustCompile("(?s)axios\\.(get|post|put|patch|delete)\\(\\s*[`'\"]([^`'\"]+)[`'\"]\\s*(,\\s*\\{(.{0,600}?)\\})?")
	axiosObjectPattern  = regexp.MustCompile(`(?s)axios\(\s*\{(.{0,600}?)\}\s*\)`)
	ajaxPattern         = regexp.MustCompile(`(?s)\$\.ajax\(\s*\{(.{0,600}?)\}\s*\)`)
	xhrOpenPattern      = regexp.MustCompile("(?i)\\.open\\(\\s*[`'\"](\\w+)[`'\"]\\s*,\\s*[`'\"]([^`'\"]+)[`'\"]")
	urlFieldPattern     = regexp.MustCompile("url\\s*:\\s*[`'\"]([^`'\"]+)[`'\"]")
	methodFieldPattern  = regexp.MustCompile(`(?i)(?:method|type)\s*:\s*['"](\w+)['"]`)
	bodyFieldPattern    = regexp.MustCompile(`(?s)(?:body|data)\s*:\s*(?:JSON\.stringify\()?\{(.{0,400}?)\}`)
	headersFieldPattern = regexp.MustCompile(`(?s)headers\s*:\s*\{(.{0,300}?)\}`)
	objectKeyPattern    = regexp.MustCompile(`['"]?([A-Za-z_$][A-Za-z0-9_\-$]*)['"]?\s*:`)
	// genericAPIPathPattern is the catch-all for a bare string literal that
	// looks like an API path even when no recognized call wraps it --
	// requires an /api/, /v1-v9/, or /graphql-style segment so this doesn't
	// match every relative asset path in the bundle.
	genericAPIPathPattern = regexp.MustCompile(`["'](/(?:api|v[1-9])[a-zA-Z0-9_\-./{}]*)["']`)
	templateVarPattern    = regexp.MustCompile(`\$\{\s*([A-Za-z_$][A-Za-z0-9_.$]*)\s*\}`)
)

// mineJS scans every downloaded script for fetch/axios/$.ajax/XHR calls and
// bare API-shaped string literals, returning one Route per distinct
// method+path it finds -- see the package doc's "JS bundle mining" goal.
// Every route from this pass starts Confirmed: false; characterize.go
// upgrades it once a live probe actually responds (see its own doc
// comment for the confirmed/uncertain split).
func mineJS(scripts []scriptFile, t *Target) []Route {
	found := map[string]*Route{}
	add := func(method, rawPath string, bodyKeys, headerKeys []string) {
		resolved := resolveJSPath(t, rawPath)
		if resolved == nil {
			return
		}
		normPath, pathParams := normalizeTemplatePath(resolved.Path)
		key := method + " " + normPath
		r, ok := found[key]
		if !ok {
			r = &Route{ID: routeID("js", key), Path: normPath, Group: pathGroup(normPath), Source: "js", Methods: []MethodProbe{{Method: method}}}
			found[key] = r
		}
		r.Params = mergeParams(r.Params, pathParams)
		for _, q := range queryParamNames(resolved.RawQuery) {
			r.Params = mergeParams(r.Params, []Param{flagParam(Param{Name: q, Location: LocationQuery})})
		}
		for _, k := range bodyKeys {
			r.Params = mergeParams(r.Params, []Param{flagParam(Param{Name: k, Location: LocationBody})})
		}
		for _, k := range headerKeys {
			r.Params = mergeParams(r.Params, []Param{flagParam(Param{Name: k, Location: LocationHeader})})
		}
	}

	for _, s := range scripts {
		text := string(s.Body)

		for _, m := range fetchCallPattern.FindAllStringSubmatch(text, -1) {
			opts := m[3]
			method := firstMatch(methodFieldPattern, opts, "GET")
			add(strings.ToUpper(method), m[1], objectKeys(bodyFieldPattern, opts), objectKeys(headersFieldPattern, opts))
		}
		for _, m := range axiosMethodPattern.FindAllStringSubmatch(text, -1) {
			opts := m[4]
			add(strings.ToUpper(m[1]), m[2], objectKeys(bodyFieldPattern, opts), objectKeys(headersFieldPattern, opts))
		}
		for _, m := range axiosObjectPattern.FindAllStringSubmatch(text, -1) {
			opts := m[1]
			path := firstMatch(urlFieldPattern, opts, "")
			if path == "" {
				continue
			}
			add(strings.ToUpper(firstMatch(methodFieldPattern, opts, "GET")), path, objectKeys(bodyFieldPattern, opts), objectKeys(headersFieldPattern, opts))
		}
		for _, m := range ajaxPattern.FindAllStringSubmatch(text, -1) {
			opts := m[1]
			path := firstMatch(urlFieldPattern, opts, "")
			if path == "" {
				continue
			}
			add(strings.ToUpper(firstMatch(methodFieldPattern, opts, "GET")), path, objectKeys(bodyFieldPattern, opts), objectKeys(headersFieldPattern, opts))
		}
		for _, m := range xhrOpenPattern.FindAllStringSubmatch(text, -1) {
			add(strings.ToUpper(m[1]), m[2], nil, nil)
		}
		for _, m := range genericAPIPathPattern.FindAllStringSubmatch(text, -1) {
			// add() dedupes on its own normalized method+path key (resolved
			// and template-normalized), which a raw match here hasn't been
			// through yet -- no need to pre-check before calling it.
			add("GET", m[1], nil, nil)
		}
	}

	routes := make([]Route, 0, len(found))
	for _, r := range found {
		routes = append(routes, *r)
	}
	return routes
}

// resolveJSPath resolves a path mined from JS (which may be a bare path,
// a relative path, or a full URL) against t, dropping anything that
// resolves off-host (see crawl.go's inScope) or that isn't resolvable at
// all (a template literal built from a runtime variable with no literal
// prefix, e.g. bare `${base}`).
func resolveJSPath(t *Target, raw string) *url.URL {
	raw = templateVarPattern.ReplaceAllString(raw, "{$1}")
	if raw == "" || strings.HasPrefix(raw, "{") {
		return nil
	}
	base, err := url.Parse(t.URL)
	if err != nil {
		return nil
	}
	resolved, err := base.Parse(raw)
	if err != nil || !inScope(base, resolved) {
		return nil
	}
	return resolved
}

// normalizeTemplatePath turns every "{name}" segment survival from
// resolveJSPath's template substitution into a path Param, returning the
// path with those segments left as-is (so routes sharing the same
// parameterized shape group together) and the params it found.
func normalizeTemplatePath(path string) (string, []Param) {
	var params []Param
	for _, m := range regexp.MustCompile(`\{([A-Za-z0-9_.$]+)\}`).FindAllStringSubmatch(path, -1) {
		name := m[1]
		if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
			name = name[idx+1:] // "user.id" -> "id": the variable's own field name is the useful part
		}
		params = append(params, flagParam(Param{Name: name, Location: LocationPath}))
	}
	return path, params
}

func queryParamNames(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	return names
}

func firstMatch(re *regexp.Regexp, text, fallback string) string {
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	return fallback
}

// objectKeys pulls every top-level "key:" out of the first object literal
// re finds inside text -- a deliberately shallow, non-nested-aware scan
// (RE2 can't balance braces), good enough to catch a flat request-body/
// headers object without needing a real parser.
func objectKeys(re *regexp.Regexp, text string) []string {
	m := re.FindStringSubmatch(text)
	if len(m) < 2 {
		return nil
	}
	var keys []string
	for _, km := range objectKeyPattern.FindAllStringSubmatch(m[1], -1) {
		keys = append(keys, km[1])
	}
	return keys
}
