package idor

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"sort"
	"strings"
)

// point is one place a request carries an object reference that a check can
// mutate: a query parameter, a path segment, a JSON or form body field, a
// cookie, or an identity header. The build* function fields describe which
// mutations the point supports -- a nil field means "not applicable here", so
// a module that needs it skips the point rather than guessing.
type point struct {
	// id is the dedupe key: two discoveries of the same place produce one point.
	id string
	// label describes the point for the progress grid and for findings.
	label string
	// where is the coarse location ("query", "path", "json", "form",
	// "cookie", "header"), shown in findings and used to gate modules.
	where string
	// kind is the inferred shape of the reference the point carries, which
	// drives neighbour generation.
	kind refKind
	// value is the reference currently in place -- the owner's own object id.
	value string
	// name is the parameter/field name for query and form points, used to form
	// an array name like "id[]". Empty for path, cookie, and header points.
	name string

	// build replaces the point's value with a single scalar string. Every
	// point supports this.
	build func(value string) requestSpec
	// buildValues sets the point to several occurrences at once, for HTTP
	// parameter pollution. Nil where repetition is meaningless (path, header).
	buildValues func(values []string) requestSpec
	// buildArrayName renames the parameter (e.g. "id" -> "id[]") and sets one
	// value, for array/type-juggling tricks. Nil outside query/form points.
	buildArrayName func(name, value string) requestSpec
	// buildJSON sets a JSON leaf to an arbitrary JSON value (an array, an
	// object, a number), for type-juggling and NoSQL-operator payloads. Nil
	// unless the point is a JSON body leaf.
	buildJSON func(v any) requestSpec
}

// commonIDParams are query-parameter names that frequently select an object by
// id. They are tried on the seed even when it does not carry them (seeded with
// the value "1"), the same way openredirect and pathtraversal try their own
// common parameter lists. Parameter mining adds to this set at runtime.
var commonIDParams = []string{
	"id", "user_id", "userid", "uid", "account_id", "account", "customer_id",
	"order_id", "order", "invoice_id", "invoice", "doc_id", "document_id",
	"file_id", "object_id", "item_id", "profile_id", "group_id", "team_id",
	"org_id", "project_id", "ticket_id", "message_id", "post_id", "comment_id",
	"ref", "key", "no", "num", "pid", "gid", "oid",
}

// identityHeaders are request headers some apps trust to carry the caller's
// identity -- tampering with them is a direct IDOR vector (ask for another
// user's data by changing X-User-Id). They are seeded with "1" and tested
// alongside any the operator already sends.
var identityHeaders = []string{
	"X-User-Id", "X-User", "X-Account-Id", "X-Customer-Id", "X-Org-Id",
	"X-Tenant-Id", "X-Profile-Id", "X-Owner-Id", "X-Impersonate-User",
}

// maxBodyFields caps how many JSON leaves or form fields of a body become
// points, so a large document does not turn into thousands of probes.
const maxBodyFields = 40

// discover builds every identity point from the seed request: its query
// parameters, path segments, request body, cookies, and identity headers,
// plus the common id-parameter names and any mined parameters folded into
// extraParams. Only places that look like they carry an object reference
// become points.
func discover(seed *url.URL, base requestSpec, body, contentType string, extraParams []string, setCookies []string) []point {
	var out []point
	out = append(out, queryPoints(seed, base, extraParams)...)
	out = append(out, pathPoints(seed, base)...)
	out = append(out, bodyPoints(base, body, contentType)...)
	out = append(out, cookiePoints(base, setCookies)...)
	out = append(out, headerPoints(base)...)
	return dedupePoints(out)
}

// queryPoints returns one point per query parameter that carries a reference,
// plus one per common/mined id-parameter name the seed does not already have
// (seeded with "1"). The seed keeps its method and body, so a POST endpoint is
// still tested through its query string.
func queryPoints(seed *url.URL, base requestSpec, extraParams []string) []point {
	existing := seed.Query()
	var out []point

	// Parameters the seed already carries: tested only when the value or the
	// name looks like an object reference.
	names := make([]string, 0, len(existing))
	for k := range existing {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, key := range names {
		val := existing.Get(key)
		kind, ok := classify(val)
		// A name like "user_id" makes the parameter a point even when its
		// value is empty or does not classify; it is then treated as numeric.
		if !ok {
			if !nameLooksLikeID(key) {
				continue
			}
			kind, val = kindNumeric, firstNonEmpty(val, "1")
		}
		out = append(out, queryPoint(seed, base, key, val, kind, false))
	}

	// Common and mined id-parameter names the seed does not have: added to the
	// query with a seed value of "1", to surface endpoints that accept a hidden
	// id the UI never sends.
	seen := map[string]bool{}
	for k := range existing {
		seen[strings.ToLower(k)] = true
	}
	for _, key := range append(appendTrimmed(nil, extraParams), commonIDParams...) {
		if key == "" || seen[strings.ToLower(key)] {
			continue
		}
		seen[strings.ToLower(key)] = true
		out = append(out, queryPoint(seed, base, key, "1", kindNumeric, true))
	}
	return out
}

// queryPoint builds a point for one query parameter. injected marks a
// parameter added by the scan (not present on the seed), so the label can say
// so. The build functions rewrite only this parameter and leave the rest of
// the query byte-stable via url.Values.
func queryPoint(seed *url.URL, base requestSpec, key, value string, kind refKind, injected bool) point {
	label := fmt.Sprintf("query parameter %q", key)
	// An injected parameter is called out, since a finding on it means the app
	// honoured an id the client was never meant to send.
	if injected {
		label = fmt.Sprintf("injected query parameter %q", key)
	}
	// withQuery rebuilds the URL with key set to the given raw pairs and every
	// other parameter preserved.
	withQuery := func(pairs []string) requestSpec {
		others := url.Values{}
		for k, vs := range seed.Query() {
			if k == key {
				continue
			}
			others[k] = append([]string(nil), vs...)
		}
		u := *seed
		u.RawQuery = joinQuery(others.Encode(), pairs)
		spec := base
		spec.URL = u.String()
		spec.Headers = cloneHeaders(base.Headers)
		return spec
	}
	return point{
		id:    "query|" + key,
		label: label,
		where: "query",
		kind:  kind,
		value: value,
		name:  key,
		build: func(v string) requestSpec {
			return withQuery([]string{url.QueryEscape(key) + "=" + url.QueryEscape(v)})
		},
		buildValues: func(vs []string) requestSpec {
			pairs := make([]string, len(vs))
			// Repeat the parameter once per value, in order, for pollution.
			for i, v := range vs {
				pairs[i] = url.QueryEscape(key) + "=" + url.QueryEscape(v)
			}
			return withQuery(pairs)
		},
		buildArrayName: func(name, v string) requestSpec {
			return withQuery([]string{url.QueryEscape(name) + "=" + url.QueryEscape(v)})
		},
	}
}

// pathPoints returns one point per path segment that carries a reference. A
// segment becomes a point on its value (a numeric id in /users/1001) and never
// on a name, since a path segment has no name.
func pathPoints(seed *url.URL, base requestSpec) []point {
	segments := strings.Split(seed.EscapedPath(), "/")
	var out []point
	// Index 0 is the empty string before the first "/", so start at 1.
	for i := 1; i < len(segments); i++ {
		seg := segments[i]
		kind, ok := classify(seg)
		// Only a segment that itself looks like a reference is worth mutating;
		// a literal path component ("users") is not an object id.
		if !ok {
			continue
		}
		out = append(out, pathSegmentPoint(seed, base, segments, i, seg, kind))
	}
	return out
}

// pathSegmentPoint replaces one path segment with a mutated value, keeping the
// query string and the rest of the path as the seed had them.
func pathSegmentPoint(seed *url.URL, base requestSpec, segments []string, idx int, seg string, kind refKind) point {
	return point{
		id:    fmt.Sprintf("path|%d", idx),
		label: fmt.Sprintf("path segment %q", seg),
		where: "path",
		kind:  kind,
		value: seg,
		build: func(v string) requestSpec {
			segs := append([]string(nil), segments...)
			segs[idx] = url.PathEscape(v)
			u := *seed
			u.RawPath = ""
			u.Path = strings.Join(decodeSegments(segs), "/")
			spec := base
			spec.URL = u.String()
			spec.Headers = cloneHeaders(base.Headers)
			return spec
		},
	}
}

// bodyPoints turns the operator's request body into points: one per string
// leaf of a JSON body, or one per field of a form-encoded body, keeping only
// those that look like object references. Any other body contributes none.
func bodyPoints(base requestSpec, body, contentType string) []point {
	if body == "" {
		return nil
	}
	trimmed := strings.TrimSpace(body)
	isJSON := strings.Contains(strings.ToLower(contentType), "json") ||
		(contentType == "" && (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")))
	if isJSON {
		return jsonBodyPoints(base, body)
	}
	return formBodyPoints(base, body)
}

// jsonBodyPoints walks a JSON body and returns a point per string or numeric
// leaf that looks like a reference (or whose key looks like an id).
func jsonBodyPoints(base requestSpec, body string) []point {
	var doc any
	// A body that is not valid JSON yields no JSON points.
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil
	}
	var leaves []jsonLeaf
	collectJSONLeaves(doc, nil, &leaves)
	out := make([]point, 0, len(leaves))
	for _, lf := range leaves {
		out = append(out, jsonPoint(base, doc, lf))
	}
	return out
}

// jsonLeaf is one scalar value in a JSON document, where it sits, its inferred
// kind, and its value as a string.
type jsonLeaf struct {
	path    []any
	pointer string
	kind    refKind
	value   string
}

// collectJSONLeaves gathers reference-looking scalar leaves in a stable order,
// stopping at maxBodyFields. A leaf qualifies on its value classifying or on
// the key that holds it looking like an id.
func collectJSONLeaves(node any, path []any, out *[]jsonLeaf) {
	if len(*out) >= maxBodyFields {
		return
	}
	switch n := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectJSONLeaves(n[k], appendPath(path, k), out)
		}
	case []any:
		for i, x := range n {
			collectJSONLeaves(x, appendPath(path, i), out)
		}
	case string:
		addJSONLeaf(path, n, out)
	case float64:
		// A JSON number is rendered without a trailing ".0" so it classifies
		// as numeric the same way the wire form would.
		addJSONLeaf(path, formatNumber(n), out)
	}
}

// addJSONLeaf appends a leaf when its value or its key looks like a reference.
func addJSONLeaf(path []any, value string, out *[]jsonLeaf) {
	kind, ok := classify(value)
	keyName := lastKey(path)
	// The leaf is a point if the value classifies, or if its key name is id-ish
	// (then it is treated as numeric so neighbours can still be generated).
	if !ok {
		if !nameLooksLikeID(keyName) {
			return
		}
		kind = kindNumeric
	}
	*out = append(*out, jsonLeaf{path: append([]any(nil), path...), pointer: pointerOf(path), kind: kind, value: value})
}

// jsonPoint builds a point for one JSON leaf. build replaces it with a string;
// buildJSON replaces it with an arbitrary JSON value; the document is
// re-serialized each time so the app's own decoder applies the escaping.
func jsonPoint(base requestSpec, doc any, lf jsonLeaf) point {
	spec := func(v any) requestSpec {
		b, _ := json.Marshal(replaceAt(doc, lf.path, v))
		s := base
		s.Body = string(b)
		s.Headers = cloneHeaders(base.Headers)
		s.Headers["Content-Type"] = "application/json"
		return s
	}
	return point{
		id:        "json|" + lf.pointer,
		label:     fmt.Sprintf("JSON body field %q", lf.pointer),
		where:     "json",
		kind:      lf.kind,
		value:     lf.value,
		build:     func(v string) requestSpec { return spec(v) },
		buildJSON: spec,
	}
}

// formBodyPoints returns a point per form field that looks like a reference,
// supporting single, polluted (repeated), and array-renamed values in the body.
func formBodyPoints(base requestSpec, body string) []point {
	fields, err := url.ParseQuery(body)
	// A body that is not form-encoded yields no form points.
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []point
	for _, key := range keys {
		val := fields.Get(key)
		kind, ok := classify(val)
		if !ok {
			if !nameLooksLikeID(key) {
				continue
			}
			kind, val = kindNumeric, firstNonEmpty(val, "1")
		}
		out = append(out, formPoint(base, fields, key, val, kind))
	}
	return out
}

// formPoint builds a point for one form-encoded body field. The other fields
// keep their values; only this one is rewritten.
func formPoint(base requestSpec, fields url.Values, key, value string, kind refKind) point {
	withField := func(pairs []string) requestSpec {
		others := url.Values{}
		for k, vs := range fields {
			if k == key {
				continue
			}
			others[k] = append([]string(nil), vs...)
		}
		s := base
		s.Body = joinQuery(others.Encode(), pairs)
		s.Headers = cloneHeaders(base.Headers)
		s.Headers["Content-Type"] = "application/x-www-form-urlencoded"
		return s
	}
	return point{
		id:    "form|" + key,
		label: fmt.Sprintf("form field %q", key),
		where: "form",
		kind:  kind,
		value: value,
		name:  key,
		build: func(v string) requestSpec {
			return withField([]string{url.QueryEscape(key) + "=" + url.QueryEscape(v)})
		},
		buildValues: func(vs []string) requestSpec {
			pairs := make([]string, len(vs))
			for i, v := range vs {
				pairs[i] = url.QueryEscape(key) + "=" + url.QueryEscape(v)
			}
			return withField(pairs)
		},
		buildArrayName: func(name, v string) requestSpec {
			return withField([]string{url.QueryEscape(name) + "=" + url.QueryEscape(v)})
		},
	}
}

// cookiePoints returns a point per cookie (operator-sent or set by the seed
// response) that carries a reference. Some apps store the acting user id in a
// cookie, so tampering with it is an IDOR vector.
func cookiePoints(base requestSpec, setCookies []string) []point {
	order, vals := parseCookies(base.Headers, setCookies)
	var out []point
	for _, name := range order {
		val := vals[name]
		kind, ok := classify(val)
		if !ok {
			if !nameLooksLikeID(name) {
				continue
			}
			kind, val = kindNumeric, firstNonEmpty(val, "1")
		}
		out = append(out, cookiePoint(base, order, vals, name, val, kind))
	}
	return out
}

// cookiePoint builds a point for one cookie, keeping the others as sent.
func cookiePoint(base requestSpec, order []string, vals map[string]string, name, value string, kind refKind) point {
	return point{
		id:    "cookie|" + name,
		label: fmt.Sprintf("cookie %q", name),
		where: "cookie",
		kind:  kind,
		value: value,
		build: func(v string) requestSpec {
			merged := make(map[string]string, len(vals))
			maps.Copy(merged, vals)
			merged[name] = v
			s := base
			s.Headers = cloneHeaders(base.Headers)
			s.Headers["Cookie"] = renderCookies(order, merged)
			return s
		},
	}
}

// headerPoints returns a point per identity header: those the operator already
// sends whose name looks id-ish, plus the fixed identityHeaders list seeded
// with "1".
func headerPoints(base requestSpec) []point {
	seen := map[string]bool{}
	var out []point
	// Operator-sent headers whose name looks like an identity header.
	for k, v := range base.Headers {
		if !nameLooksLikeID(k) || strings.EqualFold(k, "Cookie") {
			continue
		}
		kind, ok := classify(v)
		if !ok {
			kind, v = kindNumeric, firstNonEmpty(v, "1")
		}
		seen[strings.ToLower(k)] = true
		out = append(out, headerPoint(base, k, v, kind, false))
	}
	// The fixed list of headers apps trust for identity, seeded with "1".
	for _, h := range identityHeaders {
		if seen[strings.ToLower(h)] {
			continue
		}
		out = append(out, headerPoint(base, h, "1", kindNumeric, true))
	}
	return out
}

// headerPoint builds a point for one request header set to a mutated value.
func headerPoint(base requestSpec, name, value string, kind refKind, injected bool) point {
	label := fmt.Sprintf("%q header", name)
	// An injected header is called out, since honouring it is itself the bug.
	if injected {
		label = fmt.Sprintf("injected %q header", name)
	}
	return point{
		id:    "header|" + name,
		label: label,
		where: "header",
		kind:  kind,
		value: value,
		build: func(v string) requestSpec {
			s := base
			s.Headers = cloneHeaders(base.Headers)
			s.Headers[name] = v
			return s
		},
	}
}

// dedupePoints removes points with the same id, keeping the first, so a key a
// query and a body both name is tested once.
func dedupePoints(points []point) []point {
	seen := map[string]bool{}
	out := make([]point, 0, len(points))
	for _, p := range points {
		if seen[p.id] {
			continue
		}
		seen[p.id] = true
		out = append(out, p)
	}
	return out
}

// --- small helpers shared by the point builders ---

// joinQuery concatenates an encoded "others" query string with extra raw pairs,
// dropping empty parts so there is never a stray "&".
func joinQuery(others string, pairs []string) string {
	parts := make([]string, 0, len(pairs)+1)
	if others != "" {
		parts = append(parts, others)
	}
	parts = append(parts, pairs...)
	return strings.Join(parts, "&")
}

// decodeSegments percent-decodes each path segment so url.URL.Path (which
// re-escapes on String) carries the intended bytes. A segment that fails to
// decode is kept as-is.
func decodeSegments(segs []string) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		if dec, err := url.PathUnescape(s); err == nil {
			out[i] = dec
			continue
		}
		out[i] = s
	}
	return out
}

// appendTrimmed appends every non-empty, trimmed string of in to dst.
func appendTrimmed(dst, in []string) []string {
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			dst = append(dst, s)
		}
	}
	return dst
}

// firstNonEmpty returns a if it is non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// formatNumber renders a JSON number the way the wire form carries it: an
// integer without a decimal point, a fractional value with one.
func formatNumber(f float64) string {
	// An integral value is printed without a trailing ".0" so it classifies
	// as a numeric id.
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%v", f)
}

// appendPath returns path with seg added on a fresh slice, so sibling walks do
// not share a backing array.
func appendPath(path []any, seg any) []any {
	out := make([]any, len(path)+1)
	copy(out, path)
	out[len(path)] = seg
	return out
}

// pointerOf renders a JSON path as a pointer-like string ("/user/0/id").
func pointerOf(path []any) string {
	var b strings.Builder
	for _, seg := range path {
		fmt.Fprintf(&b, "/%v", seg)
	}
	return b.String()
}

// lastKey returns the final string key of a JSON path, or "" when the path
// ends in an array index or is empty.
func lastKey(path []any) string {
	if len(path) == 0 {
		return ""
	}
	if s, ok := path[len(path)-1].(string); ok {
		return s
	}
	return ""
}

// replaceAt returns a copy of node with the leaf at path set to v, copying only
// the containers along the path so each probe gets its own document.
func replaceAt(node any, path []any, v any) any {
	if len(path) == 0 {
		return v
	}
	switch n := node.(type) {
	case map[string]any:
		key := path[0].(string)
		c := make(map[string]any, len(n))
		maps.Copy(c, n)
		c[key] = replaceAt(n[key], path[1:], v)
		return c
	case []any:
		idx := path[0].(int)
		c := append([]any(nil), n...)
		c[idx] = replaceAt(n[idx], path[1:], v)
		return c
	}
	return node
}

// parseCookies collects cookie names (in order) and values from the operator's
// Cookie header plus any the seed response set, later duplicates ignored.
func parseCookies(headers map[string]string, setCookies []string) ([]string, map[string]string) {
	var order []string
	vals := map[string]string{}
	add := func(name, value string) {
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = value
	}
	if raw, ok := headerValue(headers, "Cookie"); ok {
		// Each "; "-separated pair is one cookie the operator sent.
		for _, part := range strings.Split(raw, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && name != "" {
				add(name, value)
			}
		}
	}
	for _, sc := range setCookies {
		// Only the name=value before the first ";" matters for a Set-Cookie.
		pair, _, _ := strings.Cut(sc, ";")
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && name != "" {
			add(name, value)
		}
	}
	return order, vals
}

// renderCookies rebuilds a Cookie header from names in order and their values.
func renderCookies(order []string, vals map[string]string) string {
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+"="+vals[name])
	}
	return strings.Join(parts, "; ")
}
