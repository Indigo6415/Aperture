package pathtraversal

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Indigo6415/Aperture/internal/robots"
)

// point is one place a traversal payload can be supplied: a query parameter,
// a form or body field, a JSON string, a path segment, a request header, or a
// cookie. build turns a value into the full request that carries it.
type point struct {
	// id is the dedupe key. Two discoveries of the same place (for example a
	// query parameter the URL and a form both name) produce one point.
	id string
	// label describes the point for the progress grid and findings.
	label string
	// segment is the path segment's own text, set only for path-segment
	// points. The nginx alias payload needs it.
	segment string
	build   func(value string) requestSpec
}

// commonParams are query/form names that commonly carry a file or path. They
// are tried on the seed URL even when it does not carry them, the same way
// openredirect tries its common redirect parameters.
var commonParams = []string{
	"file", "filename", "file_name", "filepath", "file_path", "path", "folder", "dir", "directory",
	"doc", "document", "page", "template", "tpl", "view", "include", "inc", "load", "read",
	"resource", "img", "image", "download", "pdf", "lang", "locale", "theme", "module", "content",
	"name", "src", "log", "config",
}

// commonCookies are cookie names that often select a file, template, or
// language. They are added to the Cookie header on the seed request.
var commonCookies = []string{"file", "path", "template", "page", "lang", "theme", "view", "doc"}

// pathHeaders are request headers that some apps read as a file name, template
// name, or internal path. Applications that trust them are a known vector.
var pathHeaders = []string{"X-Original-URL", "X-Rewrite-URL", "X-File-Name", "X-Filename", "X-Path", "X-Template-Name", "X-Include-File"}

// maxJSONFields caps how many string leaves of a JSON body become points, so
// a large document does not turn into hundreds of probes.
const maxJSONFields = 40

// crawl limits, sized like the other scanners' crawlers.
const (
	crawlDefaultMaxPages = 25
	crawlMaxPagesCap     = 50
)

var (
	anchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	formPattern       = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	formActionPattern = regexp.MustCompile(`(?is)\saction\s*=\s*["']([^"']*)["']`)
	formMethodPattern = regexp.MustCompile(`(?is)\smethod\s*=\s*["']([^"']*)["']`)
	formEnctypePat    = regexp.MustCompile(`(?is)\senctype\s*=\s*["']([^"']*)["']`)
	// fieldPattern covers every element that submits a named value. A file
	// input is skipped later, since a filename is not a read.
	fieldPattern     = regexp.MustCompile(`(?is)<(input|select|textarea)([^>]*)>`)
	fieldNamePattern = regexp.MustCompile(`(?is)\sname\s*=\s*["']([^"']+)["']`)
	fieldValuePatt   = regexp.MustCompile(`(?is)\svalue\s*=\s*["']([^"']*)["']`)
	fieldTypePattern = regexp.MustCompile(`(?is)\stype\s*=\s*["']([^"']*)["']`)
)

// cloneHeaders copies a header map. Points build their own header sets, so
// they must not share one.
func cloneHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h)+1)
	maps.Copy(out, h)
	return out
}

// headerValue finds a header by case-insensitive name. The operator's
// header keys are not normalized, so an exact-case lookup would miss "cookie".
func headerValue(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// rawURL rebuilds scheme://host plus the given escaped path and the query
// string, keeping the path exactly as given instead of re-escaping it.
func rawURL(base *url.URL, escapedPath, rawQuery string) string {
	s := base.Scheme + "://" + base.Host + escapedPath
	if rawQuery != "" {
		s += "?" + rawQuery
	}
	return s
}

// queryPoint is one query-string parameter on pageURL. The other parameters
// keep their values. base supplies the method, headers, and body the probe
// uses, so the seed's own POST body survives a query-parameter test.
func queryPoint(base requestSpec, pageURL *url.URL, key string) point {
	bare := *pageURL
	bare.RawQuery = ""
	return point{
		id:    "query|" + base.Method + "|" + bare.String() + "|" + key,
		label: fmt.Sprintf("query parameter %q on %s", key, bare.String()),
		build: func(value string) requestSpec {
			u := *pageURL
			// The payload is written raw, so the app decodes it exactly once,
			// the way a browser's URL would reach it. Re-encoding the value
			// here would add one more layer and break every encoding bypass.
			u.RawQuery = setRawQueryParam(pageURL.RawQuery, key, rawValueFor(value))
			spec := base
			spec.URL = u.String()
			spec.Headers = cloneHeaders(base.Headers)
			return spec
		},
	}
}

// setRawQueryParam returns the raw query string q with every pair named key
// removed and key=raw appended. The other pairs are kept byte for byte, so
// their encoding is the operator's own. key is decoded before comparing, so
// an escaped name still matches.
func setRawQueryParam(q, key, raw string) string {
	parts := []string{}
	// Keep every pair except the one named key. Empty pairs from "&&" are dropped.
	for _, pair := range strings.Split(q, "&") {
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		// A name that fails to decode cannot be key, so the pair is kept.
		if decoded, err := url.QueryUnescape(name); err == nil && decoded == key {
			continue
		}
		parts = append(parts, pair)
	}
	parts = append(parts, url.QueryEscape(key)+"="+raw)
	return strings.Join(parts, "&")
}

// rawValueFor escapes a payload for use as a query or form value, leaving its
// percent sequences as written. Only the bytes that would change how the query
// is split or decoded are escaped: "&", "#", "+", space, non-ASCII, and a "%"
// that does not start a valid escape. A "%u2215" sequence is kept as written
// too, since it is the IIS form and is not a valid percent escape.
func rawValueFor(v string) string {
	var b strings.Builder
	// Walk the payload byte by byte, so each escape decision sees one byte.
	for i := 0; i < len(v); i++ {
		c := v[i]
		// A percent sequence the payload wrote on purpose goes out unchanged.
		if c == '%' && isPercentSequence(v[i:]) {
			b.WriteByte(c)
			continue
		}
		if querySafe(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// querySafe reports whether c can stand unescaped inside a query value. The
// set is the unreserved characters plus the sub-delimiters that a payload
// uses (path separators, "=", "?", ":", "@", "$", ",", ";", "(", ")", "*",
// "!", "'"), and it leaves out "&", "#", and "+", which change the query.
func querySafe(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~/:=?@!$'()*,;[]", c) >= 0
}

// isPercentSequence reports whether s starts with a percent escape: "%" plus
// two hex digits, or "%u" plus four hex digits (the IIS form). Anything else
// starting with "%" is not an escape and must be encoded as %25.
func isPercentSequence(s string) bool {
	if len(s) >= 3 && isHex(s[1]) && isHex(s[2]) {
		return true
	}
	if len(s) >= 6 && s[1] == 'u' && isHex(s[2]) && isHex(s[3]) && isHex(s[4]) && isHex(s[5]) {
		return true
	}
	return false
}

// isHex reports whether c is an ASCII hexadecimal digit.
func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// formEncodeWith encodes fields as a query or form body, with key set to the
// raw payload. The other fields are encoded normally, and key is written last.
func formEncodeWith(fields url.Values, key, raw string) string {
	others := url.Values{}
	// Copy every field except key, which is written raw below.
	for k, v := range fields {
		if k != key {
			others[k] = v
		}
	}
	return setRawQueryParam(others.Encode(), key, raw)
}

// formPoint is one field of a discovered form. A GET form puts its fields in
// the query, a POST form puts them in the body, and a multipart form is
// encoded as multipart/form-data, the same as a browser would submit it.
func formPoint(action *url.URL, method, enctype string, fields url.Values, key string, headers map[string]string) point {
	bare := *action
	bare.RawQuery = ""
	return point{
		id:    "form|" + method + "|" + bare.String() + "|" + key,
		label: fmt.Sprintf("form field %q (%s %s)", key, method, bare.String()),
		build: func(value string) requestSpec {
			// The payload is written raw in the query and urlencoded body, the
			// same as queryPoint, so the app decodes it once. Multipart has no
			// decoding step, so its value goes in as is.
			raw := rawValueFor(value)
			f := url.Values{}
			for k, v := range fields {
				f[k] = append([]string(nil), v...)
			}
			spec := requestSpec{Method: method, Headers: cloneHeaders(headers)}
			if method == http.MethodGet {
				u := *action
				u.RawQuery = formEncodeWith(f, key, raw)
				spec.URL = u.String()
				return spec
			}
			spec.URL = action.String()
			if strings.Contains(strings.ToLower(enctype), "multipart") {
				f.Set(key, value)
				body, contentType := encodeMultipart(f)
				spec.Body = body
				spec.Headers["Content-Type"] = contentType
			} else {
				spec.Body = formEncodeWith(f, key, raw)
				spec.Headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
			return spec
		},
	}
}

// multipartBoundary is fixed so probes are reproducible. It is long and odd
// enough that a field value will not contain it.
const multipartBoundary = "ApertureTraversalBoundary7d1f"

// encodeMultipart writes fields as a multipart/form-data body, in key order.
// It returns the body and the Content-Type value that goes with it.
func encodeMultipart(fields url.Values) (string, string) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		// Each field is one part with its own header block, then the value.
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", multipartBoundary, k, fields.Get(k))
	}
	fmt.Fprintf(&b, "--%s--\r\n", multipartBoundary)
	return b.String(), "multipart/form-data; boundary=" + multipartBoundary
}

// jsonPoint is one string leaf of a JSON body. build replaces that leaf and
// re-serializes the document, so JSON escaping is applied to the payload the
// way the app's own encoder would apply it.
func jsonPoint(base requestSpec, doc any, path []any, pointer string) point {
	return point{
		id:    "json|" + base.Method + "|" + base.URL + "|" + pointer,
		label: fmt.Sprintf("JSON body field %q (%s %s)", pointer, base.Method, base.URL),
		build: func(value string) requestSpec {
			b, _ := json.Marshal(replaceAt(doc, path, value))
			spec := base
			spec.Body = string(b)
			spec.Headers = cloneHeaders(base.Headers)
			spec.Headers["Content-Type"] = "application/json"
			return spec
		},
	}
}

// replaceAt returns a copy of node with the leaf at path set to v. Only the
// containers on the path are copied, so the original document is not changed
// and each probe gets its own document.
func replaceAt(node any, path []any, v string) any {
	if len(path) == 0 {
		return v
	}
	switch n := node.(type) {
	case map[string]any:
		key := path[0].(string)
		c := make(map[string]any, len(n))
		for k, x := range n {
			c[k] = x
		}
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

// jsonLeaf is one string value in a JSON document and where it sits.
type jsonLeaf struct {
	path    []any
	pointer string
}

// collectJSONLeaves walks doc and gathers string leaves in a stable order,
// stopping at maxJSONFields.
func collectJSONLeaves(node any, path []any, out *[]jsonLeaf) {
	if len(*out) >= maxJSONFields {
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
		*out = append(*out, jsonLeaf{path: append([]any(nil), path...), pointer: pointerOf(path)})
	}
}

// appendPath returns path with seg added, on a fresh slice so siblings do
// not share a backing array.
func appendPath(path []any, seg any) []any {
	out := make([]any, len(path)+1)
	copy(out, path)
	out[len(path)] = seg
	return out
}

// pointerOf renders a path as a JSON-pointer-like string ("/user/0/name") for
// labels and dedupe keys.
func pointerOf(path []any) string {
	var b strings.Builder
	for _, seg := range path {
		fmt.Fprintf(&b, "/%v", seg)
	}
	return b.String()
}

// parseCookieHeader splits a Cookie header into its names, in order, and their
// values. Later duplicates of a name are ignored.
func parseCookieHeader(s string) ([]string, map[string]string) {
	var order []string
	vals := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || name == "" {
			continue
		}
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = value
	}
	return order, vals
}

// cookieHeader renders cookies back into a Cookie header, in the given order.
func cookieHeader(order []string, vals map[string]string) string {
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+"="+vals[name])
	}
	return strings.Join(parts, "; ")
}

// cookiePoint is one cookie. build sets that cookie and keeps the others as
// the seed sent them, so the request still looks like a real session.
func cookiePoint(base requestSpec, order []string, vals map[string]string, name string) point {
	return point{
		id:    "cookie|" + name,
		label: fmt.Sprintf("cookie %q on %s", name, base.URL),
		build: func(value string) requestSpec {
			o := append([]string(nil), order...)
			if _, ok := vals[name]; !ok {
				o = append(o, name)
			}
			v := make(map[string]string, len(vals)+1)
			maps.Copy(v, vals)
			v[name] = value
			spec := base
			spec.Headers = cloneHeaders(base.Headers)
			spec.Headers["Cookie"] = cookieHeader(o, v)
			return spec
		},
	}
}

// headerPoint is one request header set to the payload, with everything else
// the same as the seed.
func headerPoint(base requestSpec, name string) point {
	return point{
		id:    "header|" + name,
		label: fmt.Sprintf("%q request header on %s", name, base.URL),
		build: func(value string) requestSpec {
			spec := base
			spec.Headers = cloneHeaders(base.Headers)
			spec.Headers[name] = value
			return spec
		},
	}
}

// pathSegmentPoint replaces one segment of the seed path with the payload.
// idx is the index in the split path, where index 0 is the empty string before
// the first "/".
func pathSegmentPoint(seed *url.URL, base requestSpec, segments []string, idx int) point {
	seg := segments[idx]
	return point{
		id:      fmt.Sprintf("path|%d", idx),
		label:   fmt.Sprintf("path segment %q on %s", seg, seed.Path),
		segment: seg,
		build: func(value string) requestSpec {
			segs := append([]string(nil), segments...)
			segs[idx] = value
			spec := base
			spec.URL = rawURL(seed, strings.Join(segs, "/"), seed.RawQuery)
			spec.Headers = cloneHeaders(base.Headers)
			return spec
		},
	}
}

// pathSuffixPoint appends the payload as a new final segment. It covers apps
// that take a file name after a fixed directory, such as /files/<name>.
func pathSuffixPoint(seed *url.URL, base requestSpec) point {
	return point{
		id:    "path|suffix",
		label: fmt.Sprintf("appended path segment on %s", seed.Path),
		build: func(value string) requestSpec {
			spec := base
			spec.URL = rawURL(seed, strings.TrimRight(seed.EscapedPath(), "/")+"/"+value, seed.RawQuery)
			spec.Headers = cloneHeaders(base.Headers)
			return spec
		},
	}
}

// bodyPoints turns the operator's body into points. A JSON body gives one
// point per string leaf. An XML body gives one point per text node. A
// form-encoded body gives one point per field. Any other body gives none.
func bodyPoints(base requestSpec, body, contentType string) []point {
	if body == "" {
		return nil
	}
	trimmed := strings.TrimSpace(body)
	isJSON := strings.Contains(strings.ToLower(contentType), "json") ||
		(contentType == "" && (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")))
	if isJSON {
		var doc any
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			return nil
		}
		var leaves []jsonLeaf
		collectJSONLeaves(doc, nil, &leaves)
		out := make([]point, 0, len(leaves))
		for _, lf := range leaves {
			out = append(out, jsonPoint(base, doc, lf.path, lf.pointer))
		}
		return out
	}
	// XML is checked before form encoding, since an XML body is not a query string.
	isXML := strings.Contains(strings.ToLower(contentType), "xml") ||
		(contentType == "" && strings.HasPrefix(trimmed, "<"))
	if isXML {
		return xmlPoints(base, body)
	}
	fields, err := url.ParseQuery(body)
	if err != nil {
		return nil
	}
	target, err := url.Parse(base.URL)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]point, 0, len(keys))
	for _, k := range keys {
		out = append(out, formPoint(target, base.Method, "application/x-www-form-urlencoded", fields, k, base.Headers))
	}
	return out
}

// maxXMLNodes caps how many text nodes of an XML body become points, the same
// way maxJSONFields caps JSON leaves.
const maxXMLNodes = 40

// xmlTextPattern matches the text between a closing ">" and the next "<",
// which is the text content of one element.
var xmlTextPattern = regexp.MustCompile(`>([^<>]*)<`)

// xmlPoints gives one point per non-blank text node of an XML body. The
// payload is XML-escaped before it goes in, so the document stays well formed
// and the parser hands the app the payload's own characters.
func xmlPoints(base requestSpec, body string) []point {
	var out []point
	// Each match is one text node, with group 1 the text itself.
	for _, loc := range xmlTextPattern.FindAllStringSubmatchIndex(body, -1) {
		// Stop at the cap so a large document does not become hundreds of probes.
		if len(out) >= maxXMLNodes {
			break
		}
		start, end := loc[2], loc[3]
		// Skip the whitespace between tags. Only real text is a point.
		if strings.TrimSpace(body[start:end]) == "" {
			continue
		}
		out = append(out, xmlPoint(base, body, start, end, xmlElementName(body[:start])))
	}
	return out
}

// xmlElementName returns the name of the innermost element that is open at the
// end of before, which is the element whose text comes next. It returns "?"
// when no tag can be found.
func xmlElementName(before string) string {
	i := strings.LastIndex(before, "<")
	if i < 0 || i+1 >= len(before) {
		return "?"
	}
	name := before[i+1:]
	// Stop the name at the first space, ">", or "/" (a closing tag).
	if j := strings.IndexAny(name, " \t\r\n>/"); j >= 0 {
		name = name[:j]
	}
	if name == "" {
		return "?"
	}
	return name
}

// xmlPoint replaces the text at body[start:end] with the escaped payload. The
// element name is only for the label, and the id uses the text's offset, which
// is stable for one body.
func xmlPoint(base requestSpec, body string, start, end int, element string) point {
	return point{
		id:    fmt.Sprintf("xml|%s|%s|%d", base.Method, base.URL, start),
		label: fmt.Sprintf("XML text of <%s> (%s %s)", element, base.Method, base.URL),
		build: func(value string) requestSpec {
			var esc strings.Builder
			// EscapeText writes into a strings.Builder without failing.
			_ = xml.EscapeText(&esc, []byte(value))
			spec := base
			spec.Body = body[:start] + esc.String() + body[end:]
			spec.Headers = cloneHeaders(base.Headers)
			return spec
		},
	}
}

// formSpec is one <form> from a page, with its action resolved and its fields
// collected with their default values.
type formSpec struct {
	action  *url.URL
	method  string
	enctype string
	fields  url.Values
}

// parseForms finds every form on body, resolving each action against the
// page's URL. A form with no action submits to the page itself, without its
// query string.
func parseForms(body string, page *url.URL) []formSpec {
	var forms []formSpec
	for _, m := range formPattern.FindAllStringSubmatch(body, -1) {
		// Pad the attributes with a space so the attribute patterns can
		// require whitespace before the attribute name.
		attrs := " " + m[1]
		action := page.String()
		if am := formActionPattern.FindStringSubmatch(attrs); am != nil && strings.TrimSpace(am[1]) != "" {
			action = am[1]
		}
		actionURL, err := page.Parse(action)
		if err != nil {
			continue
		}
		actionURL.Fragment = ""
		method := http.MethodGet
		if mm := formMethodPattern.FindStringSubmatch(attrs); mm != nil && strings.EqualFold(strings.TrimSpace(mm[1]), "post") {
			method = http.MethodPost
		}
		enctype := ""
		if em := formEnctypePat.FindStringSubmatch(attrs); em != nil {
			enctype = em[1]
		}
		fields := url.Values{}
		for _, fm := range fieldPattern.FindAllStringSubmatch(m[2], -1) {
			fa := " " + fm[2]
			nm := fieldNamePattern.FindStringSubmatch(fa)
			if nm == nil {
				continue
			}
			// File inputs and buttons are not text fields and get no value
			// here. A file input's filename is not a read.
			if tm := fieldTypePattern.FindStringSubmatch(fa); tm != nil {
				switch strings.ToLower(tm[1]) {
				case "file", "submit", "button", "reset", "image":
					continue
				}
			}
			value := ""
			if vm := fieldValuePatt.FindStringSubmatch(fa); vm != nil {
				value = vm[1]
			}
			fields.Set(nm[1], value)
		}
		if len(fields) == 0 {
			continue
		}
		forms = append(forms, formSpec{action: actionURL, method: method, enctype: enctype, fields: fields})
	}
	return forms
}

// queuedPage is one page waiting to be crawled, with its distance from the seed.
type queuedPage struct {
	url   string
	depth int
}

// crawlResult is the crawl's output: the pages it fetched and every point
// found on them.
type crawlResult struct {
	pages  []string
	points []point
}

// crawl does a breadth-first, same-origin walk from seed, up to depth link
// hops and maxPages pages. On each page it collects the query parameters, the
// forms, and the links to follow. The seed's own query parameters are left
// to Run, because the seed may use a POST body that a plain GET would drop.
func crawl(ctx context.Context, client *http.Client, seed *url.URL, seedBody string, headers map[string]string, depth, maxPages int) crawlResult {
	if maxPages <= 0 {
		maxPages = crawlDefaultMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	var res crawlResult
	visited := map[string]bool{}
	seen := map[string]bool{}
	addPoint := func(p point) {
		if seen[p.id] {
			return
		}
		seen[p.id] = true
		res.points = append(res.points, p)
	}

	policy := robots.Load(ctx, client, seed, headers)
	getBase := requestSpec{Method: http.MethodGet, Headers: headers}
	queue := []queuedPage{{seed.String(), 0}}
	for len(queue) > 0 && len(visited) < maxPages {
		// A cancelled run stops at the next page boundary.
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		if visited[item.url] {
			continue
		}
		visited[item.url] = true

		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}
		isSeed := item.url == seed.String()

		// The seed page is already fetched, so its body is reused. Other
		// pages get a plain GET.
		body := seedBody
		if !isSeed {
			r := send(ctx, client, nil, requestSpec{Method: http.MethodGet, URL: item.url, Headers: headers})
			if r.Err != nil {
				continue
			}
			body = r.Body
		}
		res.pages = append(res.pages, item.url)

		if !isSeed {
			keys := make([]string, 0)
			for k := range pageURL.Query() {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				addPoint(queryPoint(getBase, pageURL, k))
			}
		}
		for _, f := range parseForms(body, pageURL) {
			keys := make([]string, 0, len(f.fields))
			for k := range f.fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				addPoint(formPoint(f.action, f.method, f.enctype, f.fields, k, headers))
			}
		}

		if item.depth >= depth {
			continue
		}
		for _, m := range anchorHrefPattern.FindAllStringSubmatch(body, -1) {
			next, err := pageURL.Parse(strings.TrimSpace(m[1]))
			if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
				continue
			}
			// Same origin only, and no fragment, so a page is not visited twice.
			if next.Scheme != seed.Scheme || next.Host != seed.Host {
				continue
			}
			next.Fragment = ""
			if visited[next.String()] || !policy.Allowed(next) {
				continue
			}
			queue = append(queue, queuedPage{next.String(), item.depth + 1})
		}
	}
	return res
}
