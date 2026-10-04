package csrf

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

// startTagPattern matches one HTML start tag. Group 1 is the tag name and
// group 2 the raw attribute text. The attribute text is matched quote-aware,
// so a ">" inside a quoted attribute value does not end the tag early, which
// the naive [^>]* patterns this replaces would do.
var startTagPattern = regexp.MustCompile(`(?s)<([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>`)

// attrPattern pulls name=value pairs out of a tag's attribute text. The value
// may be double-quoted, single-quoted, or bare, and a bare name with no "=" is
// a boolean attribute. Groups 2-4 hold the three value forms; for any one match
// at most one of them is non-empty, so they can be concatenated.
var attrPattern = regexp.MustCompile(`([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)

// commentPattern matches an HTML comment. A browser never renders a comment's
// contents, so a form inside one is not a real form.
var commentPattern = regexp.MustCompile(`(?s)<!--.*?-->`)

// formClosePattern matches a closing </form> tag.
var formClosePattern = regexp.MustCompile(`(?i)</form\s*>`)

// tokenFieldPattern matches the names anti-CSRF hidden fields are commonly
// given: csrf/xsrf variants (csrf_token, _csrf, csrfmiddlewaretoken, _xsrf),
// authenticity_token (Rails), __RequestVerificationToken (ASP.NET), and
// antiforgery (ASP.NET Core). A generic "_token" suffix is deliberately not
// matched, since it also catches access_token and similar non-CSRF fields.
var tokenFieldPattern = regexp.MustCompile(`(?i)csrf|xsrf|authenticity[_-]?token|requestverificationtoken|antiforgery`)

// htmlTag is one start tag found in a document.
type htmlTag struct {
	// Name is the lower-cased tag name.
	Name string
	// Attrs maps lower-cased attribute names to their (entity-decoded) values.
	// The first occurrence of a repeated attribute wins, as browsers do.
	Attrs map[string]string
	// Start and End are the byte offsets of the tag's "<" and just past its ">".
	Start, End int
}

// stripComments removes HTML comments from doc so commented-out markup is not
// mistaken for live markup.
func stripComments(doc string) string {
	return commentPattern.ReplaceAllString(doc, "")
}

// scanTags returns every start tag in doc, in document order, with its
// attributes parsed by name. Closing tags and text are not included.
func scanTags(doc string) []htmlTag {
	matches := startTagPattern.FindAllStringSubmatchIndex(doc, -1)
	tags := make([]htmlTag, 0, len(matches))
	for _, m := range matches {
		t := htmlTag{
			Name:  strings.ToLower(doc[m[2]:m[3]]),
			Attrs: map[string]string{},
			Start: m[0],
			End:   m[1],
		}
		// Parse each attribute of this tag, keeping only the first value seen
		// for a name.
		for _, am := range attrPattern.FindAllStringSubmatch(doc[m[4]:m[5]], -1) {
			name := strings.ToLower(am[1])
			if _, dup := t.Attrs[name]; dup {
				continue
			}
			t.Attrs[name] = html.UnescapeString(am[2] + am[3] + am[4])
		}
		tags = append(tags, t)
	}
	return tags
}

// documentBase returns the URL that relative references in a page resolve
// against: the first <base href> that parses, or pageURL when there is none.
// A <base> changes where a form's action and a link's href actually point.
func documentBase(tags []htmlTag, pageURL *url.URL) *url.URL {
	for _, t := range tags {
		if t.Name != "base" {
			continue
		}
		href, ok := t.Attrs["href"]
		if !ok {
			continue
		}
		if b, err := pageURL.Parse(strings.TrimSpace(href)); err == nil {
			return b
		}
		break
	}
	return pageURL
}

// extractLinks returns the absolute URL of every <a href> and <area href> in
// body, resolved against the page's base. Quoted and unquoted attribute values
// are both accepted.
func extractLinks(body string, pageURL *url.URL) []string {
	doc := stripComments(body)
	tags := scanTags(doc)
	base := documentBase(tags, pageURL)
	var out []string
	for _, t := range tags {
		if t.Name != "a" && t.Name != "area" {
			continue
		}
		href := strings.TrimSpace(t.Attrs["href"])
		if href == "" {
			continue
		}
		if resolved, err := base.Parse(href); err == nil {
			out = append(out, resolved.String())
		}
	}
	return out
}

// isTokenFieldName reports whether a form field name reads as an anti-CSRF
// token. The bare "_token" is matched exactly, the Laravel default name.
func isTokenFieldName(name string) bool {
	return strings.EqualFold(name, "_token") || tokenFieldPattern.MatchString(name)
}

// isTokenMetaName reports whether a <meta name> is a page-level CSRF token
// (csrf-token, _csrf, xsrf-token). csrf-param and csrf-header name the field
// or header the token travels in, not the token itself, so they do not count.
func isTokenMetaName(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "param") || strings.Contains(lower, "header") {
		return false
	}
	return strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf")
}

// isSubmitControl reports whether a tag is a control that submits its form
// when activated, the only kind whose formmethod/formaction can change how
// the form is sent.
func isSubmitControl(t htmlTag) bool {
	typ := strings.ToLower(strings.TrimSpace(t.Attrs["type"]))
	switch t.Name {
	case "button":
		return typ == "" || typ == "submit"
	case "input":
		return typ == "submit" || typ == "image"
	}
	return false
}

// resolveMethod returns the verb a submission actually performs. A browser only
// sends GET or POST. A POST carrying a _method override (the Rails/Laravel
// convention) is served as the override verb. The framework ignores _method on
// a GET, so an override there does not count.
func resolveMethod(declared, override string) string {
	if declared == "POST" && (override == "PUT" || override == "PATCH" || override == "DELETE") {
		return override
	}
	return declared
}

// setCookieInfo is the part of a Set-Cookie header the CSRF checks read.
type setCookieInfo struct {
	Name string
	// SameSite is the lower-cased SameSite attribute value, "" when absent.
	SameSite string
}

// parseSetCookie reads one Set-Cookie header value. Attributes are read by
// name from the ";"-separated list, so a cookie value that merely contains the
// text "samesite=lax" is not mistaken for the attribute.
func parseSetCookie(raw string) setCookieInfo {
	parts := strings.Split(raw, ";")
	var info setCookieInfo
	// The first segment is name=value. Only the name is kept.
	if i := strings.Index(parts[0], "="); i >= 0 {
		info.Name = strings.TrimSpace(parts[0][:i])
	} else {
		info.Name = strings.TrimSpace(parts[0])
	}
	// Each later segment is an attribute. Only SameSite matters to this package.
	for _, p := range parts[1:] {
		key, val := p, ""
		if i := strings.Index(p, "="); i >= 0 {
			key, val = p[:i], p[i+1:]
		}
		if strings.EqualFold(strings.TrimSpace(key), "samesite") {
			info.SameSite = strings.ToLower(strings.TrimSpace(val))
		}
	}
	return info
}

// trackingCookiePrefixes are cookies set by analytics, advertising, consent,
// and bot-management tooling. None of them authenticate a user, so a missing
// SameSite on one is not a CSRF concern.
var trackingCookiePrefixes = []string{
	"_ga", "_gid", "_gat", "_gcl", "_fbp", "_fbc", "__utm", "_hj", "_pk_",
	"_clck", "_clsk", "ajs_", "mp_", "OptanonConsent", "OptanonAlertBoxClosed",
	"cookieconsent", "euconsent", "__cf_bm", "cf_clearance",
}

// isTrackingCookie reports whether name matches a known analytics, consent, or
// bot-management cookie prefix.
func isTrackingCookie(name string) bool {
	for _, p := range trackingCookiePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// authCookiePattern matches cookie names that commonly carry a session or
// authentication credential. A SameSite gap on one of these is what
// cross-site request forgery actually rides on.
var authCookiePattern = regexp.MustCompile(`(?i)sess|auth|token|sid|jwt|login|remember|csrf|xsrf|identity|passport`)

// looksLikeAuthCookie reports whether name reads as a session or auth cookie.
func looksLikeAuthCookie(name string) bool {
	return authCookiePattern.MatchString(name)
}
