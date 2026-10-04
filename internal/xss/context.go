package xss

import (
	"regexp"
	"strings"
)

// reflectionContext is the parser state a reflected payload lands in. It decides
// whether the browser would parse the payload as code, as markup, or as text.
type reflectionContext string

const (
	ctxText      reflectionContext = "html-text"
	ctxAttribute reflectionContext = "attribute"
	ctxScript    reflectionContext = "script"
	ctxComment   reflectionContext = "comment"
	ctxRawText   reflectionContext = "raw-text"
)

// rawTextTags are elements whose content the HTML parser reads as text rather
// than markup (RCDATA or raw text). A payload inside one is inert until it
// writes that element's own end tag, which the rawtext payload does.
var rawTextTags = map[string]bool{
	"textarea": true, "title": true, "style": true, "xmp": true,
	"iframe": true, "noembed": true, "noframes": true, "noscript": true,
}

// urlAttributes are attributes a browser follows as a URL, so a javascript:
// value in one of them runs code. data: is left out on purpose: an object
// data="javascript:" does not execute in current browsers.
var urlAttributes = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true, "xlink:href": true,
}

// markupStartPattern matches "<" followed by a letter, the start of an element
// the browser would create. A "<" followed by a space or a digit is just text.
var markupStartPattern = regexp.MustCompile(`<[a-zA-Z]`)

// codeHandlerPattern matches an inline event handler attribute such as
// onfocus=, which a breakout can add to run code without any markup.
var codeHandlerPattern = regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)

// htmlState is where the HTML parser stands at one byte offset of a document.
// It is a simplified tokenizer state, not a full parser: it covers the states
// a reflected payload can land in and what each one lets the payload break
// out of.
type htmlState struct {
	kind reflectionContext
	// tag is the lower-cased element name of the open tag, raw-text element or
	// script being read.
	tag string
	// endTag is true while reading an end tag such as </div>, where attributes
	// have no effect and the tag cannot switch the parser into a raw-text or
	// script body.
	endTag bool
	// attr is the lower-cased name of the attribute whose value is open.
	attr string
	// afterEq is true right after "=", so a quote or value character now starts
	// an attribute value.
	afterEq bool
	// quote is the quote character that opened the current attribute value, or
	// the open string literal inside a script (0 when none is open).
	quote byte
	// valueStart is the offset just past the opening quote of the current
	// attribute value. Together with the payload's own offset it tells whether
	// the payload is the first thing in that value.
	valueStart int
	// jsComment is '/' inside a // comment in a script, '*' inside a /* */
	// comment, and 0 otherwise.
	jsComment byte
	// closer ends a comment: "-->" for an HTML comment, ">" for a bogus one such
	// as <!DOCTYPE> or <?xml.
	closer string
}

// asciiLower lower-cases only ASCII letters. Unlike strings.ToLower it never
// changes the byte length, so offsets found in the lowered copy are valid in
// the original string.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// isSpace reports whether c is HTML whitespace.
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// isTagDelim reports whether c may follow a tag name: whitespace, "/" or ">".
func isTagDelim(c byte) bool {
	return c == '>' || c == '/' || isSpace(c)
}

// isAlnum reports whether c can appear in an element name.
func isAlnum(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
}

// isNameChar reports whether c can appear in an attribute name.
func isNameChar(c byte) bool {
	return isAlnum(c) || c == '-' || c == '_' || c == ':' || c == '.'
}

// findEndTag returns the offset in lower (already lower-cased) of the first
// "</tag" followed by a tag delimiter, or -1 when there is none.
func findEndTag(lower, tag string) int {
	needle := "</" + tag
	from := 0
	for {
		j := strings.Index(lower[from:], needle)
		if j < 0 {
			return -1
		}
		k := from + j
		end := k + len(needle)
		// The name must end here, so "</titles" is not "</title".
		if end < len(lower) && isTagDelim(lower[end]) {
			return k
		}
		from = k + 1
	}
}

// attrNameBefore returns the lower-cased attribute name that ends just before
// the "=" at offset eq in s.
func attrNameBefore(s string, eq int) string {
	k := eq
	for k > 0 && isSpace(s[k-1]) {
		k--
	}
	end := k
	for k > 0 && isNameChar(s[k-1]) {
		k--
	}
	return asciiLower(s[k:end])
}

// stateAt walks body[:end] the way an HTML parser would and returns the state
// it is in at offset end. It tracks tags, quoted attribute values, comments,
// raw-text elements, and script bodies (including JS string literals and
// comments), which covers every context the payload battery targets.
func stateAt(body string, end int) htmlState {
	s := body[:end]
	lower := asciiLower(s)
	st := htmlState{kind: ctxText}
	i := 0
	// Each pass consumes at least one byte, so this loop always ends.
	for i < len(s) {
		switch st.kind {
		case ctxText:
			// Only "<" can start markup, so jump straight to the next one.
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				return st
			}
			i += j
			switch {
			case strings.HasPrefix(s[i:], "<!--"):
				st = htmlState{kind: ctxComment, closer: "-->"}
				i += len("<!--")
			case strings.HasPrefix(s[i:], "<!"), strings.HasPrefix(s[i:], "<?"):
				// A bogus comment such as <!DOCTYPE> ends at the next ">".
				st = htmlState{kind: ctxComment, closer: ">"}
				i += 2
			case i+1 < len(s) && (s[i+1] == '/' || isAlnum(s[i+1])):
				// A start or end tag: record its name and read its attributes next.
				k := i + 1
				endTag := s[k] == '/'
				if endTag {
					k++
				}
				nameStart := k
				for k < len(s) && isAlnum(s[k]) {
					k++
				}
				st = htmlState{kind: ctxAttribute, tag: lower[nameStart:k], endTag: endTag}
				i = k
			default:
				i++
			}

		case ctxComment:
			// The comment body is inert until its closer.
			j := strings.Index(s[i:], st.closer)
			if j < 0 {
				return st
			}
			i += j + len(st.closer)
			st = htmlState{kind: ctxText}

		case ctxRawText:
			// Raw text ends only at its own end tag.
			j := findEndTag(lower[i:], st.tag)
			if j < 0 {
				return st
			}
			i += j + len("</"+st.tag)
			st = htmlState{kind: ctxAttribute, tag: st.tag, endTag: true}

		case ctxScript:
			// "</script" ends the element even inside a JS string or comment.
			if strings.HasPrefix(lower[i:], "</script") {
				st = htmlState{kind: ctxAttribute, tag: "script", endTag: true}
				i += len("</script")
				continue
			}
			c := s[i]
			switch {
			case st.jsComment == '/':
				// A line comment runs to the end of the line.
				if c == '\n' {
					st.jsComment = 0
				}
				i++
			case st.jsComment == '*':
				// A block comment runs to "*/".
				if c == '*' && i+1 < len(s) && s[i+1] == '/' {
					st.jsComment = 0
					i += 2
				} else {
					i++
				}
			case st.quote != 0:
				// Inside a string literal only an unescaped matching quote ends it.
				if c == '\\' {
					i += 2
				} else {
					if c == st.quote {
						st.quote = 0
					}
					i++
				}
			case c == '/' && i+1 < len(s) && s[i+1] == '/':
				st.jsComment = '/'
				i += 2
			case c == '/' && i+1 < len(s) && s[i+1] == '*':
				st.jsComment = '*'
				i += 2
			case c == '"' || c == '\'' || c == '`':
				st.quote = c
				i++
			default:
				i++
			}

		case ctxAttribute:
			c := s[i]
			// Inside a quoted value only the matching quote ends it, so ">" and "<" are plain text there.
			if st.quote != 0 {
				if c == st.quote {
					st.quote = 0
					st.attr = ""
				}
				i++
				continue
			}
			switch {
			case c == '>':
				// The tag closes. A start tag of a script or raw-text element moves
				// the parser into that element's body.
				i++
				switch {
				case st.endTag:
					st = htmlState{kind: ctxText}
				case st.tag == "script":
					st = htmlState{kind: ctxScript, tag: "script"}
				case rawTextTags[st.tag]:
					st = htmlState{kind: ctxRawText, tag: st.tag}
				default:
					st = htmlState{kind: ctxText}
				}
			case c == '=':
				st.attr = attrNameBefore(s, i)
				st.afterEq = true
				i++
			case (c == '"' || c == '\'') && st.afterEq:
				// A quote right after "=" opens a quoted attribute value.
				st.quote = c
				st.afterEq = false
				st.valueStart = i + 1
				i++
			case isSpace(c):
				i++
			default:
				st.afterEq = false
				i++
			}
		}
	}
	return st
}

// injectsCode reports whether s, placed right after a breakout, would add
// something a browser runs: markup, an event-handler attribute, or a
// javascript: URL. Plain text such as x="  does not count.
func injectsCode(s string) bool {
	return markupStartPattern.MatchString(s) || codeHandlerPattern.MatchString(s) || strings.Contains(asciiLower(s), "javascript:")
}

// hasJSScheme reports whether a value starts with a javascript: URL, ignoring
// the leading whitespace browsers strip from URLs.
func hasJSScheme(s string) bool {
	return strings.HasPrefix(asciiLower(strings.TrimLeft(s, " \t\r\n\f")), "javascript:")
}

// looksLikeCode reports whether s contains a call, an assignment, or a
// template-literal call, which is enough to be JavaScript that runs.
func looksLikeCode(s string) bool {
	return strings.ContainsAny(s, "(=`")
}

// executesAt reports whether payload, placed at a position whose parser state
// is st, would run or render as markup in the browser. valueEmpty is true when
// the payload is the first thing in its attribute value.
func executesAt(st htmlState, payload string, valueEmpty bool) bool {
	switch st.kind {
	case ctxText:
		// Markup in text becomes live elements.
		return markupStartPattern.MatchString(payload)

	case ctxAttribute:
		if st.quote != 0 {
			// A quoted value must be closed first, and what follows the quote must
			// inject code.
			if k := strings.IndexByte(payload, st.quote); k >= 0 && injectsCode(payload[k+1:]) {
				return true
			}
		} else {
			// An unquoted value (or an attribute name position) ends at whitespace,
			// "/" or ">".
			if k := strings.IndexAny(payload, " \t\r\n\f/>"); k >= 0 && injectsCode(payload[k:]) {
				return true
			}
		}
		// A javascript: URL is code when it is the whole value of a URL attribute.
		return valueEmpty && urlAttributes[st.attr] && hasJSScheme(payload)

	case ctxRawText:
		// The payload must write the element's own end tag, then inject markup.
		if k := findEndTag(asciiLower(payload), st.tag); k >= 0 {
			return markupStartPattern.MatchString(payload[k+len("</"+st.tag):])
		}
		return false

	case ctxComment:
		// The payload must close the comment, then inject markup.
		if k := strings.Index(payload, st.closer); k >= 0 {
			return markupStartPattern.MatchString(payload[k+len(st.closer):])
		}
		return false

	case ctxScript:
		return executesInScript(st, payload)
	}
	return false
}

// executesInScript reports whether payload runs when it lands inside a script
// body in state st. An end tag in the payload closes the script, so anything
// before it is script code, and anything after it is markup.
func executesInScript(st htmlState, payload string) bool {
	if k := findEndTag(asciiLower(payload), "script"); k >= 0 {
		if k == 0 {
			// The payload closes the script at once, so its markup after the end tag runs.
			return markupStartPattern.MatchString(payload[len("</script"):])
		}
		// Code before the end tag runs only if it is valid in the current state.
		return executesInScript(st, payload[:k])
	}
	switch {
	case st.jsComment == '/':
		// A line comment hides the payload until a newline, after which code may run.
		k := strings.IndexByte(payload, '\n')
		return k >= 0 && looksLikeCode(payload[k+1:])
	case st.jsComment == '*':
		// A block comment hides the payload until "*/".
		k := strings.Index(payload, "*/")
		return k >= 0 && looksLikeCode(payload[k+2:])
	case st.quote == '`':
		// A template literal runs any ${...} expression without breaking out.
		if strings.Contains(payload, "${") {
			return true
		}
		k := strings.IndexByte(payload, '`')
		return k >= 0 && looksLikeCode(payload[k+1:])
	case st.quote != 0:
		// A string literal ends only at its matching quote, then the rest must be code.
		k := strings.IndexByte(payload, st.quote)
		return k >= 0 && looksLikeCode(payload[k+1:])
	default:
		// Plain code runs as it is. A payload that opens with markup does not,
		// since "<" is not valid JavaScript there.
		return !strings.HasPrefix(payload, "<") && looksLikeCode(payload)
	}
}

// payloadExecutes reports whether a payload that appears verbatim in body would
// run in the browser. Every occurrence is checked, because one occurrence can
// be inert (inside a comment) while another one executes. The state at each
// occurrence comes from stateAt.
func payloadExecutes(body, payload string) bool {
	if payload == "" {
		return false
	}
	// A bound on occurrences keeps a pathological response from making this
	// quadratic.
	const maxOccurrences = 64
	from := 0
	for n := 0; n < maxOccurrences; n++ {
		idx := strings.Index(body[from:], payload)
		if idx < 0 {
			return false
		}
		idx += from
		st := stateAt(body, idx)
		valueEmpty := st.kind == ctxAttribute && ((st.quote != 0 && st.valueStart == idx) || (st.quote == 0 && st.afterEq))
		if executesAt(st, payload, valueEmpty) {
			return true
		}
		from = idx + 1
	}
	return false
}

// locateContext reports the parser state at the first occurrence of payload in
// body, for logs and test messages.
func locateContext(body, payload string) reflectionContext {
	idx := strings.Index(body, payload)
	if idx < 0 {
		return ctxText
	}
	return stateAt(body, idx).kind
}

// htmlResponse reports whether a response is HTML the browser would render.
// JSON, plain text, and other non-HTML bodies do not execute reflected input,
// whatever characters they echo back.
func htmlResponse(contentType string) bool {
	ct := strings.ToLower(contentType)
	return ct == "" || strings.Contains(ct, "html")
}

// rendersAsHTML reports whether a response would be rendered as a page in the
// browser: HTML content type, and not sent as an attachment. A download
// reflects input into a file the browser saves rather than runs.
func rendersAsHTML(contentType, disposition string) bool {
	if strings.Contains(strings.ToLower(disposition), "attachment") {
		return false
	}
	return htmlResponse(contentType)
}
