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

// Element sets for the handlers that fire without the user doing anything. An
// injected handler is inert on an element that cannot fire it.
var (
	// autofocusTags are the elements that honor the autofocus attribute. Checked
	// in headless Chrome: <input autofocus> fires its onfocus on load, but
	// <a href autofocus> does not.
	autofocusTags = map[string]bool{"button": true, "input": true, "select": true, "textarea": true}
	// errorEventTags are the elements that fire an error event when a resource fails.
	errorEventTags = map[string]bool{
		"img": true, "input": true, "script": true, "iframe": true, "video": true,
		"audio": true, "object": true, "embed": true, "link": true, "source": true, "track": true,
	}
	// loadEventTags are the elements that fire a load event.
	loadEventTags = map[string]bool{
		"img": true, "iframe": true, "script": true, "link": true, "object": true,
		"embed": true, "body": true, "frame": true, "svg": true,
	}
)

// eventHandlerAttrPattern finds an injected event-handler attribute, such as onerror=.
// Its group 1 is the handler name without "on".
var eventHandlerAttrPattern = regexp.MustCompile(`(?i)\bon([a-z]+)\s*=`)

// tagNameAttrPattern finds the start of an element and captures its name.
var tagNameAttrPattern = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9-]*)`)

// handlerUse is one event-handler attribute an injection adds, and the element
// that carries it.
type handlerUse struct {
	name  string
	owner string
}

// injectedHandlers lists the event handlers in injected text. Each handler belongs
// to the nearest element opened before it. A handler that comes before any new
// element belongs to host, the element the injection breaks out into.
func injectedHandlers(injected, host string) []handlerUse {
	tags := tagNameAttrPattern.FindAllStringSubmatchIndex(injected, -1)
	var out []handlerUse
	for _, m := range eventHandlerAttrPattern.FindAllStringSubmatchIndex(injected, -1) {
		owner := host
		for _, t := range tags {
			if t[0] < m[0] {
				owner = asciiLower(injected[t[2]:t[3]])
			}
		}
		out = append(out, handlerUse{name: "on" + asciiLower(injected[m[2]:m[3]]), owner: owner})
	}
	return out
}

// handlerFiresOn reports whether an event handler fires on an element named owner
// without the user doing anything. Only the automatic events count: load and error
// on the elements that fetch a resource, toggle on details, begin on SVG timing,
// and focus only when autofocus is set on an element that can take it. A handler
// such as onclick or onmouseover needs the victim to act, so it is not counted.
func handlerFiresOn(name, injected, owner string) bool {
	switch name {
	case "onerror":
		return errorEventTags[owner]
	case "onload":
		return loadEventTags[owner]
	case "ontoggle":
		return owner == "details"
	case "onstart":
		return owner == "marquee"
	case "onbegin":
		return owner == "animate" || owner == "set" || owner == "animatemotion" || owner == "animatetransform"
	case "onfocus":
		lower := asciiLower(injected)
		return strings.Contains(lower, "autofocus") && (autofocusTags[owner] || strings.Contains(lower, "tabindex"))
	}
	return false
}

// handlersInertOn reports whether an injected run cannot execute because every
// handler it adds is one that does not fire automatically on the element it lands
// on. Injected text that opens a <script> is never inert: that runs whatever the
// handlers do.
func handlersInertOn(injected, host string) bool {
	if strings.Contains(asciiLower(injected), "<script") {
		return false
	}
	uses := injectedHandlers(injected, host)
	if len(uses) == 0 {
		return false
	}
	for _, u := range uses {
		if handlerFiresOn(u.name, injected, u.owner) {
			return false
		}
	}
	return true
}

// executesAt reports whether payload, placed at a position whose parser state
// is st, would run or render as markup in the browser. valueEmpty is true when
// the payload is the first thing in its attribute value.
func executesAt(st htmlState, payload string, valueEmpty bool) bool {
	switch st.kind {
	case ctxText:
		// Markup in text becomes live elements, but a handler that needs the user
		// to act does not run on its own.
		return markupStartPattern.MatchString(payload) && !handlersInertOn(payload, "")

	case ctxAttribute:
		if st.quote != 0 {
			// A quoted value must be closed first, and what follows the quote must
			// inject code.
			if k := strings.IndexByte(payload, st.quote); k >= 0 && injectsCode(payload[k+1:]) && !handlersInertOn(payload[k+1:], st.tag) {
				return true
			}
		} else {
			// An unquoted value (or an attribute name position) ends at whitespace,
			// "/" or ">".
			if k := strings.IndexAny(payload, " \t\r\n\f/>"); k >= 0 && injectsCode(payload[k:]) && !handlersInertOn(payload[k:], st.tag) {
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
	return scriptPayloadRuns(st, payload)
}

// scriptPayloadRuns walks payload with the JavaScript lexer's rules, starting in
// the string or comment the landing point is in. Only characters outside strings
// and comments are code. The payload runs when some code character calls,
// assigns, or opens a template expression.
//
// The walk matters because the payload's own quotes can be the ones that open a
// string. A payload such as ';alert(1);' that lands in code is inert: its
// leading quote starts a string, and nothing after it is code.
func scriptPayloadRuns(st htmlState, payload string) bool {
	quote := st.quote
	comment := st.jsComment
	for i := 0; i < len(payload); i++ {
		c := payload[i]
		// next is the byte after c, or 0 at the end of the payload.
		var next byte
		if i+1 < len(payload) {
			next = payload[i+1]
		}
		switch {
		case comment == '/':
			// A line comment ends at a newline.
			if c == '\n' {
				comment = 0
			}
		case comment == '*':
			// A block comment ends at "*/".
			if c == '*' && next == '/' {
				comment = 0
				i++
			}
		case quote == '`':
			// Inside a template literal, ${ opens an expression that runs, and a
			// backtick closes the literal.
			if c == '$' && next == '{' {
				return true
			}
			if c == '\\' {
				i++
			} else if c == '`' {
				quote = 0
			}
		case quote != 0:
			// Inside a string literal only the matching, unescaped quote ends it.
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '/' && next == '/':
			comment = '/'
			i++
		case c == '/' && next == '*':
			comment = '*'
			i++
		case c == '<' && i == 0:
			// A payload that opens with markup is not valid JavaScript at a code
			// position, so nothing it carries runs.
			return false
		case c == '"' || c == '\'':
			quote = c
		case c == '`':
			// A backtick right after a name is a tagged-template call, which runs.
			if i > 0 && isNameChar(payload[i-1]) {
				return true
			}
			quote = c
		case c == '(' || c == '=':
			return true
		}
	}
	return false
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

// payloadRunsInScriptBody reports whether payload executes when body is loaded as
// a script file, such as a JSONP response. The body is read as the code of a
// <script> element, so the state at each occurrence is the state the browser is
// in there. A script file cannot be closed by its own end tag, so the payload is
// judged with the lexer alone, and a "</script>" in it does not count as a breakout.
func payloadRunsInScriptBody(body, payload string) bool {
	if payload == "" {
		return false
	}
	const prefix = "<script>"
	wrapped := prefix + body
	from := len(prefix)
	// The same occurrence bound as payloadExecutes keeps this linear.
	const maxOccurrences = 64
	for n := 0; n < maxOccurrences; n++ {
		idx := strings.Index(wrapped[from:], payload)
		if idx < 0 {
			return false
		}
		at := from + idx
		if scriptPayloadRuns(stateAt(wrapped, at), payload) {
			return true
		}
		from = at + 1
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
