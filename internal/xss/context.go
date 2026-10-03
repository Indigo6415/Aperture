package xss

import "strings"

// reflectionContext is where in the HTML a reflected payload begins. It decides
// whether the browser would parse the payload as code or just show it as text.
type reflectionContext string

const (
	ctxText      reflectionContext = "html-text"
	ctxAttribute reflectionContext = "attribute"
	ctxScript    reflectionContext = "script"
	ctxComment   reflectionContext = "comment"
	ctxRawText   reflectionContext = "raw-text"
	ctxUnknown   reflectionContext = "unknown"
)

// rawTextTags are elements whose content is shown verbatim rather than parsed
// as markup: a payload placed inside one never runs.
var rawTextTags = []string{"textarea", "title", "style", "noscript"}

// locateContext reports the context at the first occurrence of payload in
// body. It is a lightweight state check over the text before the payload, not
// a full HTML parser: it looks for an unclosed comment, raw-text element,
// script element, or tag, which covers the contexts the payload set targets.
func locateContext(body, payload string) reflectionContext {
	idx := strings.Index(body, payload)
	if idx < 0 {
		return ctxUnknown
	}
	prefix := body[:idx]
	lower := strings.ToLower(prefix)

	// An opening comment with no close after it means the payload is commented out.
	if open := strings.LastIndex(lower, "<!--"); open >= 0 && !strings.Contains(lower[open:], "-->") {
		return ctxComment
	}
	for _, tag := range rawTextTags {
		open := strings.LastIndex(lower, "<"+tag)
		if open >= 0 && !strings.Contains(lower[open:], "</"+tag) {
			return ctxRawText
		}
	}
	if open := strings.LastIndex(lower, "<script"); open >= 0 && !strings.Contains(lower[open:], "</script") {
		return ctxScript
	}
	// A "<" after the last ">" means the payload sits inside a tag's attributes.
	if strings.LastIndex(prefix, "<") > strings.LastIndex(prefix, ">") {
		return ctxAttribute
	}
	return ctxText
}

// openAttributeQuote returns the quote character the payload's position is
// inside, or 0 when it is unquoted. It scans the current tag only.
func openAttributeQuote(body, payload string) byte {
	idx := strings.Index(body, payload)
	if idx < 0 {
		return 0
	}
	prefix := body[:idx]
	seg := prefix[strings.LastIndex(prefix, "<")+1:]
	var quote byte
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if quote != 0 {
			// Inside a quoted value, only the matching quote can end it.
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
		}
	}
	return quote
}

// payloadExecutes reports whether a payload that appears verbatim in body would
// run in the browser. The rules follow the context:
//   - comments and raw-text elements never execute;
//   - inside a quoted attribute, the payload must close that quote first;
//   - inside a script block, markup needs "</script" to escape, while
//     script-level code runs as it is;
//   - in plain text, only injected markup executes.
func payloadExecutes(body, payload string) bool {
	switch locateContext(body, payload) {
	case ctxComment, ctxRawText:
		return false
	case ctxAttribute:
		switch openAttributeQuote(body, payload) {
		case '"':
			return strings.Contains(payload, `"`)
		case '\'':
			return strings.Contains(payload, "'")
		default:
			return strings.ContainsAny(payload, " \t>")
		}
	case ctxScript:
		return strings.Contains(strings.ToLower(payload), "</script") || !strings.HasPrefix(payload, "<")
	case ctxText:
		return strings.Contains(payload, "<")
	}
	// Unknown context: be conservative and let the browser check decide.
	return true
}

// htmlResponse reports whether a response is HTML the browser would render.
// JSON, plain text, and other non-HTML bodies do not execute reflected input,
// whatever characters they echo back.
func htmlResponse(contentType string) bool {
	ct := strings.ToLower(contentType)
	return ct == "" || strings.Contains(ct, "html")
}
