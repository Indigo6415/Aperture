package xss

// catalog.go turns dalfox's payload tables (catalog_dalfox.go) into payload
// families the scanner fires. A family is one technique with an ordered list of
// candidate payloads; the scan walks the families round-robin under a per-point
// budget (see xss.go), so the most useful candidate of every technique is tried
// before any one technique's tail.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// classMarkerSuffix and idMarkerSuffix turn the run's canary into the class and
// id values the marker-carrying templates write. They share the canary as a
// prefix, so a reflected marker still counts as a reflection of this run.
const (
	classMarkerSuffix = "c"
	idMarkerSuffix    = "i"
)

// fillCatalogMarkers replaces a template's {CLASS}, {ID} and {JS} placeholders.
// {JS} is left alone; callers substitute a primitive before calling this.
func fillCatalogMarkers(tmpl, canary string) string {
	return strings.NewReplacer(
		"{CLASS}", canary+classMarkerSuffix,
		"{ID}", canary+idMarkerSuffix,
	).Replace(tmpl)
}

// dalfoxHandlerPriority lists the event handlers that fire with no user action,
// or that the common WAF rule sets miss, ahead of the rest of the table. Within a
// family the list order is the try order, so these come first.
var dalfoxHandlerPriority = []string{
	"onerror", "onload", "onfocus", "onmouseover", "ontoggle", "onpointerover",
	"onanimationstart", "onpointerenter", "onmouseenter", "onclick", "oninput",
	"onchange", "onkeydown", "onwheel", "onbeforeinput", "onformdata",
}

// automaticHandlerNames keeps the handlers that fire without the user acting:
// the ones handlerFiresOn counts. An interaction handler such as onclick would
// only be sent and never counted, so it is left out of the family.
func automaticHandlerNames(names []string) []string {
	auto := map[string]bool{"onerror": true, "onload": true, "ontoggle": true, "onfocus": true}
	var out []string
	for _, n := range names {
		if auto[n] {
			out = append(out, n)
		}
	}
	return out
}

// orderedHandlerNames returns dalfoxEventHandlerNames with the priority handlers
// moved to the front, in priority order.
func orderedHandlerNames() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(dalfoxEventHandlerNames))
	for _, n := range dalfoxHandlerPriority {
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range dalfoxEventHandlerNames {
		if !seen[n] {
			out = append(out, n)
		}
	}
	return out
}

// handlerWrappers are the attribute contexts an event handler is injected into:
// a double-quoted value, a single-quoted value, and an unquoted value. Each closes
// the value and then opens a new attribute carrying the handler.
var handlerWrappers = []string{
	`" %s x="`,
	`' %s x='`,
	` %s x=`,
}

// jsBreakoutWrappers close a JavaScript string or template literal and then run
// the primitive as code. The leading and trailing parts are chosen so the rest
// of the original statement stays well formed.
var jsBreakoutWrappers = []string{
	"%s",
	`";%s;"`,
	`';%s;'`,
	"`;%s;`",
}

// protocolVariants are the ways to write javascript: in a URL attribute. Each
// entry is a format string whose %s is the primitive. The whitespace and case
// variants are the ones a browser normalizes before it resolves the URL.
var protocolVariants = []string{
	"javascript:%s",
	"Javascript:%s",
	"jAvAsCrIpT:%s",
	"java\tscript:%s",
	"java\nscript:%s",
	"javascript\t:%s",
	"\tjavascript:%s",
	"\njavascript:%s",
	"javas\tcript:%s",
	"javasscriptcript:%s",
	"javascriptjavascript:%s",
}

// markerAttrPattern matches a marker attribute in a template, such as ` class={CLASS}`
// or the slash-separated `/ID={ID}` form.
// Removing it gives the short form a length-limited reflection can still carry.
var markerAttrPattern = regexp.MustCompile(`[\s/]+(?i:class|id)=\{(?:CLASS|ID)\}`)

// compactTemplates are the dalfox HTML templates with their marker attributes
// removed, sorted shortest first. A reflection cut off at a length limit still
// fits the short forms, and the marker is not needed for a literal match.
func compactTemplates() []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range dalfoxHTMLTemplates {
		c := markerAttrPattern.ReplaceAllString(t, "")
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out
}

// buildCatalogFamilies returns every payload family in try order, with its
// candidates filled for this run's canary. A run calls it once and keeps the result.
//
// DOM clobbering is not a family here: a clobbering element is inert on its own,
// and it only executes through an application's own script, which a reflection
// scan cannot see. The clobbering templates are kept in catalog_dalfox.go for a
// future DOM-gadget check.
//
// The order is the order a point is tried in: families come round-robin, so the
// first entry of every family runs before the second entry of any of them.
func buildCatalogFamilies(canary string) []payloadDef {
	fill := func(tmpl, prim string) string {
		return fillCatalogMarkers(strings.ReplaceAll(tmpl, "{JS}", prim), canary)
	}

	var htmlList []string
	for _, prim := range dalfoxJSPrimitivesSmall {
		for _, t := range dalfoxHTMLTemplates {
			htmlList = append(htmlList, fill(t, prim))
		}
	}

	var eventList []string
	for _, prim := range dalfoxJSPrimitivesSmall[:1] {
		for _, w := range handlerWrappers {
			for _, name := range automaticHandlerNames(orderedHandlerNames()) {
				// onfocus only runs with autofocus set, so its wrapper carries it.
				attr := name + "=" + prim
				if name == "onfocus" {
					attr = "autofocus " + attr
				}
				eventList = append(eventList, fillCatalogMarkers(fmt.Sprintf(w, attr), canary))
			}
		}
	}

	var jsList []string
	for _, prim := range dalfoxJSPrimitives {
		for _, w := range jsBreakoutWrappers {
			jsList = append(jsList, fmt.Sprintf(w, prim))
		}
	}

	var mxssList []string
	for _, prim := range dalfoxJSPrimitivesSmall[:1] {
		for _, t := range dalfoxMXSSTemplates {
			mxssList = append(mxssList, fill(t, prim))
		}
	}

	var protoList []string
	for _, prim := range dalfoxJSPrimitivesSmall {
		for _, v := range protocolVariants {
			protoList = append(protoList, fmt.Sprintf(v, prim))
		}
	}

	var compactList []string
	for _, t := range compactTemplates() {
		compactList = append(compactList, strings.ReplaceAll(t, "{JS}", dalfoxJSPrimitivesSmall[0]))
	}

	return []payloadDef{
		{
			id: "html-injection", name: "HTML tag injection (dalfox template catalog)", severity: "high",
			list: func(string) []string { return htmlList }, match: substringMatch,
		},
		{
			id: "event-handler-injection", name: "Event-handler attribute injection (dalfox handler catalog)", severity: "high",
			list: func(string) []string { return eventList }, match: substringMatch,
		},
		{
			id: "js-context-primitives", name: "JavaScript-context execution primitives", severity: "high",
			list: func(string) []string { return jsList }, match: substringMatch,
		},
		{
			id: "mxss-templates", name: "Mutation XSS (parser differential) templates", severity: "high",
			list: func(string) []string { return mxssList }, match: substringMatch,
		},
		{
			id: "protocol-uri-injection", name: "javascript: URI injection in href/src/action", severity: "medium",
			list: func(string) []string { return protoList }, match: protocolURIMatch,
		},
		{
			id: "compact-injection", name: "Short injection without marker attributes", severity: "high",
			list: func(string) []string { return compactList }, match: substringMatch,
		},
	}
}

// protocolURIMatch judges a javascript: URI payload. A browser drops tabs and
// newlines from a URL before it resolves the scheme, so both the attribute window
// and the payload are compared with them removed. The payload must sit in a URL
// attribute to count.
func protocolURIMatch(body, payload, canary string) (string, bool) {
	if !strings.Contains(body, payload) {
		return "", false
	}
	idx := strings.Index(body, payload)
	start := max(idx-80, 0)
	window := stripURLWhitespace(body[start:idx] + payload)
	if !hrefAttrPattern.MatchString(window) {
		return "", false
	}
	if hasJSScheme(stripURLWhitespace(payload)) {
		return payload, true
	}
	return "", false
}

// stripURLWhitespace removes the tab, newline and carriage-return characters a
// browser ignores inside a URL.
func stripURLWhitespace(s string) string {
	return urlWhitespaceReplacer.Replace(s)
}

// urlWhitespaceReplacer is the removal stripURLWhitespace applies.
var urlWhitespaceReplacer = strings.NewReplacer("\t", "", "\n", "", "\r", "")
