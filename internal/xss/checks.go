package xss

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// pointFinding pairs a candidate Finding with the injectionPoint that produced
// it. The point's parameter and payload are kept so the browser check can
// replay exactly this request.
type pointFinding struct {
	key     string
	finding Finding
	// param and payload let verifyPointFinding rebuild the request with a
	// different value. browserable is false for header and POST injections.
	param       string
	payload     string
	browserable bool
}

// escapedSighting is one injection point that reflects input without any payload
// running: the probe or a payload came back in the response, but nothing
// executed (it was encoded, stripped, or sat somewhere inert). Tracked separately
// from a confirmed Finding and reported once per point as a low-noise "reflected
// but not executable" informational note (see aggregateEscapedModule).
type escapedSighting struct {
	key        string
	descriptor string
	evidence   string
	method     string
	statusCode int
	request    CapturedRequest
}

// pointOutcome is what the scan of one injection point found.
type pointOutcome struct {
	// family indexes deps.families for the technique that confirmed the point.
	family  int
	finding *pointFinding
	// escaped is set when the point reflected the run's marker without
	// executing anything. See escapedSighting.
	escaped *escapedSighting
}

// indexedPoint is an injection point with its position in deps.points, so the
// parallel scan can write each outcome back in order.
type indexedPoint struct {
	idx int
	pt  injectionPoint
}

// candidate is one payload to send, and the family (index into deps.families)
// that it belongs to.
type candidate struct {
	family  int
	payload string
}

// candidates returns the payloads to try at a point, in order. Every family's
// candidates that the probe allows are interleaved round-robin, so each
// technique's best candidate comes before any technique's tail. Duplicates across
// families are dropped, and the list is cut at the run's budget.
func (d runDeps) candidates(probe *probeResult) []candidate {
	lists := make([][]string, len(d.families))
	for i, fam := range d.families {
		var all []string
		if fam.list != nil {
			all = fam.list(d.canary)
		} else {
			all = []string{fam.build(d.canary)}
		}
		for _, p := range all {
			if probe.viable(p) {
				lists[i] = append(lists[i], p)
			}
		}
	}

	seen := map[string]bool{}
	var out []candidate
	for round := 0; len(out) < d.budget; round++ {
		progressed := false
		for i, list := range lists {
			// A family with fewer candidates than this round has run out.
			if round >= len(list) {
				continue
			}
			progressed = true
			p := list[round]
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, candidate{family: i, payload: p})
			if len(out) >= d.budget {
				break
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// scanPoints runs scanPoint against every injection point in parallel, reporting
// one progress check per point. Each outcome lands at its point's index.
func scanPoints(ctx context.Context, deps runDeps) []pointOutcome {
	client := newClient()
	items := make([]indexedPoint, len(deps.points))
	for i, pt := range deps.points {
		items[i] = indexedPoint{idx: i, pt: pt}
	}
	outcomes := make([]pointOutcome, len(deps.points))
	scanprogress.Each(deps.rep, 0, items, func(it indexedPoint) scanprogress.Check {
		return scanprogress.Check{ID: pointKey(it.pt), Label: pointDescriptor(it.pt), Group: "Reflected XSS"}
	}, func(it indexedPoint) (int, error) {
		o := scanPoint(ctx, deps, client, it.pt)
		outcomes[it.idx] = o
		if o.finding != nil {
			return 1, nil
		}
		return 0, nil
	})
	return outcomes
}

// scanPoint probes one injection point and then tries the candidates that
// survive the probe. It stops at the first payload that executes, so each point
// yields at most one finding, attributed to the technique that landed it.
func scanPoint(ctx context.Context, deps runDeps, client *http.Client, pt injectionPoint) pointOutcome {
	probe := probePoint(ctx, deps.sem, client, pt, deps.canary, deps.req.Headers)
	// A point the probe did not reflect cannot reflect a payload either, so the
	// point is skipped without spending the payload budget on it. A blocked
	// probe says nothing, so that point keeps every candidate.
	if !probe.reflected && !probe.blocked {
		return pointOutcome{}
	}

	var escaped *escapedSighting
	for _, c := range deps.candidates(&probe) {
		if ctx.Err() != nil {
			break
		}
		res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, c.payload, deps.req.Headers)
		if res.Err != nil {
			continue
		}
		fam := deps.families[c.family]
		// A script file (a JSONP response, say) runs its reflections as code, so it
		// is judged as a script body. Every other non-HTML response is inert: a JSON
		// or plain-text body never runs reflected markup, and an attachment is saved.
		if isJavaScriptResponse(res.ContentType) {
			if evidence, ok := fam.match(res.Body, c.payload, deps.canary); ok && payloadRunsInScriptBody(res.Body, c.payload) {
				return pointOutcome{family: c.family, finding: confirmedPointFinding(pt, fam, c.payload, evidence, res)}
			}
			continue
		}
		if !rendersAsHTML(res.ContentType, res.Disposition) {
			continue
		}
		// Both the payload's own match and the parser-state check must agree before
		// a reflection counts as executable.
		if evidence, ok := fam.match(res.Body, c.payload, deps.canary); ok && payloadExecutes(res.Body, c.payload) {
			return pointOutcome{family: c.family, finding: confirmedPointFinding(pt, fam, c.payload, evidence, res)}
		}
		// The payload is inert here (a comment, a raw-text element, or a quoted
		// attribute it cannot close). If the marker still shows, the input is
		// reflected but not executable, which is the escaped note.
		if escaped == nil && probe.blocked && reflectsCanary(res.Body, deps.canary) {
			escaped = escapedFrom(pt, deps.canary, res)
		}
	}
	// A reflected probe with no executing payload is the same observation: the
	// input comes back, but nothing runs. The probe's own response is the evidence.
	if escaped == nil && probe.reflected {
		escaped = escapedFrom(pt, probe.marker, &probe.res)
	}
	return pointOutcome{escaped: escaped}
}

// confirmedPointFinding builds the finding for a payload that executed at pt.
func confirmedPointFinding(pt injectionPoint, fam payloadDef, payload, evidence string, res *xssResult) *pointFinding {
	return &pointFinding{
		key:         pointKey(pt),
		param:       pt.Param,
		payload:     payload,
		browserable: pt.Kind == kindQuery || (pt.Kind == kindForm && pt.Method == "GET"),
		finding: Finding{
			Label: fmt.Sprintf("%s reflects an unescaped %s", capitalize(pointDescriptor(pt)), strings.ToLower(fam.name)),
			Detail: fmt.Sprintf(
				"Set %s to %s and the response reflected it verbatim -- no HTML, attribute, or JavaScript-string escaping -- which a browser parses as live markup/script rather than inert text.",
				pointDescriptor(pt), payload,
			),
			Evidence:   evidence,
			Method:     pt.Method,
			StatusCode: res.StatusCode,
			Request:    &res.Request,
			Confidence: ConfidenceLikely,
		},
	}
}

// escapedFrom builds the escaped note for pt from the response that reflected
// marker.
func escapedFrom(pt injectionPoint, marker string, res *xssResult) *escapedSighting {
	return &escapedSighting{
		key: pointKey(pt), descriptor: pointDescriptor(pt), evidence: marker,
		method: pt.Method, statusCode: res.StatusCode, request: res.Request,
	}
}

// isJavaScriptResponse reports whether a response is a script file, which a page
// loads with <script src>, rather than a document.
func isJavaScriptResponse(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// reflectsCanary reports whether the scan's marker token is in body, either as
// written or after HTML character references are decoded. A page that echoes
// input as &#x61;-style references still echoes it, and a browser shows that
// text rather than running it.
func reflectsCanary(body, canary string) bool {
	return strings.Contains(body, canary) || strings.Contains(html.UnescapeString(body), canary)
}

// aggregateEscapedModule builds the "reflected but not executable" info
// module from every payload module's escaped sightings, keeping only points
// that no module actually confirmed (confirmedPoints) and only the first
// sighting per point -- see escapedSighting's doc comment for why this
// keeps the report to one note per point.
func aggregateEscapedModule(all []escapedSighting, confirmedPoints map[string]bool) ModuleResult {
	seen := map[string]bool{}
	var findings []Finding
	for _, e := range all {
		if confirmedPoints[e.key] || seen[e.key] {
			continue
		}
		seen[e.key] = true
		req := e.request
		findings = append(findings, Finding{
			Label:    fmt.Sprintf("%s reflects input, but it does not execute", capitalize(e.descriptor)),
			Detail:   "The scan's own marker token came back in the response, but none of the payloads ran: each was encoded, stripped, or sat somewhere the browser does not parse as code (a comment, a textarea or title, or a quoted attribute with nothing to break out with). Worth a manual look anyway, since an encoding or context this scanner did not try can still produce exploitable reflected XSS.",
			Evidence: e.evidence,
			Method:   e.method, StatusCode: e.statusCode,
			Request:    &req,
			Confidence: ConfidenceHeuristic,
		})
	}
	if findings == nil {
		findings = []Finding{}
	}
	return ModuleResult{ID: "reflected-escaped", Name: "Reflected input (not executable)", Severity: "info", Findings: findings}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// domSinkPattern/domTaintSourcePattern are the two halves of
// runDomSinkModule's static heuristic: a dangerous sink that renders a
// string as live HTML/script, and a source the client itself doesn't
// control (the URL fragment/query, document.referrer, window.name, ...).
// Flagging only inline scripts where *both* appear mirrors the same
// lightweight "no real data-flow tracing" approach every scanner in this
// codebase takes elsewhere -- a real finding needs the tainted value to
// actually reach the sink unescaped at runtime, which this can't confirm from
// markup alone. Every Finding here is therefore a lead to confirm manually,
// reported at low severity with heuristic confidence.
var (
	// domSinkPattern lists the calls and assignments that render a string as live
	// HTML, run it as code, or hand it to a URL-navigating or selector-parsing API.
	domSinkPattern = regexp.MustCompile(
		`(?i)\.(?:innerHTML|outerHTML)\s*=|document\.write(?:ln)?\s*\(|insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'` + "`" + `]|setInterval\s*\(\s*["'` + "`" + `]|execScript\s*\(|\$\([^)]*\)\s*\.\s*html\s*\(` +
			`|\.srcdoc\s*=[^=]|createContextualFragment\s*\(|location(?:\.href)?\s*=[^=]|location\.(?:assign|replace)\s*\(|window\.open\s*\(|(?:\$|jQuery)\s*\(\s*(?:location|window\.location|document\.URL)`,
	)
	// domTaintSourcePattern lists browser-side values an attacker controls
	// through the URL, the referrer, a window name, or a postMessage they can
	// send from another origin.
	domTaintSourcePattern = regexp.MustCompile(
		`(?i)location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|cookie|baseURI)|window\.name|addEventListener\s*\(\s*["']message["']`,
	)
	// domSanitizerPattern names a sanitizer or escaper; a sink on the same line
	// as one of these is treated as already protected.
	domSanitizerPattern = regexp.MustCompile(`(?i)DOMPurify|sanitiz|escapeHtml|encodeHTML`)
	inlineScriptPattern = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
)

// sinkSanitized reports whether the line holding sink's first occurrence in
// script also calls a sanitizer. That line is then treated as protected, so
// it is not reported.
func sinkSanitized(script, sink string) bool {
	idx := strings.Index(script, sink)
	if idx < 0 {
		return false
	}
	// Walk out to the line's edges, which are the nearest newlines.
	start := strings.LastIndexByte(script[:idx], '\n') + 1
	end := len(script)
	if nl := strings.IndexByte(script[idx:], '\n'); nl >= 0 {
		end = idx + nl
	}
	return domSanitizerPattern.MatchString(script[start:end])
}

// runDomSinkModule scans crawled pages for a tainted source and a rendering
// sink in the same script. Inline <script> blocks are read from each page's
// markup. A same-origin external script (crawled as its own entry with
// Script set) is read whole.
func runDomSinkModule(pages []crawledPage) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, pg := range pages {
		var scripts []string
		if pg.Script {
			scripts = []string{pg.Body}
		} else {
			for _, m := range inlineScriptPattern.FindAllStringSubmatch(pg.Body, -1) {
				scripts = append(scripts, m[1])
			}
		}
		for _, script := range scripts {
			where := "an inline <script> block"
			if pg.Script {
				where = "the external script " + pg.URL
			}
			// The AST taint analysis is the primary check. A script that does not
			// parse falls through to the regex heuristic below.
			if flows, err := analyzeDOMScript(script); err == nil {
				for _, f := range flows {
					key := pg.URL + "|" + f.sink
					if seen[key] {
						continue
					}
					seen[key] = true
					findings = append(findings, domFlowFinding(pg, where, f, script))
				}
				continue
			}
			source := domTaintSourcePattern.FindString(script)
			sink := domSinkPattern.FindString(script)
			if source == "" || sink == "" || sinkSanitized(script, sink) {
				continue
			}
			key := pg.URL + "|" + sink
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{
				Label: fmt.Sprintf("Script combines a tainted source (%s) with a dangerous sink (%s)", source, sink),
				Detail: fmt.Sprintf(
					"Found on %s: %s reads attacker-influenceable data (%s) and passes a value into %s without this scanner seeing it sanitized/encoded first. This is a static heuristic over the page's own script, not a confirmed DOM XSS -- confirm manually by tracing whether the tainted value actually reaches the sink unescaped at runtime (e.g. craft a URL whose #hash/query contains a payload and watch it execute).",
					pg.URL, where, source, sink,
				),
				Evidence:   snippetAround(script, sink),
				Method:     "GET",
				Request:    &CapturedRequest{Method: "GET", URL: pg.URL},
				Confidence: ConfidenceHeuristic,
			})
		}
	}
	if findings == nil {
		findings = []Finding{}
	}
	return findings
}

// domFlowFinding reports one flow the AST analysis traced from a source to a
// sink on a page. The finding stays heuristic: the analysis is a static model of
// the script, so a flow is a strong lead, not a confirmed DOM XSS.
func domFlowFinding(pg crawledPage, where string, f domFlow, script string) Finding {
	return Finding{
		Label: fmt.Sprintf("Script combines a tainted source (%s) with a dangerous sink (%s)", f.origin, f.sink),
		Detail: fmt.Sprintf(
			"Found on %s: the script's AST shows %s reads attacker-influenceable data (%s) and that value reaches %s, with no sanitizer on the path. This is a static model of the script, not a confirmed DOM XSS -- confirm by loading a URL whose fragment or query carries a payload and watching it execute.",
			pg.URL, where, f.origin, f.sink,
		),
		Evidence:   snippetAround(script, f.sink),
		Method:     "GET",
		Request:    &CapturedRequest{Method: "GET", URL: pg.URL},
		Confidence: ConfidenceHeuristic,
	}
}

// snippetAround returns up to ~60 characters on either side of marker's
// first occurrence in script, whitespace-collapsed -- enough surrounding
// code for an operator to recognize the line without dumping an entire
// (possibly minified, possibly huge) inline script block as evidence.
func snippetAround(script, marker string) string {
	idx := strings.Index(script, marker)
	if idx < 0 {
		return strings.TrimSpace(collapseWhitespace(script))
	}
	start := max(idx-60, 0)
	end := min(idx+len(marker)+60, len(script))
	snippet := collapseWhitespace(script[start:end])
	if start > 0 {
		snippet = "…" + snippet
	}
	if end < len(script) {
		snippet += "…"
	}
	return strings.TrimSpace(snippet)
}

var whitespaceRunPattern = regexp.MustCompile(`\s+`)

func collapseWhitespace(s string) string {
	return whitespaceRunPattern.ReplaceAllString(s, " ")
}
