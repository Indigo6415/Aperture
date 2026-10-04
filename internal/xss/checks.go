package xss

import (
	"context"
	"fmt"
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

// escapedSighting is one (module, point) pair whose canary came back in the
// response body but the payload's own breakout characters (<, >, ", ',
// etc.) didn't -- i.e. the input is reflected somewhere, but this
// particular payload shape got encoded/stripped rather than landing
// verbatim. Tracked separately from a confirmed Finding: reported later,
// once per point, as a single low-noise "reflected but escaped"
// informational note (see aggregateEscapedModule) rather than once per
// payload module, which would otherwise repeat the same observation up to
// len(payloadModules) times for one point.
type escapedSighting struct {
	key        string
	descriptor string
	evidence   string
	method     string
	statusCode int
	request    CapturedRequest
}

// runPayloadModule runs m's payload against every candidate injection point
// concurrently. A point that an earlier module already confirmed is skipped,
// so the battery stops spending requests on a point that is known to be
// vulnerable. Each (module, point) pair is one progress check. Returns both
// candidate Findings and, for any point m didn't confirm but whose canary
// still showed up in the response, an escapedSighting for
// aggregateEscapedModule to fold in later.
func runPayloadModule(ctx context.Context, deps runDeps, m payloadDef) ([]pointFinding, []escapedSighting) {
	client := newClient()
	payload := m.build(deps.canary)

	type indexedPoint struct {
		idx int
		pt  injectionPoint
	}
	items := make([]indexedPoint, len(deps.points))
	for i, pt := range deps.points {
		items[i] = indexedPoint{idx: i, pt: pt}
	}
	outcomes := make([]payloadOutcome, len(deps.points))
	scanprogress.Each(deps.rep, 0, items, func(it indexedPoint) scanprogress.Check {
		return scanprogress.Check{ID: m.id + "|" + pointKey(it.pt), Label: pointDescriptor(it.pt), Group: m.name}
	}, func(it indexedPoint) (int, error) {
		o := checkPoint(ctx, deps, client, m, payload, it.pt)
		outcomes[it.idx] = o
		if o.finding != nil {
			return 1, nil
		}
		return 0, nil
	})

	// Collect in point order so findings come out in the same order every run.
	var findings []pointFinding
	var escaped []escapedSighting
	for _, o := range outcomes {
		if o.finding != nil {
			findings = append(findings, *o.finding)
		}
		if o.escaped != nil {
			escaped = append(escaped, *o.escaped)
		}
	}
	return findings, escaped
}

// payloadOutcome is what one (module, point) check found: a confirmed
// reflected execution (finding), or an inert echo worth noting (escaped), or
// neither.
type payloadOutcome struct {
	finding *pointFinding
	escaped *escapedSighting
}

// checkPoint replays payload against one injection point for module m and
// classifies the response: a confirmed reflected execution, an inert echo
// worth noting, or nothing at all.
func checkPoint(ctx context.Context, deps runDeps, client *http.Client, m payloadDef, payload string, pt injectionPoint) payloadOutcome {
	key := pointKey(pt)
	if _, done := deps.confirmed.Load(key); done {
		return payloadOutcome{}
	}
	res := fetchInjectionPointThrottled(ctx, deps.sem, client, pt, payload, deps.req.Headers)
	if res.Err != nil {
		return payloadOutcome{}
	}
	// A JSON or plain-text response never runs reflected markup, and an
	// attachment is saved rather than rendered, so neither can be a finding,
	// whatever it echoes back.
	if !rendersAsHTML(res.ContentType, res.Disposition) {
		return payloadOutcome{}
	}
	// Both the payload's own match and the parser-state check must agree before
	// a reflection counts as executable.
	if evidence, ok := m.match(res.Body, payload, deps.canary); ok && payloadExecutes(res.Body, payload) {
		deps.confirmed.Store(key, true)
		return payloadOutcome{finding: &pointFinding{
			key:         key,
			param:       pt.Param,
			payload:     payload,
			browserable: pt.Kind == kindQuery || (pt.Kind == kindForm && pt.Method == "GET"),
			finding: Finding{
				Label: fmt.Sprintf("%s reflects an unescaped %s", capitalize(pointDescriptor(pt)), strings.ToLower(m.name)),
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
		}}
	}
	// The payload is inert here (a comment, a raw-text element, or a
	// quoted attribute it cannot close). If the marker still shows, the
	// input is reflected but not executable, which is the escaped note.
	if strings.Contains(res.Body, deps.canary) {
		return payloadOutcome{escaped: &escapedSighting{
			key: key, descriptor: pointDescriptor(pt), evidence: deps.canary,
			method: pt.Method, statusCode: res.StatusCode, request: res.Request,
		}}
	}
	return payloadOutcome{}
}

// aggregateEscapedModule builds the "reflected but not executable" info
// module from every payload module's escaped sightings, keeping only points
// that no module actually confirmed (confirmedPoints) and only the first
// sighting per point -- see escapedSighting's doc comment for why this
// collapses what would otherwise be up to len(payloadModules) near-duplicate
// notes per point into one.
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
			where := "an inline <script> block"
			if pg.Script {
				where = "the external script " + pg.URL
			}
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
