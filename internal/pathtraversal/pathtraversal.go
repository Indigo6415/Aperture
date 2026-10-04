// Package pathtraversal tests for path traversal (CWE-22): any place where
// the application takes a file or path from the client and uses it to read a
// file without keeping the result inside the intended directory. Unlike an
// open redirect or SSRF, the point is not to make the server reach out to us.
// It is to read a file the app should not expose, so every finding is
// confirmed by a file signature in the response, never by a status code or a
// callback alone.
//
// The scanner builds its own list of injection points, each one a place the
// client's input can name a path:
//   - query-string parameters on the seed URL and on every same-origin page it
//     crawls, plus a fixed list of common file/path parameter names tried on the
//     seed (see commonParams);
//   - <form> fields (GET or POST, urlencoded or multipart) on those pages;
//   - the path itself: each segment replaced in turn, and a segment appended
//     at the end (see pathSegmentPoint and pathSuffixPoint);
//   - the request body when the operator supplies one: every string leaf of a
//     JSON body, or every field of a form-encoded body;
//   - a fixed set of request headers that apps read as file or path names
//     (X-Original-URL, X-File-Name, ...);
//   - cookies: those the operator sent, those the seed response set, and a
//     fixed set of common file/path cookie names.
//
// Six check modules run against every point (see modules in payloads.go):
// classic ../ sequences, Windows separators and paths, encoding and
// filter-evasion bypasses, absolute paths and file:// URLs, the PHP
// php://filter base64 wrapper, and the nginx alias off-by-slash for path
// segments. Each module stops at the first payload that reads a file on a
// given point.
//
// One further module, oob-callback (see oob.go), runs only when a callback
// listener is configured. It is the exception to the rule above: it puts a
// callback address where the path goes, and a hit proves the application
// fetched that value as a URL, not that it read a file. Its finding says so.
//
// A response only counts as a read when one of the fileSigs matches text the
// baseline did not contain. A negative control then sends the same request
// with a nonexistent file in its place. If that control also shows the
// signature, the page always contains it, so the point is dropped as a
// catch-all. Shaped like the other scanners: a battery of check modules, each
// with fixed severity and findings present even when empty.
package pathtraversal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// Confidence levels for a Finding. "confirmed" means a strong file signature
// appeared in the response and not in the baseline, and the control did not
// show it. "likely" means only a weak signature matched.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
)

// maxConcurrentRequests bounds in-flight requests across every module and
// point. Same reasoning as the other scanners: a few hundred points would all
// fire at once otherwise, and a burst is read by the target as an outage rather
// than a signal.
const maxConcurrentRequests = 16

// Finding is one confirmed read. Label names the point and Detail the payload
// and file. Request is the exact request that caused it, for "Send to Tester".
type Finding struct {
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Payload    string `json:"payload,omitempty"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Confidence is "confirmed" or "likely" (see the constants above).
	Confidence string `json:"confidence,omitempty"`
	// Request is the exact request this finding sent, so the frontend's "Send to
	// Tester" action can replay it.
	Request *CapturedRequest `json:"request,omitempty"`
}

// ModuleResult is one check module's outcome for this run.
type ModuleResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Findings []Finding `json:"findings"`
}

// Request is one run's configuration.
type Request struct {
	// URL is the seed the crawl starts from. Its query string is tested too.
	URL string `json:"url"`
	// Method is GET or POST. Empty means POST when Body is set and GET otherwise.
	Method string `json:"method,omitempty"`
	// Body is an optional request body. A JSON body is tested per string leaf,
	// and a form-encoded body per field.
	Body string `json:"body,omitempty"`
	// ContentType is sent with Body. Empty means JSON when Body looks like JSON,
	// and form-encoded otherwise.
	ContentType string `json:"contentType,omitempty"`
	// Params are extra query parameter names to test on URL, beyond the ones
	// it already carries and the common list.
	Params  []string          `json:"params,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	// RecursionDepth is how many hops of same-origin links the crawl follows
	// beyond URL. 0 scans only that page.
	RecursionDepth int `json:"recursionDepth,omitempty"`
	// MaxPages overrides the crawl's default page limit, capped at the crawler's own maximum.
	MaxPages int `json:"maxPages,omitempty"`
	// Progress, when set, receives one check per (module, injection point).
	Progress scanprogress.Reporter `json:"-"`
}

// Baseline is the seed's unmodified response.
type Baseline struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statusCode"`
}

// Result is one full run's outcome.
type Result struct {
	Baseline Baseline       `json:"baseline"`
	Modules  []ModuleResult `json:"modules"`
	// PagesScanned is every page the crawl fetched.
	PagesScanned []string `json:"pagesScanned"`
	// PointsTested is how many distinct injection points the modules ran against.
	PointsTested int `json:"pointsTested"`
	// OOBEnabled reports whether the callback module had a listener. When
	// false, that module did not run, so its absence isn't a clean result.
	OOBEnabled bool `json:"oobEnabled"`
}

// runDeps is what every module needs for one run.
type runDeps struct {
	client *http.Client
	points []point
	sem    chan struct{}
	// baseline is the seed's response body as served, before any payload.
	baseline string
	rep      scanprogress.Reporter
}

// Run crawls req.URL to find injection points, takes a baseline response, then
// runs every module against every point and returns one ModuleResult per
// module. The callback module joins them when oob names a listener. It returns
// an error only when the seed cannot be parsed or fetched.
func Run(ctx context.Context, req Request, oob OOBConfig) (*Result, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := parseTarget(req.URL)
	if err != nil {
		return nil, err
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
		if req.Body != "" {
			method = http.MethodPost
		}
	}

	headers := cloneHeaders(req.Headers)
	contentType := req.ContentType
	if req.Body != "" {
		if contentType == "" {
			// Same rule bodyPoints uses: JSON-looking bodies are JSON.
			trimmed := strings.TrimSpace(req.Body)
			if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				contentType = "application/json"
			} else {
				contentType = "application/x-www-form-urlencoded"
			}
		}
		if _, ok := headerValue(headers, "Content-Type"); !ok {
			headers["Content-Type"] = contentType
		}
	}

	seedSpec := requestSpec{Method: method, URL: seed.String(), Headers: headers, Body: req.Body}
	client := newClient()
	baseline := send(ctx, client, nil, seedSpec)
	if baseline.Err != nil {
		return nil, fmt.Errorf("pathtraversal: baseline request failed: %w", baseline.Err)
	}

	cr := crawl(ctx, client, seed, baseline.Body, headers, req.RecursionDepth, req.MaxPages)

	points := append([]point{}, cr.points...)
	points = append(points, seedPoints(seed, seedSpec, req, baseline.SetCookies)...)
	points = dedupePoints(points)

	rep.Phase(fmt.Sprintf("Testing %d injection point(s)", len(points)))
	deps := runDeps{client: client, points: points, sem: make(chan struct{}, maxConcurrentRequests), baseline: baseline.Body, rep: rep}

	// Every runner is one module with the func that executes it. The callback
	// module is added only when a listener is configured, so it reports nothing
	// otherwise.
	type runner struct {
		meta moduleMeta
		run  func() []Finding
	}
	runners := make([]runner, 0, len(modules)+1)
	for _, m := range modules {
		runners = append(runners, runner{m.moduleMeta, func() []Finding { return runModule(ctx, deps, m) }})
	}
	oobOn := oobConfigured(oob)
	if oobOn {
		runners = append(runners, runner{oobCallbackModule, func() []Finding { return runOOBCallbackModule(ctx, deps, oob) }})
	}

	// Modules run concurrently. Their requests share deps.sem, so the total
	// in-flight count stays bounded no matter how many modules there are.
	results := make([]ModuleResult, len(runners))
	var wg sync.WaitGroup
	for i, r := range runners {
		wg.Add(1)
		go func(i int, r runner) {
			defer wg.Done()
			results[i] = ModuleResult{ID: r.meta.id, Name: r.meta.name, Severity: r.meta.severity, Findings: r.run()}
		}(i, r)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return &Result{
		Baseline:     Baseline{URL: req.URL, StatusCode: baseline.StatusCode},
		Modules:      results,
		PagesScanned: cr.pages,
		PointsTested: len(points),
		OOBEnabled:   oobOn,
	}, nil
}

// seedPoints builds every point that comes from the seed itself, rather than
// from a crawled page: its own query parameters, the operator's extra and common
// parameters, path segments, the request body, headers, and cookies.
func seedPoints(seed *url.URL, base requestSpec, req Request, setCookies []string) []point {
	var out []point

	// Query parameters the seed already carries, plus the operator's extras and
	// the common list. The seed keeps its own method and body.
	names := map[string]bool{}
	for k := range seed.Query() {
		names[k] = true
	}
	for _, p := range req.Params {
		if p = strings.TrimSpace(p); p != "" {
			names[p] = true
		}
	}
	for _, p := range commonParams {
		names[p] = true
	}
	sortedNames := make([]string, 0, len(names))
	for k := range names {
		sortedNames = append(sortedNames, k)
	}
	sort.Strings(sortedNames)
	for _, k := range sortedNames {
		out = append(out, queryPoint(base, seed, k))
	}

	// Path segments: each one replaced in turn, plus an appended segment. The
	// split keeps the leading empty element, so indexes line up with the path.
	segments := strings.Split(seed.EscapedPath(), "/")
	for i := 1; i < len(segments); i++ {
		if segments[i] == "" {
			continue
		}
		out = append(out, pathSegmentPoint(seed, base, segments, i))
	}
	out = append(out, pathSuffixPoint(seed, base))

	// The request body, when the operator supplied one.
	ct, _ := headerValue(base.Headers, "Content-Type")
	out = append(out, bodyPoints(base, req.Body, ct)...)

	// Path-like request headers.
	for _, h := range pathHeaders {
		out = append(out, headerPoint(base, h))
	}

	// Cookies: those the operator sent, those the seed response set, and the
	// common list. Operator cookies come first so the header keeps its order.
	cookieOrder, cookieVals := []string{}, map[string]string{}
	if raw, ok := headerValue(base.Headers, "Cookie"); ok {
		cookieOrder, cookieVals = parseCookieHeader(raw)
	}
	for _, sc := range setCookies {
		// Only the name=value pair before the first ";" matters here.
		pair, _, _ := strings.Cut(sc, ";")
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" {
			continue
		}
		if _, seen := cookieVals[name]; !seen {
			cookieOrder = append(cookieOrder, name)
			cookieVals[name] = value
		}
	}
	for _, name := range cookieOrder {
		out = append(out, cookiePoint(base, cookieOrder, cookieVals, name))
	}
	for _, name := range commonCookies {
		if _, seen := cookieVals[name]; seen {
			continue
		}
		out = append(out, cookiePoint(base, cookieOrder, cookieVals, name))
	}
	return out
}

// dedupePoints removes points with the same id, keeping the first, so a
// parameter the seed and a crawled form both name is tested once.
func dedupePoints(points []point) []point {
	seen := map[string]bool{}
	out := make([]point, 0, len(points))
	for _, p := range points {
		if seen[p.id] {
			continue
		}
		seen[p.id] = true
		out = append(out, p)
	}
	return out
}

// runModule runs one module against every point it applies to, returning the
// findings in point order. A point with no finding contributes nothing.
func runModule(ctx context.Context, deps runDeps, m module) []Finding {
	// Path-only modules skip points that are not path segments.
	var pts []point
	for _, p := range deps.points {
		if m.pathOnly && p.segment == "" {
			continue
		}
		pts = append(pts, p)
	}

	found := make([]*Finding, len(pts))
	scanprogress.Each(deps.rep, 0, indexed(pts), func(it indexedPoint) scanprogress.Check {
		return scanprogress.Check{ID: m.id + "|" + it.pt.id, Label: it.pt.label, Group: m.name}
	}, func(it indexedPoint) (int, error) {
		f, ok := probePoint(ctx, deps, m, it.pt)
		if !ok {
			return 0, nil
		}
		found[it.idx] = &f
		return 1, nil
	})

	out := []Finding{}
	for _, f := range found {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// indexedPoint carries a point with its position, so results can be stored in
// point order even though points run concurrently.
type indexedPoint struct {
	idx int
	pt  point
}

// indexed pairs each point with its position.
func indexed(pts []point) []indexedPoint {
	out := make([]indexedPoint, len(pts))
	for i, p := range pts {
		out[i] = indexedPoint{idx: i, pt: p}
	}
	return out
}

// probePoint tries the module's payloads on one point in order, and stops at the
// first that reads a file. It returns that finding and true, or false when no
// payload reads anything.
func probePoint(ctx context.Context, deps runDeps, m module, pt point) (Finding, bool) {
	for _, p := range m.payloads {
		value := p.build(p.target, pt)
		res := send(ctx, deps.client, deps.sem, pt.build(value))
		if res.Err != nil {
			continue
		}
		sig, evidence, ok := matchFile(res.Body, deps.baseline, m.decodeBase64)
		if !ok {
			continue
		}

		// Negative control: the same request with a file that does not exist.
		// If the signature still shows, the response carries it regardless of
		// input, so this point is a catch-all and is dropped.
		control := send(ctx, deps.client, deps.sem, pt.build(p.build(negativeControlName, pt)))
		if control.Err == nil {
			if _, _, again := matchFile(control.Body, deps.baseline, m.decodeBase64); again {
				return Finding{}, false
			}
		}

		confidence := ConfidenceLikely
		if sig.strong {
			confidence = ConfidenceConfirmed
		}
		captured := res.Request
		return Finding{
			Label:      "Arbitrary file read via " + pt.label,
			Detail:     fmt.Sprintf("Payload %q (%s) returned the contents of %s. A control request for a nonexistent file at the same point did not.", value, p.name, sig.name),
			Evidence:   truncate(evidence, 200),
			Payload:    value,
			Method:     res.Request.Method,
			StatusCode: res.StatusCode,
			Confidence: confidence,
			Request:    &captured,
		}, true
	}
	return Finding{}, false
}

// truncate shortens s to at most n bytes, marking the cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
