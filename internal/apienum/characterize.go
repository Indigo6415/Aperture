package apienum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// writeBodyParam appends one body param's probe element to an XML probe
// body -- kept as a helper so xmlEncode builds each tag with WriteString
// calls instead of string concatenation.
func writeBodyParam(b *strings.Builder, name string) {
	b.WriteString("<")
	b.WriteString(name)
	b.WriteString(">test</")
	b.WriteString(name)
	b.WriteString(">")
}

// candidateMethods is every method a route gets swapped through during
// characterization, regardless of which method it was originally
// discovered with -- see the package doc's "OPTIONS probe, and try
// swapping GET/POST/PUT/PATCH/DELETE" goal. HEAD is deliberately left out:
// it never carries a body and almost always mirrors GET's status, so
// testing it separately would just double GET's own request for no new
// signal.
var candidateMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

// isWriteMethod reports whether method changes server state in the way a
// routine probe should not do by default. PUT, PATCH and DELETE can overwrite
// or remove data, so they are sent only when the operator opted in. POST is
// left out on purpose: it is how a route shows it accepts a write at all, and
// it is what a discovered form submission already uses.
func isWriteMethod(method string) bool {
	switch method {
	case "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// rateLimitHeaderNames is every response header worth surfacing as this
// route's own rate-limit signal, if the server sends one on an ordinary
// request -- deliberately observational (see the package doc): this pass
// never sends enough requests to a single route to trip a real limit
// itself, it just reads whatever the server already advertises.
var rateLimitHeaderNames = []string{
	"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
	"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "Retry-After",
}

var pathParamPlaceholder = regexp.MustCompile(`\{([A-Za-z0-9_.$]+)\}`)

// signInMarkers are substrings of a redirect's Location that name an
// authentication page. A redirect to one of them means the route sits behind a
// login rather than answering.
var signInMarkers = []string{"login", "log-in", "signin", "sign-in", "sign_in", "/auth", "sso", "oauth"}

// characterizeAll runs characterizeRoute across every discovered route
// concurrently (bounded by c's own concurrency cap and rate limiter, same
// as every other phase), reporting progress and each finished route via
// onRoute as it completes -- in completion order, not routes' original
// order, mirroring probescan.RunScanStreaming's identical "stream as
// finished, sort at the end" shape.
func characterizeAll(ctx context.Context, c *apiClient, t *Target, routes []Route, rep scanprogress.Reporter, onRoute func(done, total int, r Route)) []Route {
	total := len(routes)
	out := make([]Route, total)
	// Every route is one progress check, planned up front; each starts when its
	// own characterization begins and finishes when it returns.
	checks := make([]scanprogress.Check, total)
	for i, r := range routes {
		checks[i] = scanprogress.Check{ID: routeCheckID(i), Label: r.Path}
	}
	rep.Plan(checks...)
	var wg sync.WaitGroup
	var done atomic.Int32
	for i, r := range routes {
		wg.Add(1)
		go func(i int, r Route) {
			defer wg.Done()
			rep.Start(routeCheckID(i))
			cr := characterizeRoute(ctx, c, t, r)
			rep.Done(routeCheckID(i), 0, nil)
			out[i] = cr
			if onRoute != nil {
				onRoute(int(done.Add(1)), total, cr)
			}
		}(i, r)
	}
	wg.Wait()
	return out
}

// routeCheckID is the progress check ID for the route at index i of a
// characterization run. Indexes are used rather than route IDs, since two
// discovery sources can produce routes that share one.
func routeCheckID(i int) string {
	return fmt.Sprintf("route-%d", i)
}

// characterizeRoute is one route's full workup: method support (OPTIONS
// plus a GET/POST/PUT/PATCH/DELETE swap), auth requirement (unauthenticated
// vs. authenticated, when a credential was supplied), content-type
// negotiation on a write method, a response-shape fingerprint, undocumented
// query-parameter discovery on a confirmed GET route, and the
// confirmed/uncertain verdict a JS-mined or brute-forced route is still
// waiting on (see mineJS/bruteforcePaths' doc comments).
//
// Every request here goes through the no-redirect client, so each response is
// judged as the one the route itself sent.
func characterizeRoute(ctx context.Context, c *apiClient, t *Target, r Route) Route {
	// GraphQL operations are already confirmed by the introspection call
	// that found them (see discoverGraphQL) and share one endpoint across
	// every operation -- method-swapping/auth-probing the literal endpoint
	// URL once per operation would just repeat the same request under every
	// query/mutation's name for no new signal.
	if r.Source == "graphql" {
		return r
	}

	resolvedPath, params := substitutePathParams(r.Path, r.Params)
	r.Params = params
	target := t.URL + resolvedPath
	dir := parentDir(resolvedPath)

	primaryMethod := "GET"
	if len(r.Methods) > 0 {
		primaryMethod = r.Methods[0].Method
	}
	// A route discovered under a write method (say, DELETE from a spec) is
	// characterized through GET unless the operator opted in, so the default
	// run never sends that write, not even as the primary probe.
	if isWriteMethod(primaryMethod) && !c.allowWrites {
		primaryMethod = "GET"
	}

	allowed := map[string]bool{}
	if optRes, err := c.doNoFollow(ctx, http.MethodOptions, target, nil, false, nil); err == nil {
		for m := range strings.SplitSeq(optRes.Header.Get("Allow"), ",") {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
				allowed[m] = true
			}
		}
	}

	methodsToTry := map[string]bool{primaryMethod: true}
	for _, m := range candidateMethods {
		// Skip write methods unless the operator allowed them for this run.
		if isWriteMethod(m) && !c.allowWrites {
			continue
		}
		methodsToTry[m] = true
	}

	var methodProbes []MethodProbe
	var primaryResult *apiResult
	for _, m := range orderedMethods(methodsToTry, primaryMethod) {
		if ctx.Err() != nil {
			break
		}
		body, contentType := sampleRequestBody(m, r.Params)
		headers := map[string]string{}
		if contentType != "" {
			headers["Content-Type"] = contentType
		}
		res, err := c.doNoFollow(ctx, m, target, headers, false, body)
		if err != nil {
			continue
		}
		if m == primaryMethod {
			primaryResult = res
		}
		// 404/405/501 is the server actively saying "not this" -- every
		// other status (including a 400 complaining about a missing field,
		// or a 401/403 gating it behind auth) means the route recognized
		// the method, which is what "allowed" is tracking here. A 502 is
		// the gateway in front of the app failing to reach it, so it says
		// nothing about the method and never counts as allowed.
		methodAllowed := res.StatusCode != 404 && res.StatusCode != 405 && res.StatusCode != 501 && res.StatusCode != http.StatusBadGateway
		if allowed[m] {
			methodAllowed = true
		}
		methodProbes = append(methodProbes, MethodProbe{
			Method: m, Allowed: methodAllowed, StatusCode: res.StatusCode,
			ContentType: res.Header.Get("Content-Type"), BodyShape: bodyShape(res.Header.Get("Content-Type"), res.Body),
			ResponseBytes: len(res.Body),
		})
	}
	r.Methods = methodProbes

	// A GET that looks exactly like this host's answer for a path that cannot
	// exist is a soft 404, not the route. The check only applies to GET, since
	// that's the method the catch-all profile is built from.
	soft404 := false
	if primaryResult != nil && primaryMethod == http.MethodGet {
		if prof := c.catchAllFor(ctx, t, dir); prof.Matches(observe(primaryResult)) {
			soft404 = true
		}
	}

	r.Auth = probeAuth(ctx, c, t, target, primaryMethod, r.Params, dir)

	if hasWriteMethod(methodProbes) {
		r.ContentTypesAccepted = negotiateContentTypes(ctx, c, target, r.Params)
	}

	if primaryResult != nil {
		for _, h := range rateLimitHeaderNames {
			if v := primaryResult.Header.Get(h); v != "" {
				if r.RateLimitHeaders == nil {
					r.RateLimitHeaders = map[string]string{}
				}
				r.RateLimitHeaders[h] = v
			}
		}
		r.Paginated = r.Paginated || responseLooksPaginated(primaryResult)
	}
	for _, p := range r.Params {
		if p.Location == LocationQuery && isPaginationField(p.Name) {
			r.Paginated = true
		}
	}

	r.Confirmed = routeIsConfirmed(r, primaryResult, soft404)

	// Undocumented query parameters are only worth sweeping for on a route that
	// is real and answers GET, and only while the run's sweep budget lasts.
	if r.Confirmed && !soft404 && methodAllowedFor(methodProbes, http.MethodGet) && c.takeParamBudget() {
		r.Params = mergeParams(r.Params, c.discoverQueryParams(ctx, t, resolvedPath, r.Params))
	}
	return r
}

// methodAllowedFor reports whether probes says method is accepted.
func methodAllowedFor(probes []MethodProbe, method string) bool {
	for _, p := range probes {
		if p.Method == method && p.Allowed {
			return true
		}
	}
	return false
}

// routeIsConfirmed finalizes the confirmed/uncertain split the package doc
// calls for: a spec/crawl-discovered route was already directly observed
// to exist, so it stays confirmed regardless of what characterization
// finds. A JS-mined or brute-forced route only earns "confirmed" once a
// live probe actually responded with something other than a 404 or a
// server error -- and, new here, something that isn't the host's own
// catch-all answer for a nonexistent path (soft404).
func routeIsConfirmed(r Route, primaryResult *apiResult, soft404 bool) bool {
	if r.Source == "spec" || r.Source == "crawl" || r.Source == "graphql" {
		return true
	}
	if primaryResult == nil || soft404 {
		return false
	}
	status := primaryResult.StatusCode
	return (status >= 200 && status < 400) || status == 401 || status == 403
}

// orderedMethods returns methods with primary first (so primaryResult is
// always captured even if ctx is cancelled partway through the rest) and
// every other candidate following in a fixed order.
func orderedMethods(methods map[string]bool, primary string) []string {
	out := []string{primary}
	for _, m := range candidateMethods {
		if m != primary && methods[m] {
			out = append(out, m)
		}
	}
	return out
}

// substitutePathParams fills every "{name}" segment in path with a sample
// value (reusing one already known from discovery, e.g. a spec default, or
// a type-appropriate guess otherwise) so a probe request has a real chance
// of hitting a route rather than literally requesting ".../{id}". Returns
// the resolved path and params with each path param's Sample filled in
// when it wasn't already.
func substitutePathParams(path string, params []Param) (string, []Param) {
	updated := make([]Param, len(params))
	copy(updated, params)
	resolved := pathParamPlaceholder.ReplaceAllStringFunc(path, func(m string) string {
		// Match jsmine.go's normalizeTemplatePath, which stores a dotted
		// placeholder's own param under just its last segment ("user.id" ->
		// "id") -- without this, a JS-mined path param would never find its
		// matching Param here and would substitute an unlinked "1" instead
		// of reusing an already-known sample.
		name := strings.Trim(m, "{}")
		if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
			name = name[idx+1:]
		}
		sample := "1"
		for i, p := range updated {
			if p.Location != LocationPath || p.Name != name {
				continue
			}
			if p.Sample != "" {
				sample = p.Sample
			} else {
				if p.TypeGuess == "uuid" {
					sample = "00000000-0000-0000-0000-000000000000"
				}
				updated[i].Sample = sample
			}
			break
		}
		return sample
	})
	return resolved, updated
}

// sampleRequestBody builds a minimal JSON body for a write method from a
// route's known body params (filling in a type-appropriate sample value
// per param), or "{}" when none are known -- enough to get past a naive
// "body is present and is valid JSON" check without claiming to actually
// exercise the endpoint's real behavior. Returns nil/"" for a method that
// never carries a body.
func sampleRequestBody(method string, params []Param) ([]byte, string) {
	if method == http.MethodGet || method == http.MethodDelete || method == http.MethodOptions || method == http.MethodHead {
		return nil, ""
	}
	fields := map[string]any{}
	for _, p := range params {
		if p.Location == LocationBody {
			fields[p.Name] = sampleJSONValue(p)
		}
	}
	body, err := json.Marshal(fields)
	if err != nil {
		body = []byte("{}")
	}
	return body, "application/json"
}

// sampleJSONValue picks a placeholder value for one body param, matching its
// type guess so the sample isn't rejected for the wrong JSON type.
func sampleJSONValue(p Param) any {
	if p.Sample != "" {
		return p.Sample
	}
	switch p.TypeGuess {
	case "numeric-id":
		return 1
	case "boolean":
		return true
	case "uuid":
		return "00000000-0000-0000-0000-000000000000"
	default:
		return "test"
	}
}

// bodyShape classifies a response body for the fingerprint the package doc
// asks for ("rough body shape (object/array/size)") -- a quick look at
// content-type plus the first non-whitespace byte, not a real parse.
func bodyShape(contentType string, body []byte) string {
	if len(body) == 0 {
		return "empty"
	}
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "text") || strings.Contains(contentType, "html") || strings.Contains(contentType, "xml") {
		trimmed := strings.TrimSpace(string(body))
		switch {
		case strings.HasPrefix(trimmed, "{"):
			return "object"
		case strings.HasPrefix(trimmed, "["):
			return "array"
		default:
			return "text"
		}
	}
	return "binary"
}

// hasWriteMethod reports whether any write method (POST/PUT/PATCH) is accepted,
// which is what makes content-type negotiation worth running.
func hasWriteMethod(methods []MethodProbe) bool {
	for _, m := range methods {
		if m.Allowed && (m.Method == http.MethodPost || m.Method == http.MethodPut || m.Method == http.MethodPatch) {
			return true
		}
	}
	return false
}

// isLoginRedirect reports whether a response is a redirect whose Location names
// a sign-in page.
func isLoginRedirect(status int, location string) bool {
	if status < 300 || status >= 400 || location == "" {
		return false
	}
	loc := strings.ToLower(location)
	for _, marker := range signInMarkers {
		if strings.Contains(loc, marker) {
			return true
		}
	}
	return false
}

// authVerdictFor names what one unauthenticated response says about the route's
// access control, and whether that means the route requires auth. siteWide
// means the same verdict came back for a nonexistent path in the same
// directory, so the control belongs to the directory or the whole host rather
// than to this route: the verdict becomes "site-wide-gate" and RequiresAuth is
// not claimed for the route.
func authVerdictFor(res *apiResult, siteWide bool) (string, bool) {
	status := res.StatusCode
	verdict, requires := "other", false
	switch {
	case isLoginRedirect(status, res.Header.Get("Location")):
		verdict, requires = "login-redirect", true
	case status == http.StatusUnauthorized:
		verdict, requires = "requires-auth", true
	case status == http.StatusForbidden:
		verdict, requires = "forbidden", true
	case status >= 200 && status < 400:
		verdict = "public"
	case status == http.StatusNotFound:
		verdict = "not-found"
	}
	if siteWide && requires {
		return "site-wide-gate", false
	}
	return verdict, requires
}

// challengeOf returns the WWW-Authenticate challenge a response carried,
// truncated to something a UI can show in one line, or "" when there is none.
func challengeOf(res *apiResult) string {
	const maxLen = 120
	v := res.Header.Get("WWW-Authenticate")
	if len(v) > maxLen {
		return v[:maxLen]
	}
	return v
}

// probeAuth sends the unauthenticated half of the auth check always, and
// the authenticated half only when this run was actually given a
// credential to test with -- see client.go's hasBaseline. dir is the route's
// own directory, used to tell a route-specific gate from a directory-wide one.
func probeAuth(ctx context.Context, c *apiClient, t *Target, target, method string, params []Param, dir string) AuthProbe {
	body, contentType := sampleRequestBody(method, params)
	headers := map[string]string{}
	if contentType != "" {
		headers["Content-Type"] = contentType
	}

	probe := AuthProbe{}
	if res, err := c.doNoFollow(ctx, method, target, headers, true, body); err == nil {
		probe.UnauthenticatedStatus = res.StatusCode
		probe.Challenge = challengeOf(res)
		base, _ := authVerdictFor(res, false)
		// A 401/403/login verdict is only route-specific if a nonexistent path in
		// the same directory doesn't get the identical verdict.
		siteWide := false
		if base == "requires-auth" || base == "forbidden" || base == "login-redirect" {
			siteWide = c.gateVerdict(ctx, t, dir) == base
		}
		probe.Verdict, probe.RequiresAuth = authVerdictFor(res, siteWide)
	} else {
		probe.Verdict = "unreachable"
	}
	if c.hasBaseline() {
		if res, err := c.doNoFollow(ctx, method, target, headers, false, body); err == nil {
			probe.AuthenticatedStatus = &res.StatusCode
		}
	}
	return probe
}

// negotiationContentTypes/negotiateContentTypes -- see the package doc's
// "content-type negotiation" goal: a write method rejecting one of these
// outright (415) means it was never going to parse that shape in the first
// place, which matters for anyone later trying an XML-only injection class
// like XXE against a route that turns out to be JSON-only.
var negotiationContentTypes = []string{"application/json", "application/x-www-form-urlencoded", "application/xml"}

// negotiateContentTypes sends the same write body under each candidate
// Content-Type and reports every type the route didn't refuse with a 415.
func negotiateContentTypes(ctx context.Context, c *apiClient, target string, params []Param) []string {
	jsonBody, _ := sampleRequestBody(http.MethodPost, params)
	bodies := map[string][]byte{
		"application/json":                  jsonBody,
		"application/x-www-form-urlencoded": formEncode(params),
		"application/xml":                   xmlEncode(params),
	}

	var accepted []string
	for _, ct := range negotiationContentTypes {
		if ctx.Err() != nil {
			break
		}
		res, err := c.doNoFollow(ctx, http.MethodPost, target, map[string]string{"Content-Type": ct}, false, bodies[ct])
		if err != nil {
			continue
		}
		if res.StatusCode != http.StatusUnsupportedMediaType {
			accepted = append(accepted, ct)
		}
	}
	return accepted
}

// formEncode builds a form-urlencoded body from the route's known body params.
func formEncode(params []Param) []byte {
	var b strings.Builder
	first := true
	for _, p := range params {
		if p.Location != LocationBody {
			continue
		}
		if !first {
			b.WriteByte('&')
		}
		first = false
		b.WriteString(p.Name)
		b.WriteByte('=')
		b.WriteString("test")
	}
	if b.Len() == 0 {
		return []byte("probe=1")
	}
	return []byte(b.String())
}

// xmlEncode builds an XML body from the route's known body params.
func xmlEncode(params []Param) []byte {
	var b strings.Builder
	b.WriteString("<root>")
	for _, p := range params {
		if p.Location != LocationBody {
			continue
		}
		writeBodyParam(&b, p.Name)
	}
	b.WriteString("</root>")
	return []byte(b.String())
}

// responseLooksPaginated checks a JSON-object response's top-level keys
// for a pagination-shaped field name (page/limit/offset/cursor/...) --
// enough signal for the "pagination behavior if observable" goal without
// needing to actually understand the response schema.
func responseLooksPaginated(res *apiResult) bool {
	if !strings.Contains(res.Header.Get("Content-Type"), "json") {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(res.Body, &m) != nil {
		return false
	}
	for k := range m {
		if isPaginationField(k) {
			return true
		}
	}
	return false
}
