// Package bypass403 tries to get past an access-denied response by
// replaying the same request through a battery of path/header/method/
// protocol variations that are each, on their own, a request for the exact
// same resource -- just spelled, addressed, or framed differently enough
// that a rule blocking the original request stops recognizing it.
//
// It treats "blocked" as either an HTTP 401/403, a redirect to a sign-in
// page, or an HTTP success whose body still reads like a denial page (a
// "soft 403") -- see classify. Every attempt is then judged against that
// same baseline by judgeAttempt: an attempt "bypasses" it only when it
// returns a 2xx that no longer looks blocked, differs from the baseline, and
// is not any of the things a non-bypass can look like -- the same block page
// served under another status, the site homepage, or the host's catch-all
// (soft-404) page for paths that don't exist. Redirects are never counted,
// since they say the protected resource was not returned.
//
// This is authorized-testing tooling: it never attempts request smuggling
// (ambiguous/malformed framing between a front-end and an origin server) or
// anything that targets infrastructure rather than one URL's own access
// control -- see attempts.go's doc comments for what's in and out of scope.
package bypass403

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// denialPhrases flag a "soft 403" -- an HTTP success/redirect whose body
// still tells the user they can't have the page. Kept deliberately generic
// (not tied to one WAF/framework's exact wording) since this runs against
// whatever an operator points it at.
var denialPhrases = []string{
	"403 forbidden",
	"forbidden</title>",
	"access denied",
	"access is denied",
	"you don't have permission",
	"you do not have permission",
	"do not have permission to access",
	"not authorized to access",
	"unauthorized access",
	"permission denied",
	"blocked by administrator",
	"request has been blocked",
	"request blocked",
}

// signInMarkers are substrings of a redirect's Location that point at an
// authentication page -- a redirect to one of these means the resource was
// withheld behind a login, not returned.
var signInMarkers = []string{"login", "log-in", "signin", "sign-in", "sign_in", "/auth", "sso", "oauth", "/account/log"}

// looksBlocked decides whether one response still reads as "denied" -- a
// hard 401/403, or a success/redirect whose body matches a denial phrase.
func looksBlocked(statusCode int, bodyLower string) (blocked bool, reason string) {
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return true, fmt.Sprintf("HTTP %d", statusCode)
	}
	for _, phrase := range denialPhrases {
		if strings.Contains(bodyLower, phrase) {
			return true, "response body reads as a denial page"
		}
	}
	return false, ""
}

// isSignInRedirect reports whether a response is a redirect whose Location
// points at a sign-in page.
func isSignInRedirect(statusCode int, location string) bool {
	if statusCode < 300 || statusCode >= 400 || location == "" {
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

// classify is looksBlocked extended with the sign-in redirect case, which a
// body-only check can't see: a 302 to /login has no denial text at all.
func classify(res *httpResult) (blocked bool, reason string) {
	if isSignInRedirect(res.StatusCode, res.Location) {
		return true, "redirects to a sign-in page"
	}
	return looksBlocked(res.StatusCode, res.BodyLower)
}

// Options tunes a run beyond the target URL itself. Headers (may be nil) is
// applied to every request the engine issues, on top of whatever technique-
// specific header each attempt sends -- e.g. a saved case credential's
// Authorization/Cookie, the same way probescan/secretscan apply one.
// Concurrency overrides defaultConcurrency.
type Options struct {
	Headers     map[string]string
	Concurrency int
	// AllowWriteMethods runs the PUT, PATCH and DELETE method-tampering
	// attempts. They can change or delete data on the target, so they run only
	// when this is set (see withoutWriteMethods).
	AllowWriteMethods bool
	// Progress, when set, receives one check per module (or per attempt). Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// defaultConcurrency bounds how many attempts are in flight at once -- a
// full run is ~90 requests against one host, so this keeps it a quick,
// reasonably-paced burst rather than either a slow serial crawl or a flood.
const defaultConcurrency = 10

// catchAllSamples is how many nonexistent paths are requested to learn what
// "not found" looks like on this host. Each shape (bare, .html, directory)
// is one sample, so the three shapes in buildCatchAll cover all of them.
const catchAllSamples = 3

// Baseline is the unmodified request's own result, and the yardstick every
// attempt is compared against.
type Baseline struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"statusCode"`
	ContentLength int    `json:"contentLength"`
	// Blocked is false when the target doesn't look denied in the first
	// place -- Run returns immediately in that case, since there's nothing
	// here for a bypass technique to get past.
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`
	// home is the site's own homepage as served right now. An attempt whose response
	// matches it got the homepage, not the protected resource, so it is not a bypass.
	home    fingerprint.Observation
	hasHome bool
	// body is the denied baseline's own page. An attempt that serves this same
	// page under a different status (a WAF answering 200 instead of 403) is
	// still the denial, so judgeAttempt compares against it ignoring status.
	body fingerprint.Observation
}

// Attempt is one technique's outcome.
type Attempt struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Method      string `json:"method"`
	// Target is the literal request-target sent on the wire (path + query),
	// not a full URL -- shown alongside Baseline.URL's scheme/host in the UI.
	Target        string            `json:"target"`
	Headers       map[string]string `json:"headers,omitempty"`
	StatusCode    int               `json:"statusCode"`
	ContentLength int               `json:"contentLength"`
	// BodySnippet is only populated when Bypassed -- there's no reason to
	// ship the first N bytes of ~30 blocked-page bodies back to the client.
	BodySnippet string `json:"bodySnippet,omitempty"`
	Bypassed    bool   `json:"bypassed"`
	// Note explains an attempt that looked like a bypass but was judged not to be.
	Note  string `json:"note,omitempty"`
	Error string `json:"error,omitempty"`
}

// Result is one target's full run.
type Result struct {
	Baseline    Baseline  `json:"baseline"`
	Attempts    []Attempt `json:"attempts"`
	BypassCount int       `json:"bypassCount"`
}

// bodySnippetLen bounds how much of a bypassed response's body is echoed
// back -- enough to recognize the page at a glance, not the whole thing.
const bodySnippetLen = 300

// Run resolves rawURL, takes a baseline request, and -- only if that
// baseline looks blocked (see classify) -- fires every technique in
// buildAttempts at it concurrently, reporting which ones stopped looking
// blocked. rawURL must include a scheme; unlike Probe's target field, this
// engine has no default-scheme fallback (mirrors secretscan.Run).
func Run(ctx context.Context, rawURL string, opts Options) (*Result, error) {
	rep := scanprogress.Or(opts.Progress)

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("bypass403: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("bypass403: unsupported scheme %q", u.Scheme)
	}

	// Bypass techniques are judged by the *first* response a technique
	// produces -- following a redirect would silently swap in whatever the
	// redirect target returns instead, which is a different question (is the
	// target of the redirect accessible?) than the one this engine is
	// answering (did this exact request just get past the block?).
	client := netgov.NewClient(requestTimeout, false)

	basePath := u.EscapedPath()
	if basePath == "" {
		basePath = "/"
	}
	baselineTarget := basePath
	if u.RawQuery != "" {
		baselineTarget += "?" + u.RawQuery
	}

	baselineResp, err := doAttempt(ctx, client, http.MethodGet, u.Scheme, u.Host, u.Host, baselineTarget, opts.Headers)
	if err != nil {
		return nil, fmt.Errorf("bypass403: baseline request failed: %w", err)
	}
	blocked, reason := classify(baselineResp)
	baseline := Baseline{
		URL:           rawURL,
		StatusCode:    baselineResp.StatusCode,
		ContentLength: baselineResp.ContentLength,
		Blocked:       blocked,
		Reason:        reason,
		body:          fingerprint.Observe(baselineResp.StatusCode, baselineResp.ContentType, []byte(baselineResp.BodyLower)),
	}
	if !blocked {
		// Nothing to bypass -- report the baseline alone rather than firing
		// ~90 requests that can't tell the operator anything new.
		return &Result{Baseline: baseline}, nil
	}

	baseline.home, baseline.hasHome = fetchHomepage(ctx, client, u.Scheme, u.Host, opts.Headers)
	// The catch-all profile is built from paths that cannot exist next to the
	// protected one, so it learns what this host's "not found" answer looks
	// like in the same directory the attempts are aimed at.
	profile := buildCatchAll(ctx, client, u.Scheme, u.Host, basePath, opts.Headers)

	trustedReferer := u.Scheme + "://" + u.Host + "/"
	specs := buildAttempts(basePath, u.RawQuery, u.Scheme, trustedReferer)
	if !opts.AllowWriteMethods {
		specs = withoutWriteMethods(specs)
	}

	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}
	results := make([]Attempt, len(specs))
	type indexedSpec struct {
		idx  int
		spec attemptSpec
	}
	items := make([]indexedSpec, len(specs))
	for i, spec := range specs {
		items[i] = indexedSpec{idx: i, spec: spec}
	}
	// Each attempt is one progress check, run with at most conc in flight.
	scanprogress.Each(rep, conc, items, func(it indexedSpec) scanprogress.Check {
		return scanprogress.Check{ID: it.spec.id, Label: it.spec.description, Group: string(it.spec.category)}
	}, func(it indexedSpec) (int, error) {
		results[it.idx] = runAttempt(ctx, client, u.Scheme, u.Host, it.spec, opts.Headers, baseline, profile)
		if results[it.idx].Bypassed {
			return 1, nil
		}
		return 0, nil
	})

	// The Wayback Machine check isn't a live request against the target at
	// all, so it doesn't fit runAttempt's request-building -- appended
	// separately once every live attempt is in.
	if archived := checkWaybackMachine(ctx, rawURL); archived != nil {
		results = append(results, *archived)
	}

	bypassCount := 0
	for _, a := range results {
		if a.Bypassed {
			bypassCount++
		}
	}
	// Sorted category-then-id so the UI can group techniques into sections
	// in a stable order regardless of which goroutine finished first.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Category != results[j].Category {
			return results[i].Category < results[j].Category
		}
		return results[i].ID < results[j].ID
	})

	return &Result{Baseline: baseline, Attempts: results, BypassCount: bypassCount}, nil
}

// runAttempt fires one technique and judges it against baseline -- shared by
// every attemptSpec regardless of category, since categories differ only in
// how they build their request, not in how the result is scored.
func runAttempt(ctx context.Context, client *http.Client, scheme, host string, spec attemptSpec, extraHeaders map[string]string, baseline Baseline, profile *fingerprint.Profile) Attempt {
	out := Attempt{ID: spec.id, Category: string(spec.category), Description: spec.description, Method: spec.method, Target: spec.target, Headers: spec.headers}

	headers := mergeHeaders(extraHeaders, spec.headers)
	hostHeader := host
	if spec.hostHeader != "" {
		hostHeader = spec.hostHeader
	}
	reqScheme := scheme
	if spec.scheme != "" {
		reqScheme = spec.scheme
	}

	var res *httpResult
	var err error
	switch {
	case spec.raw == "http10":
		res, err = doRawRequest(ctx, reqScheme, host, hostHeader, spec.target, headers, rawRequestOptions{proto: "1.0"})
	case spec.raw == "http10-no-host":
		res, err = doRawRequest(ctx, reqScheme, host, hostHeader, spec.target, headers, rawRequestOptions{proto: "1.0", omitHostHeader: true})
	case spec.raw == "no-host":
		res, err = doRawRequest(ctx, reqScheme, host, hostHeader, spec.target, headers, rawRequestOptions{proto: "1.1", omitHostHeader: true})
	// net/url renders an opaque target that begins with "//" as an absolute
	// URL (GET http://host// ...), which is not the request-target this
	// technique means to send, so those go over the raw request-line writer.
	case strings.HasPrefix(spec.target, "//"):
		res, err = doRawRequest(ctx, reqScheme, host, hostHeader, spec.target, headers, rawRequestOptions{proto: "1.1"})
	default:
		res, err = doAttempt(ctx, client, spec.method, reqScheme, host, hostHeader, spec.target, headers)
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}

	out.StatusCode = res.StatusCode
	out.ContentLength = res.ContentLength
	out.Bypassed, out.Note = judgeAttempt(res, baseline, profile)
	if out.Bypassed && len(res.BodyLower) > 0 {
		snippet := res.BodyLower
		if len(snippet) > bodySnippetLen {
			snippet = snippet[:bodySnippetLen]
		}
		out.BodySnippet = snippet
	}
	return out
}

// judgeAttempt scores one response against the baseline and returns whether
// it is a bypass, plus a note explaining why an apparent one was not. The
// rules run in order from cheapest/clearest to most contextual, and a
// response only counts once it clears every one of them.
func judgeAttempt(res *httpResult, baseline Baseline, profile *fingerprint.Profile) (bool, string) {
	// A redirect says the resource was not returned -- it may point at a
	// sign-in page, or merely at the same resource with a slash added. Either
	// way the redirect itself isn't the protected content, so it's noted, never counted.
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		if isSignInRedirect(res.StatusCode, res.Location) {
			return false, "redirected to a sign-in page; the protected resource was not returned"
		}
		return false, "redirected to " + res.Location + " instead of returning the resource (redirects are not followed)"
	}
	// Only a 2xx can be the resource opening up.
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return false, ""
	}

	obs := fingerprint.Observe(res.StatusCode, res.ContentType, []byte(res.BodyLower))
	// Anything that doesn't differ from the blocked baseline at all can't be a bypass.
	changed := res.StatusCode != baseline.StatusCode || res.ContentLength != baseline.ContentLength
	if !changed {
		return false, ""
	}
	if blockedNow, _ := classify(res); blockedNow {
		return false, "returned a 2xx, but the body still reads as a denial page"
	}
	// Same denial page with a different status code (for example a WAF answering
	// 200 instead of 403) is still the denial. Status is blanked on a copy so
	// only the page content is compared.
	sameDenial := obs
	sameDenial.Status = baseline.body.Status
	if fingerprint.Similar(baseline.body, sameDenial) {
		return false, "returned the same block page as the denied baseline, under a different status"
	}
	// A response that matches the site homepage is the front door answering, not
	// the protected path opening.
	if baseline.hasHome && fingerprint.Similar(baseline.home, obs) {
		return false, "response matches the site homepage; the protected path returned the front page, not the resource"
	}
	// A response that matches what this host serves for paths that don't exist
	// is a soft 404, not the resource.
	if profile.Matches(obs) {
		return false, "response matches the host's catch-all page for nonexistent paths (soft 404), not the resource"
	}
	return true, ""
}

// mergeHeaders layers a technique's own headers on top of the shared
// per-request headers (e.g. a saved credential) -- later wins so a
// technique that specifically needs to *set* a header (X-Forwarded-For,
// say) can't be silently overridden by an unrelated credential header of
// the same name.
func mergeHeaders(base, override map[string]string) map[string]string {
	if len(base) == 0 {
		return override
	}
	out := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

// buildCatchAll requests a few paths that cannot exist in the same directory
// as basePath and fingerprints the answers -- the host's own "not found"
// page, in the form an attempt would otherwise be mistaken for. Returns nil
// (which matches nothing) when no sample could be taken.
func buildCatchAll(ctx context.Context, client *http.Client, scheme, host, basePath string, headers map[string]string) *fingerprint.Profile {
	dir, _ := splitLastSegment(basePath)
	shapes := []string{"%s", "%s.html", "%s/"}
	var samples []fingerprint.Observation
	for i := 0; i < catchAllSamples && i < len(shapes); i++ {
		target := dir + strings.Replace(shapes[i], "%s", randomProbeName(), 1)
		res, err := doAttempt(ctx, client, http.MethodGet, scheme, host, host, target, headers)
		if err != nil {
			continue
		}
		samples = append(samples, fingerprint.Observe(res.StatusCode, res.ContentType, []byte(res.BodyLower)))
	}
	if len(samples) == 0 {
		return nil
	}
	return fingerprint.NewProfile(samples)
}

// randomProbeName returns an unguessable path segment for catch-all probes,
// so no real or cached path can match it.
func randomProbeName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the system entropy source is broken;
		// a fixed fallback still produces a name that does not exist.
		return "aperture-fallback"
	}
	return "aperture-" + hex.EncodeToString(b[:])
}

// fetchHomepage requests the site root once and fingerprints it. The result is
// the reference an attempt is compared against. The boolean is false when the
// root cannot be fetched, in which case no attempt is judged against it.
func fetchHomepage(ctx context.Context, client *http.Client, scheme, host string, headers map[string]string) (fingerprint.Observation, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
	if err != nil {
		return fingerprint.Observation{}, false
	}
	netgov.ApplyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return fingerprint.Observation{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fingerprint.Observation{}, false
	}
	return fingerprint.Observe(resp.StatusCode, resp.Header.Get("Content-Type"), []byte(strings.ToLower(string(body)))), true
}
