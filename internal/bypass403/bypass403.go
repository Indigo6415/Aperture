// Package bypass403 tries to get past an access-denied response by
// replaying the same request through a battery of path/header/method/
// protocol variations that are each, on their own, a request for the exact
// same resource -- just spelled, addressed, or framed differently enough
// that a rule blocking the original request stops recognizing it.
//
// It treats "blocked" as either an HTTP 401/403, or an HTTP success/redirect
// whose body still reads like a denial page (a "soft 403") -- see
// looksBlocked. Every attempt is then judged against that same baseline: an
// attempt "bypasses" it when the response no longer looks blocked *and*
// (status code or content length) actually changed, so a WAF that just
// serves the identical block page for every variation doesn't get
// misreported as bypassed.
//
// This is authorized-testing tooling: it never attempts request smuggling
// (ambiguous/malformed framing between a front-end and an origin server) or
// anything that targets infrastructure rather than one URL's own access
// control -- see attempts.go's doc comments for what's in and out of scope.
package bypass403

import (
	"context"
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

// Options tunes a run beyond the target URL itself. Headers (may be nil) is
// applied to every request the engine issues, on top of whatever technique-
// specific header each attempt sends -- e.g. a saved case credential's
// Authorization/Cookie, the same way probescan/secretscan apply one.
// Concurrency overrides defaultConcurrency.
type Options struct {
	Headers     map[string]string
	Concurrency int
	// Progress, when set, receives one check per module (or per attempt). Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// defaultConcurrency bounds how many attempts are in flight at once -- a
// full run is ~30 requests against one host, so this keeps it a quick,
// reasonably-paced burst rather than either a slow serial crawl or a flood.
const defaultConcurrency = 10

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
// baseline looks blocked (see looksBlocked) -- fires every technique in
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
	blocked, reason := looksBlocked(baselineResp.StatusCode, baselineResp.BodyLower)
	baseline := Baseline{
		URL:           rawURL,
		StatusCode:    baselineResp.StatusCode,
		ContentLength: baselineResp.ContentLength,
		Blocked:       blocked,
		Reason:        reason,
	}
	if !blocked {
		// Nothing to bypass -- report the baseline alone rather than firing
		// ~30 requests that can't tell the operator anything new.
		return &Result{Baseline: baseline}, nil
	}

	baseline.home, baseline.hasHome = fetchHomepage(ctx, client, u.Scheme, u.Host, opts.Headers)

	trustedReferer := u.Scheme + "://" + u.Host + "/"
	specs := buildAttempts(basePath, u.RawQuery, u.Scheme, trustedReferer)

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
		results[it.idx] = runAttempt(ctx, client, u.Scheme, u.Host, it.spec, opts.Headers, baseline)
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
func runAttempt(ctx context.Context, client *http.Client, scheme, host string, spec attemptSpec, extraHeaders map[string]string, baseline Baseline) Attempt {
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
	switch spec.raw {
	case "http10":
		res, err = doRawRequest(ctx, reqScheme, host, hostHeader, spec.target, headers, rawRequestOptions{proto: "1.0"})
	case "no-host":
		res, err = doRawRequest(ctx, reqScheme, host, hostHeader, spec.target, headers, rawRequestOptions{proto: "1.1", omitHostHeader: true})
	default:
		res, err = doAttempt(ctx, client, spec.method, reqScheme, host, hostHeader, spec.target, headers)
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}

	out.StatusCode = res.StatusCode
	out.ContentLength = res.ContentLength

	blockedNow, _ := looksBlocked(res.StatusCode, res.BodyLower)
	changed := res.StatusCode != baseline.StatusCode || res.ContentLength != baseline.ContentLength
	// A response that matches the site homepage is the front door answering, not
	// the protected path opening. Such responses are kept but flagged, not counted.
	sameAsHome := baseline.hasHome && fingerprint.Similar(baseline.home, fingerprint.Observe(res.StatusCode, "", []byte(res.BodyLower)))
	out.Bypassed = res.StatusCode < 400 && !blockedNow && changed && !sameAsHome
	if res.StatusCode < 400 && !blockedNow && changed && sameAsHome {
		out.Note = "response matches the site homepage; the protected path returned the front page, not the resource"
	}
	if out.Bypassed && len(res.BodyLower) > 0 {
		snippet := res.BodyLower
		if len(snippet) > bodySnippetLen {
			snippet = snippet[:bodySnippetLen]
		}
		out.BodySnippet = snippet
	}
	return out
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
