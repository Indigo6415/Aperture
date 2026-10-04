package ssrf

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout is deliberately more generous than the other scanners'
// (pwreset/corsscan/openredirect all use 8-10s): a payload that actually
// triggers an SSRF makes the *target* perform its own outbound request
// first, and this scanner only sees the target's response once that
// finishes (or the target's own client times out and it gives up) -- a
// slow/unreachable internal payload can legitimately take longer than a
// normal same-host request would.
const requestTimeout = 12 * time.Second

const maxBodyBytes = 256 * 1024

type ssrfResult struct {
	StatusCode    int
	ContentLength int
	Body          string
	Latency       time.Duration
	Err           error
	// Request is exactly what was sent on the wire for this check --
	// attached to any Finding it produced so "Send to Tester" (see
	// web/src/components/ScanModuleResults.tsx) can load the exact request
	// that triggered the finding rather than just the bare target URL.
	Request CapturedRequest
}

// CapturedRequest is the request a check actually sent -- same shape as
// corsscan.CapturedRequest; kept as its own type per-package, matching how
// Finding/ModuleResult are already duplicated across these scanners (see
// corsscan.Finding's doc comment).
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("ssrf: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("ssrf: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// fetchParam issues a request against target with param set to value --
// GET puts it in the query string (same shape as openredirect's own helper
// of the same name), POST (a discovered <form method="post">) instead sends
// it as the sole field of an application/x-www-form-urlencoded body, target's
// own query string left untouched. Kept as its own copy rather than shared
// with openredirect since the two packages' result types differ (this one
// also tracks latency, used by the internal-network module's anomaly
// comparison).
func fetchParam(ctx context.Context, client *http.Client, target *url.URL, method, param, value string, headers map[string]string) *ssrfResult {
	if method == "" {
		method = http.MethodGet
	}

	reqURL := *target
	var body io.Reader
	if method == http.MethodPost {
		form := url.Values{}
		form.Set(param, value)
		body = strings.NewReader(form.Encode())
	} else {
		q := reqURL.Query()
		q.Set(param, value)
		reqURL.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return &ssrfResult{Err: err}
	}
	req.Header.Set("User-Agent", "Aperture-SSRF")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	captured := CapturedRequest{Method: method, URL: reqURL.String(), Headers: sentHeaders}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return &ssrfResult{Err: err, Latency: time.Since(start), Request: captured}
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &ssrfResult{Err: err, Request: captured}
	}
	return &ssrfResult{StatusCode: resp.StatusCode, ContentLength: len(raw), Body: string(raw), Latency: elapsed, Request: captured}
}

// fetchParamThrottled is fetchParam gated by sem -- every module's own
// fan-out goes through this instead of calling fetchParam directly, so the
// scanner's *total* in-flight request count (across all three modules, and
// every target running concurrently) stays bounded. See
// maxConcurrentRequests's doc comment in ssrf.go for why this matters beyond
// just politeness: an unbounded burst can overwhelm a target enough that
// requests start failing for reasons having nothing to do with SSRF, which
// the internal-network module's own control-vs-payload comparison would
// otherwise misread as a signal.
func fetchParamThrottled(ctx context.Context, sem chan struct{}, client *http.Client, target *url.URL, method, param, value string, headers map[string]string) *ssrfResult {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return &ssrfResult{Err: ctx.Err()}
	}
	defer func() { <-sem }()
	return fetchParam(ctx, client, target, method, param, value, headers)
}

// fetchHeader issues a plain GET of target with headerName set to value. A
// payload sent this way never touches the URL or the body, so it only reaches
// whatever reads that header server-side: a virtual-host router choosing its
// backend by Host, a proxy building its upstream from X-Forwarded-Host, and
// similar. A Host payload replaces the request's Host field, since net/http
// ignores a Host entry in Header.
func fetchHeader(ctx context.Context, client *http.Client, target *url.URL, headerName, value string, headers map[string]string) *ssrfResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return &ssrfResult{Err: err}
	}
	req.Header.Set("User-Agent", "Aperture-SSRF")
	netgov.ApplyHeaders(req, headers)
	if strings.EqualFold(headerName, "Host") {
		req.Host = value
	} else {
		req.Header.Set(headerName, value)
	}

	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	if req.Host != "" {
		sentHeaders["Host"] = req.Host
	}
	captured := CapturedRequest{Method: http.MethodGet, URL: target.String(), Headers: sentHeaders}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return &ssrfResult{Err: err, Latency: time.Since(start), Request: captured}
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &ssrfResult{Err: err, Request: captured}
	}
	return &ssrfResult{StatusCode: resp.StatusCode, ContentLength: len(raw), Body: string(raw), Latency: elapsed, Request: captured}
}

// fetchPointThrottled sends value to one injection point of d's target: as a
// parameter (fetchParam, honoring d's method) or as a header (fetchHeader,
// given the value's host part). It takes a slot from d.sem first, so every
// module's requests share the same in-flight bound.
func fetchPointThrottled(ctx context.Context, d runDeps, pt probePoint, value string) *ssrfResult {
	select {
	case d.sem <- struct{}{}:
	case <-ctx.Done():
		return &ssrfResult{Err: ctx.Err()}
	}
	defer func() { <-d.sem }()
	if pt.header {
		return fetchHeader(ctx, d.client, d.target, pt.name, hostOf(value), d.req.Headers)
	}
	return fetchParam(ctx, d.client, d.target, d.method, pt.name, value, d.req.Headers)
}

// hostOf returns the host part of a URL payload, which is what a Host or
// forwarded-host header carries. A value that does not parse as a URL is
// returned unchanged.
func hostOf(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return value
	}
	return u.Host
}
