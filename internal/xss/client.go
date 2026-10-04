package xss

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

const (
	requestTimeout = 10 * time.Second
	maxBodyBytes   = 256 * 1024
)

type xssResult struct {
	StatusCode int
	Body       string
	// ContentType decides whether a reflection can execute: only HTML does.
	ContentType string
	// Disposition is the Content-Disposition header. An attachment is downloaded rather than rendered, so it cannot execute a reflection.
	Disposition string
	Err         error
	// Request is exactly what was sent on the wire for this check --
	// attached to any Finding it produced so "Send to Tester" (see
	// web/src/components/ScanModuleResults.tsx) can load the exact request
	// that triggered the finding rather than just the bare target URL.
	Request CapturedRequest
}

// CapturedRequest is the request a check actually sent -- same shape as
// sstiscan.CapturedRequest, kept as its own type per-package, matching how
// Finding/ModuleResult are already duplicated across these scanners (see
// corsscan.Finding's doc comment).
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("xss: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("xss: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// fetchPlain issues a plain GET with no payload -- used for the initial
// baseline request and for fetching pages during the crawl.
func fetchPlain(ctx context.Context, client *http.Client, target string, headers map[string]string) *xssResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return &xssResult{Err: err}
	}
	req.Header.Set("User-Agent", "Aperture-XSSScan")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return &xssResult{Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &xssResult{Err: err}
	}
	return &xssResult{StatusCode: resp.StatusCode, Body: string(raw), ContentType: resp.Header.Get("Content-Type"), Disposition: resp.Header.Get("Content-Disposition")}
}

// fetchInjectionPoint sends value at pt.Param -- for a query/form point,
// every other discovered field/query-key is kept at its harmless default
// (see crawl.go); for a header point, value replaces that one header on an
// otherwise-plain GET of pt.URL.
func fetchInjectionPoint(ctx context.Context, client *http.Client, pt injectionPoint, value string, baseHeaders map[string]string) *xssResult {
	if pt.Kind == kindHeader {
		return fetchWithHeader(ctx, client, pt.URL, pt.Param, value, baseHeaders)
	}
	return fetchWithFields(ctx, client, pt, value, baseHeaders)
}

// fetchInjectionPointThrottled is fetchInjectionPoint gated by sem -- every
// payload module's own fan-out goes through this instead of calling
// fetchInjectionPoint directly, so the scanner's *total* in-flight request
// count (across every payload module running concurrently, each against
// every discovered point) stays bounded. See maxConcurrentRequests' doc
// comment in xss.go.
func fetchInjectionPointThrottled(ctx context.Context, sem chan struct{}, client *http.Client, pt injectionPoint, value string, baseHeaders map[string]string) *xssResult {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return &xssResult{Err: ctx.Err()}
	}
	defer func() { <-sem }()
	return fetchInjectionPoint(ctx, client, pt, value, baseHeaders)
}

// fetchWithFields builds the full field set from pt.Defaults with pt.Param
// overridden to value, then submits it via pt.Method -- GET as a query
// string, POST as an application/x-www-form-urlencoded body, mirroring
// exactly how a browser would submit the discovered <form>.
func fetchWithFields(ctx context.Context, client *http.Client, pt injectionPoint, value string, baseHeaders map[string]string) *xssResult {
	q := url.Values{}
	for k, v := range pt.Defaults {
		if len(v) > 0 {
			q.Set(k, v[0])
		}
	}
	q.Set(pt.Param, value)

	var httpReq *http.Request
	var err error
	var bodyStr string
	if pt.Method == http.MethodPost {
		bodyStr = q.Encode()
		httpReq, err = http.NewRequestWithContext(ctx, http.MethodPost, pt.URL, strings.NewReader(bodyStr))
	} else {
		u, perr := url.Parse(pt.URL)
		if perr != nil {
			return &xssResult{Err: perr}
		}
		u.RawQuery = q.Encode()
		httpReq, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	}
	if err != nil {
		return &xssResult{Err: err}
	}
	httpReq.Header.Set("User-Agent", "Aperture-XSSScan")
	if pt.Method == http.MethodPost {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range baseHeaders {
		httpReq.Header.Set(k, v)
	}

	sentHeaders := map[string]string{}
	for k := range httpReq.Header {
		sentHeaders[k] = httpReq.Header.Get(k)
	}
	captured := CapturedRequest{Method: httpReq.Method, URL: httpReq.URL.String(), Headers: sentHeaders, Body: bodyStr}

	resp, err := client.Do(httpReq)
	if err != nil {
		return &xssResult{Err: err, Request: captured}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &xssResult{Err: err, Request: captured}
	}
	return &xssResult{StatusCode: resp.StatusCode, Body: string(raw), ContentType: resp.Header.Get("Content-Type"), Disposition: resp.Header.Get("Content-Disposition"), Request: captured}
}

// fetchWithHeader issues a plain GET of target with headerName set to
// value -- a payload sent this way never touches the page's own
// query/form fields, so it only ever reaches whatever reads that header
// server-side (an access-log viewer, a debug/error page, ...).
func fetchWithHeader(ctx context.Context, client *http.Client, target, headerName, value string, baseHeaders map[string]string) *xssResult {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return &xssResult{Err: err}
	}
	httpReq.Header.Set("User-Agent", "Aperture-XSSScan")
	for k, v := range baseHeaders {
		httpReq.Header.Set(k, v)
	}
	httpReq.Header.Set(headerName, value)

	sentHeaders := map[string]string{}
	for k := range httpReq.Header {
		sentHeaders[k] = httpReq.Header.Get(k)
	}
	captured := CapturedRequest{Method: http.MethodGet, URL: target, Headers: sentHeaders}

	resp, err := client.Do(httpReq)
	if err != nil {
		return &xssResult{Err: err, Request: captured}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &xssResult{Err: err, Request: captured}
	}
	return &xssResult{StatusCode: resp.StatusCode, Body: string(raw), ContentType: resp.Header.Get("Content-Type"), Disposition: resp.Header.Get("Content-Disposition"), Request: captured}
}
