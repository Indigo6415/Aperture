package idor

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"github.com/Indigo6415/Aperture/internal/netgov"
)

// requestTimeout bounds a single probe. IDOR probes are ordinary requests, so
// the same budget the other scanners use is plenty.
const requestTimeout = 10 * time.Second

// maxBodyBytes caps how much of each response is read. The comparison only
// needs a stable fingerprint of the body, so reading the whole of a large
// document would only slow the scan down without changing the verdict.
const maxBodyBytes = 256 * 1024

// requestSpec is one fully built request: exactly what a check sends. Every
// probe is a requestSpec, so the same struct drives both the send and the
// captured request a finding reports for "Send to Tester".
type requestSpec struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// CapturedRequest is the request a check actually sent. It has the same shape
// as the other scanners' CapturedRequest (see internal/pathtraversal) and is
// kept per-package for the same reason as the Finding type.
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// sendResult is one response plus what was sent to get it. Body is kept so a
// check can compare two responses byte-for-byte (an IDOR verdict turns on
// whether a different identifier returned a *different* object), and Obs is
// the fingerprint used for the looser "same kind of page" comparison.
type sendResult struct {
	StatusCode int
	Body       string
	Obs        fingerprint.Observation
	SetCookies []string
	Err        error
	Request    CapturedRequest
}

// newClient builds the HTTP client every probe shares. Redirects are not
// followed on purpose: a 302 to /login is how an app signals that access was
// denied, which is exactly the signal an IDOR check must not throw away by
// chasing the redirect to its (benign) destination.
func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

// parseTarget checks that the operator's URL is an absolute http(s) URL.
// Everything the scan builds is relative to it.
func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	// A reference with no scheme or host cannot be fetched, so it is refused
	// up front rather than failing on the first probe.
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("idor: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("idor: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// send issues spec and returns the response. A non-nil sem throttles the
// request to the scan-wide concurrency limit; the baseline and the control
// requests pass nil so they are not held back by the probe fan-out. The
// shared netgov transport applies the run's rate limit and scope on top.
func send(ctx context.Context, client *http.Client, sem chan struct{}, spec requestSpec) *sendResult {
	// Wait for a concurrency slot before sending. The select also returns
	// early if the run is cancelled while this request is queued.
	if sem != nil {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return &sendResult{Err: ctx.Err()}
		}
		defer func() { <-sem }()
	}

	// A nil body keeps GET requests free of an empty body.
	var body io.Reader
	if spec.Body != "" {
		body = strings.NewReader(spec.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, spec.Method, spec.URL, body)
	if err != nil {
		return &sendResult{Err: err}
	}
	httpReq.Header.Set("User-Agent", "Aperture-IDOR")
	// Operator headers (and the identity under test) override the defaults.
	for k, v := range spec.Headers {
		httpReq.Header.Set(k, v)
	}

	// Record the headers as they will be sent, so the captured request matches
	// the wire exactly.
	sent := map[string]string{}
	for k := range httpReq.Header {
		sent[k] = httpReq.Header.Get(k)
	}
	captured := CapturedRequest{Method: spec.Method, URL: spec.URL, Headers: sent, Body: spec.Body}

	resp, err := client.Do(httpReq)
	if err != nil {
		return &sendResult{Err: err, Request: captured}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &sendResult{Err: err, Request: captured}
	}
	return &sendResult{
		StatusCode: resp.StatusCode,
		Body:       string(raw),
		Obs:        fingerprint.Observe(resp.StatusCode, resp.Header.Get("Content-Type"), raw),
		SetCookies: resp.Header.Values("Set-Cookie"),
		Request:    captured,
	}
}

// cloneHeaders copies a header map so each probe can set its own identity and
// content-type without mutating a shared map.
func cloneHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h)+1)
	maps.Copy(out, h)
	return out
}

// headerValue finds a header by case-insensitive name, since operator header
// keys are not normalized and an exact-case lookup would miss "cookie".
func headerValue(h map[string]string, name string) (string, bool) {
	// Compare every key case-insensitively against name.
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}
