package pathtraversal

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/netgov"
)

const requestTimeout = 10 * time.Second

// maxBodyBytes caps how much of each response is read. A file read puts its
// signature near the start, and the base64 wrapper output is small, so a
// larger read only slows the scan down.
const maxBodyBytes = 256 * 1024

// requestSpec is one fully built request: what the check sends. Every probe
// is a requestSpec, so the same struct drives both the send and the captured
// request a finding reports.
type requestSpec struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// CapturedRequest is the request a check actually sent. It has the same shape
// as the other scanners' CapturedRequest and is kept per-package for the same
// reason as their Finding types.
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// sendResult is one response plus what was sent to get it.
type sendResult struct {
	StatusCode int
	Body       string
	// SetCookies is every Set-Cookie header the response carried, so the
	// scanner can find cookies the app sets without being given them.
	SetCookies []string
	Err        error
	Request    CapturedRequest
}

func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

// parseTarget checks that the operator's URL is an absolute http(s) URL.
// Everything else is built relative to it.
func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("pathtraversal: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("pathtraversal: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// send issues spec and returns the response. A non-nil sem throttles the
// request to the scan-wide concurrency limit. The baseline and crawl pass
// nil, so they are not held back by the probe fan-out.
//
// The URL is used exactly as built. Traversal payloads depend on percent
// sequences such as %2e and %252f surviving to the wire, so nothing here
// re-escapes the URL.
func send(ctx context.Context, client *http.Client, sem chan struct{}, spec requestSpec) *sendResult {
	// Wait for a slot before sending. The select also returns early if the
	// run is cancelled while this request is queued.
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
	httpReq.Header.Set("User-Agent", "Aperture-PathTraversal")
	for k, v := range spec.Headers {
		httpReq.Header.Set(k, v)
	}

	// Record the headers as they will be sent, so the captured request
	// matches the wire.
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
		SetCookies: resp.Header.Values("Set-Cookie"),
		Request:    captured,
	}
}
