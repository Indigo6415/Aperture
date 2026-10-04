package xxe

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

// requestTimeout is generous for the same reason as internal/ssrf's: an
// external entity that points at a slow or unreachable host makes the target's
// parser wait on that fetch before it answers this scanner at all.
const requestTimeout = 12 * time.Second

// maxBodyBytes caps how much of each response is read. Entity reads put their
// signature near the start of the output, and error messages are short, so a
// larger read only slows the scan down.
const maxBodyBytes = 256 * 1024

// maxConcurrentRequests bounds in-flight requests across every module and
// point of a run. Same reasoning as the other scanners: a burst of entity
// payloads reads to the target as an outage rather than a signal.
const maxConcurrentRequests = 16

// CapturedRequest is the request a check actually sent. Body is the full XML
// document, which is what "Send to Tester" needs to replay a finding exactly.
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// sendResult is one response plus what was sent to get it.
type sendResult struct {
	StatusCode  int
	ContentType string
	Body        string
	Err         error
	Request     CapturedRequest
}

func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

// parseTarget checks that the operator's URL is an absolute http(s) URL.
// Everything else is built relative to it.
func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("xxe: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("xxe: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// send POSTs (or PUTs) body to target as one request. contentType is set
// unless the operator's own headers already name a Content-Type, so an
// explicit override always wins. sem, when non-nil, gates the send so the
// run's total in-flight count stays bounded.
func send(ctx context.Context, sem chan struct{}, client *http.Client, method string, target *url.URL, contentType, body string, headers map[string]string) *sendResult {
	if sem != nil {
		// Wait for a slot, but give up as soon as the run is cancelled so a
		// stopped scan doesn't sit queued behind requests that will never run.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return &sendResult{Err: ctx.Err()}
		}
		defer func() { <-sem }()
	}

	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(body))
	if err != nil {
		return &sendResult{Err: err}
	}
	req.Header.Set("User-Agent", "Aperture-XXE")
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	sent := map[string]string{}
	for k := range req.Header {
		sent[k] = req.Header.Get(k)
	}
	captured := CapturedRequest{Method: method, URL: target.String(), Headers: sent, Body: body}

	resp, err := client.Do(req)
	if err != nil {
		return &sendResult{Err: err, Request: captured}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return &sendResult{Err: err, StatusCode: resp.StatusCode, Request: captured}
	}
	return &sendResult{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        string(raw),
		Request:     captured,
	}
}
