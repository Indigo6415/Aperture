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

// newRequest builds the request for rawURL with its request target written
// exactly as given. http.NewRequest parses and re-escapes the path, which
// fails outright on IIS-style "%u2215" escapes and turns a raw backslash into
// %5C. Both change the bytes a bypass depends on. So the target is handed to
// net/http as an opaque string, which it sends verbatim.
//
// A target that starts with "//" is the one exception: net/http reads a
// leading "//" in an opaque target as a host, so those go through the normal
// parser. They never carry the escapes that parser rejects.
func newRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	scheme, rest, ok := strings.Cut(rawURL, "://")
	// Without "://" there is no host to connect to, so the URL is refused.
	if !ok {
		return nil, fmt.Errorf("pathtraversal: URL %q has no scheme", rawURL)
	}
	// Split the host from the request target at the first "/" or "?".
	host, target := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		host, target = rest[:i], rest[i:]
	}
	// A target that is only a query string is sent as "/?...".
	if strings.HasPrefix(target, "?") {
		target = "/" + target
	}
	if target == "" || strings.HasPrefix(target, "//") {
		return http.NewRequestWithContext(ctx, method, rawURL, body)
	}
	// The placeholder URL validates the host and sets the Host header. Its
	// path is then replaced by the raw target.
	req, err := http.NewRequestWithContext(ctx, method, scheme+"://"+host+"/", body)
	if err != nil {
		return nil, err
	}
	req.URL.Opaque = target
	return req, nil
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
	httpReq, err := newRequest(ctx, spec.Method, spec.URL, body)
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
