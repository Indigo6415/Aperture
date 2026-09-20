// Package repeater implements the manual request repeater: send exactly one
// caller-specified HTTP request (method/headers/body, fully editable) and
// report back the raw response -- a single explicit action, not a running
// job, mirroring the rest of Aperture's "one explicit action per click"
// tools (jwtscan, probescan) rather than the engine's streaming node model.
package repeater

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// requestTimeout bounds the one request Send issues -- generous
	// relative to jwtscan/probescan's per-probe timeouts since this is a
	// single explicit, user-initiated request rather than one of hundreds
	// run automatically.
	requestTimeout = 30 * time.Second
	// maxBodyBytes caps how much of the response body is read, so a
	// multi-gigabyte response can't blow up server memory.
	maxBodyBytes = 10 << 20 // 10 MiB
)

// Request is exactly the request to send -- no defaults are inferred beyond
// Method ("" -> GET), so what's sent is what the caller typed.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	// FollowRedirects mirrors a manual repeater's usual default: off, so
	// the exact response the target sent back is what's shown, not
	// whatever a redirect chain eventually lands on.
	FollowRedirects bool
}

// Response is the raw response Send got back, or Error set instead when the
// request never completed (DNS failure, connection refused, timeout) --
// that's still a meaningful, displayable outcome for a manual repeater, not
// a reason to fail the API call itself.
type Response struct {
	StatusCode    int               `json:"statusCode"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	BodyEncoding  string            `json:"bodyEncoding"` // "utf8" | "base64"
	ContentLength int               `json:"contentLength"`
	DurationMs    int64             `json:"durationMs"`
	Raw           string            `json:"raw"`
	Error         string            `json:"error,omitempty"`
}

// newClient never verifies TLS -- this tool routinely targets self-signed
// lab/CTF/internal boxes, same posture as jwtscan/probescan's own clients.
func newClient(followRedirects bool) *http.Client {
	c := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // deliberate: authorized testing against lab/CTF/self-signed targets
	}
	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// Send issues exactly the one request req describes.
func Send(ctx context.Context, req Request) *Response {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	started := time.Now()
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return &Response{Error: err.Error()}
	}
	for name, value := range req.Headers {
		if strings.EqualFold(name, "Host") {
			httpReq.Host = value
			continue
		}
		httpReq.Header.Set(name, value)
	}

	resp, err := newClient(req.FollowRedirects).Do(httpReq)
	if err != nil {
		return &Response{Error: err.Error(), DurationMs: time.Since(started).Milliseconds()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	duration := time.Since(started).Milliseconds()

	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	encoding := "utf8"
	bodyStr := string(bodyBytes)
	if !utf8.ValidString(bodyStr) {
		encoding = "base64"
		bodyStr = base64.StdEncoding.EncodeToString(bodyBytes)
	}

	return &Response{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       headers,
		Body:          bodyStr,
		BodyEncoding:  encoding,
		ContentLength: len(bodyBytes),
		DurationMs:    duration,
		Raw:           rawView(resp, bodyBytes, bodyStr, encoding),
	}
}

// rawView reconstructs a readable "raw response" block for the "view the
// raw response inline" requirement -- status line, headers, blank line,
// body. Go's http.Response doesn't preserve wire-level header order (they
// go through textproto's canonicalized MIMEHeader), so this is a faithful
// reconstruction of the response's content rather than a byte-exact capture
// of what was on the wire.
func rawView(resp *http.Response, bodyBytes []byte, bodyStr, encoding string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", resp.Proto, resp.Status)
	for name, values := range resp.Header {
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\n", name, v)
		}
	}
	b.WriteString("\n")
	if encoding == "base64" {
		fmt.Fprintf(&b, "[binary body, %d bytes, base64-encoded above]", len(bodyBytes))
	} else {
		b.WriteString(bodyStr)
	}
	return b.String()
}
