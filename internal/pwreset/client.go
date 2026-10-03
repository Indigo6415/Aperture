package pwreset

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout bounds a single request's round trip -- same posture as
// bypass403.requestTimeout, just a little more generous since a request-
// reset endpoint routinely triggers a real downstream email send before
// responding.
const requestTimeout = 10 * time.Second

// maxBodyBytes caps how much of a response body any one request reads --
// enough for every check's substring/regex scan, not the whole page.
const maxBodyBytes = 512 * 1024

// httpResult is the trimmed-down response shape every check module reads.
type httpResult struct {
	StatusCode int
	Header     http.Header
	Body       string
	Latency    time.Duration
	// Request is exactly what was sent on the wire for this check --
	// attached to any Finding it produced so "Send to Tester" (see
	// web/src/components/ScanModuleResults.tsx) can load the exact request
	// that triggered the finding rather than just the bare target URL.
	Request CapturedRequest
}

// CapturedRequest is the request a check actually sent -- same shape as
// corsscan.CapturedRequest, plus Body (this package's checks are the first
// to ever submit one); kept as its own type per-package, matching how
// Finding/ModuleResult are already duplicated across these scanners (see
// corsscan.Finding's doc comment).
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// newClient builds the shared client every check module's requests go
// through. TLS verification is disabled for the same reason as
// bypass403.newTransport -- this is routinely pointed at self-signed lab/
// CTF/internal targets during an authorized engagement -- and redirects are
// left unfollowed so every check is judged on the exact response its own
// request produced, not whatever a redirect target happens to return.
func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

// parseTarget validates rawURL the same way bypass403.Run and
// secretscan.Run do: it must parse and carry an http/https scheme plus a
// host -- there's no default-scheme fallback here.
func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("pwreset: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("pwreset: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

func (r Request) method() string {
	if strings.EqualFold(r.Method, "GET") {
		return "GET"
	}
	return "POST"
}

func (r Request) contentType() string {
	if strings.EqualFold(r.ContentType, "json") {
		return "json"
	}
	return "form"
}

func (r Request) identifierField() string {
	if r.IdentifierField != "" {
		return r.IdentifierField
	}
	return "email"
}

// unknownIdentifier returns the value the baseline (and every module that
// just needs *an* identifier that isn't a real account) submits: whatever
// the operator explicitly gave, or a freshly generated one otherwise. The
// generated value is shaped like an email address whenever the identifier
// field or the operator's own KnownIdentifier suggests this form expects
// one -- most request-reset forms do -- and left as a plain token
// otherwise, so a username-based form doesn't get sent something it'll
// reject outright as malformed.
func (r Request) unknownIdentifier() string {
	if r.UnknownIdentifier != "" {
		return r.UnknownIdentifier
	}
	var suffix [5]byte
	// crypto/rand.Read only errors on a broken system entropy source, which
	// would already be fatal well before this ever ran -- falling back to a
	// fixed suffix here just keeps the scan from panicking on that
	// vanishingly unlikely case.
	if _, err := rand.Read(suffix[:]); err != nil {
		copy(suffix[:], "abcde")
	}
	token := hex.EncodeToString(suffix[:])
	if strings.Contains(r.KnownIdentifier, "@") || strings.Contains(strings.ToLower(r.identifierField()), "mail") {
		return "aperture-pwreset-" + token + "@aperture-scan.invalid"
	}
	return "aperture-pwreset-" + token
}

// buildFields returns the identifier plus every extra static field
// (identifier last-wins order matches mergeHeaders' convention elsewhere in
// Aperture, but there's no realistic case where an ExtraFields entry
// actually collides with the identifier field name).
func buildFields(identifierField, identifierValue string, extra map[string]string) map[string]string {
	fields := map[string]string{identifierField: identifierValue}
	for k, v := range extra {
		fields[k] = v
	}
	return fields
}

// submit issues one request-reset attempt. method/contentType decide how
// fields are encoded -- query string for a GET-based endpoint, a JSON body,
// or a form-encoded body -- extraHeaders is layered on top of a default
// User-Agent, and hostHeader, when non-empty, overrides the Host header Go
// would otherwise derive from target's own host; that's how the host-header
// module reuses this same helper to spoof it while still dialing the real
// target.
func submit(ctx context.Context, client *http.Client, target *url.URL, method, contentType string, fields map[string]string, extraHeaders map[string]string, hostHeader string) (*httpResult, error) {
	reqURL := *target
	var body io.Reader
	var bodyStr string

	switch {
	case method == http.MethodGet:
		q := reqURL.Query()
		for k, v := range fields {
			q.Set(k, v)
		}
		reqURL.RawQuery = q.Encode()
	case contentType == "json":
		buf, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		bodyStr = string(buf)
		body = bytes.NewReader(buf)
	default: // form
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		bodyStr = form.Encode()
		body = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-PwReset")
	if method != http.MethodGet {
		if contentType == "json" {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	if hostHeader != "" {
		req.Host = hostHeader
		// req.Host overrides the wire Host header without going through
		// req.Header (Go sends it specially) -- capture it explicitly so
		// the Tester replay reflects the spoofed Host the host-header
		// module actually tests, not the target's real one.
		sentHeaders["Host"] = hostHeader
	}
	captured := CapturedRequest{Method: method, URL: reqURL.String(), Headers: sentHeaders, Body: bodyStr}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &httpResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(raw), Latency: elapsed, Request: captured}, nil
}

// fetchForm issues a plain GET against formURL -- used only by the CSRF/
// form-security modules, never against the submission endpoint itself.
func fetchForm(ctx context.Context, client *http.Client, formURL string) (*httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, formURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-PwReset")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &httpResult{
		StatusCode: resp.StatusCode, Header: resp.Header, Body: string(raw),
		Request: CapturedRequest{Method: http.MethodGet, URL: formURL},
	}, nil
}
