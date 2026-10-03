package graphqlenum

import (
	"bytes"
	"context"
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
// bypass403.requestTimeout/pwreset.requestTimeout.
const requestTimeout = 10 * time.Second

// maxBodyBytes caps how much of a response body a generic (non-introspection)
// request reads -- enough for every check's substring/regex scan.
const maxBodyBytes = 512 * 1024

// maxIntrospectionBytes is the same cap for the introspection response
// specifically: a full schema dump routinely runs into the hundreds of KB
// on a large API, and truncating it mid-JSON would just make the whole
// response fail to parse instead of degrading gracefully.
const maxIntrospectionBytes = 8 * 1024 * 1024

// httpResult is the trimmed-down response shape every check reads.
type httpResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Latency    time.Duration
	// Request is exactly what was sent on the wire for this check --
	// attached to any Finding it produced so "Send to Tester" (see
	// web/src/components/ScanModuleResults.tsx) can load the exact request
	// that triggered the finding rather than just the bare target URL.
	Request CapturedRequest
}

// CapturedRequest is the request a check actually sent -- same shape as
// pwreset.CapturedRequest; kept as its own type per-package, matching how
// Finding/ModuleResult are already duplicated across these scanners (see
// corsscan.Finding's doc comment).
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// newClient builds the shared client every check's requests go through.
// TLS verification is disabled for the same reason as bypass403/pwreset --
// this is routinely pointed at self-signed lab/CTF/internal targets during
// an authorized engagement -- and redirects are left unfollowed so every
// check is judged on the exact response its own request produced.
func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

// parseTarget validates rawURL the same way bypass403.Run/pwreset.Run do: it
// must parse and carry an http/https scheme plus a host.
func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("graphqlenum: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("graphqlenum: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// doHTTP issues one request and reads its body up to limit. method/body/
// contentType are the caller's to build; extraHeaders (e.g. a saved
// credential's Authorization/Cookie) is layered on top of a default
// User-Agent and Accept.
func doHTTP(ctx context.Context, client *http.Client, method, rawURL string, bodyBytes []byte, contentType string, extraHeaders map[string]string, limit int64) (*httpResult, error) {
	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-GraphQLEnum")
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	captured := CapturedRequest{Method: method, URL: rawURL, Headers: sentHeaders, Body: string(bodyBytes)}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return &httpResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: raw, Latency: elapsed, Request: captured}, nil
}

// postJSON sends {"query": query, "variables": variables} as a normal
// GraphQL-over-HTTP POST request -- the shape every real client uses.
func postJSON(ctx context.Context, client *http.Client, target *url.URL, query string, variables map[string]any, headers map[string]string) (*httpResult, error) {
	payload := map[string]any{"query": query}
	if variables != nil {
		payload["variables"] = variables
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return doHTTP(ctx, client, http.MethodPost, target.String(), buf, "application/json", headers, maxBodyBytes)
}

// postRawJSON sends an already-encoded JSON body verbatim -- used for the
// array-based batching probe (a top-level array, not an object) and the
// persisted-query probe (a payload shape postJSON doesn't produce).
func postRawJSON(ctx context.Context, client *http.Client, target *url.URL, rawBody []byte, headers map[string]string) (*httpResult, error) {
	return doHTTP(ctx, client, http.MethodPost, target.String(), rawBody, "application/json", headers, maxBodyBytes)
}

// postForm sends the query as a form-urlencoded POST body -- the CSRF-
// relevant "simple request" content type most GraphQL servers also accept
// alongside JSON (see hacktricks's GraphQL CSRF section).
func postForm(ctx context.Context, client *http.Client, target *url.URL, query string, headers map[string]string) (*httpResult, error) {
	form := url.Values{}
	form.Set("query", query)
	return doHTTP(ctx, client, http.MethodPost, target.String(), []byte(form.Encode()), "application/x-www-form-urlencoded", headers, maxBodyBytes)
}

// getQuery sends the query as a GET request's ?query= parameter -- the
// GraphQL-over-HTTP spec allows GET for queries (never mutations), and some
// introspection-blocking middleware only inspects the POST path.
func getQuery(ctx context.Context, client *http.Client, target *url.URL, query string, headers map[string]string, limit int64) (*httpResult, error) {
	u := *target
	q := u.Query()
	q.Set("query", query)
	u.RawQuery = q.Encode()
	return doHTTP(ctx, client, http.MethodGet, u.String(), nil, "", headers, limit)
}

// gqlEnvelope is the standard GraphQL-over-HTTP response shape. Data is
// left as raw JSON so callers that need the full introspection payload can
// unmarshal it further, while everyone else just checks it's non-null.
type gqlEnvelope struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

type gqlError struct {
	Message string `json:"message"`
}

// parseEnvelope best-effort decodes body as a single GraphQL response
// object. A body that isn't valid JSON, or that batches into an array (see
// parseBatchEnvelope), comes back as a zero-value envelope with ok=false
// rather than an error -- every caller here treats "didn't look like a
// normal GraphQL response" as just another kind of "the technique failed".
func parseEnvelope(body []byte) (env gqlEnvelope, ok bool) {
	if err := json.Unmarshal(body, &env); err != nil {
		return gqlEnvelope{}, false
	}
	return env, true
}

// hasData reports whether env carries a non-null "data" key -- the
// consistent signal this package uses for "the server actually executed
// the operation", regardless of whether it also returned errors alongside
// (a partial response is still evidence the operation ran).
func (env gqlEnvelope) hasData() bool {
	return len(env.Data) > 0 && string(env.Data) != "null"
}

// errorText joins every error message into one lowercase string for the
// substring/regex matching every check module here does against it.
func (env gqlEnvelope) errorText() string {
	msgs := make([]string, len(env.Errors))
	for i, e := range env.Errors {
		msgs[i] = e.Message
	}
	return strings.ToLower(strings.Join(msgs, " | "))
}

// typename extracts data.__typename from a response that queried it --
// used by the baseline check and the mutation-over-GET probe, both of
// which only ever ask for this one field.
func (env gqlEnvelope) typename() string {
	var v struct {
		Typename string `json:"__typename"`
	}
	if err := json.Unmarshal(env.Data, &v); err != nil {
		return ""
	}
	return v.Typename
}
