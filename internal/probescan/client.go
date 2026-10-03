package probescan

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
	"github.com/Indigo6415/Aperture/internal/netgov"
)

// probeTimeout bounds a single request against the target -- same posture
// as jwtscan.probeTimeout: every check is one more round-trip, and a full
// scan can run into the hundreds of them.
const probeTimeout = 5 * time.Second

// maxBodyBytes caps how much of a response body a check will read, so a
// misconfigured target serving a multi-gigabyte "directory listing" can't
// blow up scan memory.
const maxBodyBytes = 2 << 20 // 2 MiB

// httpResult is the trimmed-down response shape every check works from.
type httpResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Text       string // Body decoded as UTF-8-ish text, for substring checks
	FinalURL   string // after any followed redirects
}

func (r *httpResult) textLower() string { return strings.ToLower(r.Text) }

// probeClient is the shared transport every module.go check uses. Two
// *http.Client values share one Transport (so connections still pool)
// because Go's CheckRedirect is configured per-Client, not per-request, and
// the original Python modules vary between allow_redirects=True and False
// check by check.
type probeClient struct {
	follow   *http.Client
	noFollow *http.Client
	sem      chan struct{}
	// profile is the host's catch-all fingerprint for this scan. It is nil
	// when the probe that builds it failed, and then nothing is filtered as a
	// soft-404.
	profile *fingerprint.Profile
	// headers is applied to every request this client issues (get and
	// post alike) -- e.g. a saved credential's Authorization/Cookie header,
	// set once here rather than threaded through every check module.
	headers map[string]string
}

// newProbeClient builds a client that never verifies TLS (this tool
// routinely targets self-signed lab/CTF/internal boxes -- same posture as
// jwtscan.newHTTPClient) and bounds how many requests are ever in flight at
// once across every module running concurrently, so a scan stays a
// reasonably-paced burst rather than a request flood. headers (may be nil)
// is applied to every request issued by the returned client.
func newProbeClient(concurrency int, headers map[string]string) *probeClient {
	return &probeClient{
		follow:   netgov.NewClient(probeTimeout, true),
		noFollow: netgov.NewClient(probeTimeout, false),
		sem:      make(chan struct{}, concurrency),
		headers:  headers,
	}
}

func (c *probeClient) acquire(ctx context.Context) bool {
	select {
	case c.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *probeClient) release() { <-c.sem }

// get issues a GET against url, following redirects when follow is true.
// A network-level error (timeout, connection refused, DNS failure) is
// returned as an error, exactly as requests.RequestException was silently
// swallowed by the Python modules -- callers here likewise just treat it as
// "no finding" rather than aborting the module.
func (c *probeClient) get(ctx context.Context, target string, follow bool) (*httpResult, error) {
	if !c.acquire(ctx) {
		return nil, ctx.Err()
	}
	defer c.release()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	client := c.noFollow
	if follow {
		client = c.follow
	}
	return doRequest(client, req)
}

// post issues a POST with the given content type and body, always following
// redirects (mirrors the Python modules' POST calls, none of which pass
// allow_redirects=False).
func (c *probeClient) post(ctx context.Context, target, contentType string, body []byte) (*httpResult, error) {
	if !c.acquire(ctx) {
		return nil, ctx.Err()
	}
	defer c.release()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", contentType)
	return doRequest(c.follow, req)
}

func doRequest(client *http.Client, req *http.Request) (*httpResult, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	finalURL := req.URL.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &httpResult{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		Text:       string(body),
		FinalURL:   finalURL,
	}, nil
}
