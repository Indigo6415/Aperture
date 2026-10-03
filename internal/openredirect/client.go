package openredirect

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	requestTimeout = 8 * time.Second
	maxBodyBytes   = 128 * 1024
)

type orResult struct {
	StatusCode int
	Location   string
	Body       string
	// Request is exactly what was sent on the wire for this check --
	// attached to any Finding it produced so "Send to Tester" (see
	// web/src/components/ScanModuleResults.tsx) can load the exact request
	// that triggered the finding rather than just the bare target URL.
	Request CapturedRequest
}

// CapturedRequest is the request a check actually sent -- same shape as
// corsscan.CapturedRequest; kept as its own type per-package rather than
// shared, matching how Finding/ModuleResult are already duplicated across
// these scanners (see corsscan.Finding's doc comment).
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

// parseTarget validates the operator-supplied endpoint: it must be an
// absolute http(s) URL, since everything else (the Location header, the
// Host header, the path-segment probes) is built relative to it.
func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("openredirect: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("openredirect: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// withParam returns a copy of target with param set to value -- replacing
// any existing value that param already had, same as how a browser
// navigating a link with that query string would present it.
func withParam(target *url.URL, param, value string) string {
	reqURL := *target
	q := reqURL.Query()
	q.Set(param, value)
	reqURL.RawQuery = q.Encode()
	return reqURL.String()
}

// send issues one GET for rawURL with headers applied, optionally gated by
// sem (nil means unthrottled), and returns the raw response without following
// anything -- redirect chains are walked explicitly by findCallbackHop.
//
// Two deliberate departures from a plain http.Client:
//   - It calls netgov.Shared.RoundTrip directly. A client refuses to go on
//     past a Location it can't parse (a literal tab, say), but a browser
//     strips that tab and follows the URL, so the raw 3xx has to come back
//     for browserResolve to judge it the way a browser would.
//   - Headers go through netgov.ApplyHeaders, so a Host header is honored.
//     Go's request writer silently drops a Host set via req.Header, which
//     used to make operator-supplied Host headers no-ops.
func send(ctx context.Context, sem chan struct{}, rawURL string, headers map[string]string) (*orResult, error) {
	// Only a semaphore-holding caller is throttled, so the baseline and
	// callback confirmations can go without waiting on the probe fan-out.
	if sem != nil {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { <-sem }()
	}

	// RoundTrip has no http.Client timeout behind it, so the per-request
	// budget is applied to the context instead.
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-OpenRedirect")
	netgov.ApplyHeaders(req, headers)

	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	// Go keeps an overridden Host in req.Host rather than req.Header, so
	// record it explicitly or the captured request would omit the one
	// header this module family exists to vary.
	if req.Host != "" {
		sentHeaders["Host"] = req.Host
	}

	resp, err := netgov.Shared.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &orResult{
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Body:       string(raw),
		Request:    CapturedRequest{Method: http.MethodGet, URL: rawURL, Headers: sentHeaders},
	}, nil
}
