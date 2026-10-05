package openredirect

import (
	"context"
	"errors"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const (
	requestTimeout = 8 * time.Second
	maxBodyBytes   = 128 * 1024
)

// baselineTimeout is the budget for each attempt at the baseline request. It
// is longer than requestTimeout because the first request to a host also runs
// netgov's canary probe, and a host that is still paused from an earlier scan
// makes the request wait out that pause first. Vars rather than consts so the
// tests can shrink them.
var (
	baselineTimeout    = 15 * time.Second
	baselineRetries    = 2
	baselineRetryPause = 3 * time.Second
)

type orResult struct {
	StatusCode int
	Location   string
	// Header is the full response header set. The CRLF check reads injected
	// headers (a Set-Cookie canary) from it, which Location alone can't show.
	Header http.Header
	Body   string
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
	return sendWithin(ctx, sem, requestTimeout, rawURL, headers)
}

// sendWithin is send with an explicit per-request budget, for callers such as
// the baseline that need more time than requestTimeout allows.
func sendWithin(ctx context.Context, sem chan struct{}, timeout time.Duration, rawURL string, headers map[string]string) (*orResult, error) {
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
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
		Header:     resp.Header,
		Body:       string(raw),
		Request:    CapturedRequest{Method: http.MethodGet, URL: rawURL, Headers: sentHeaders},
	}, nil
}

// baselineRequest sends the baseline GET, retrying up to baselineRetries more
// times after a transport failure, with baselineRetryPause between attempts.
// Each attempt gets baselineTimeout. It gives up early if the run's own
// context has ended, since retrying a cancelled run only wastes time.
func baselineRequest(ctx context.Context, rawURL string, headers map[string]string, stats *runStats) (*orResult, error) {
	var lastErr error
	// One initial attempt plus baselineRetries retries.
	for attempt := 0; attempt <= baselineRetries; attempt++ {
		// Pause before every retry (not before the first attempt) so a host
		// that just paused or throttled has a moment to recover.
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(baselineRetryPause):
			}
		}
		res, err := sendWithin(ctx, nil, baselineTimeout, rawURL, headers)
		stats.record(ctx, err)
		if err == nil {
			return res, nil
		}
		lastErr = err
		// The run itself was cancelled; another attempt cannot succeed.
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", baselineRetries+1, lastErr)
}

// runStats counts one run's requests and how many of them timed out. Every
// goroutine in a run adds to it, so both counters are atomic.
type runStats struct {
	requests atomic.Int64
	timedOut atomic.Int64
}

// record counts one finished request, and also counts it as a timeout when
// err is one. ctx is the run's own context, not the per-request one: a
// timeout that only happened because the whole run was ended (cancelled or
// past its own deadline) says nothing about the host, so it is not counted.
func (s *runStats) record(ctx context.Context, err error) {
	s.requests.Add(1)
	if err != nil && ctx.Err() == nil && isTimeout(err) {
		s.timedOut.Add(1)
	}
}

// isTimeout reports whether err means a request ran out of its time budget,
// as opposed to a refused connection, a reset, or a host block.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
