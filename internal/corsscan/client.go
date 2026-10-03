package corsscan

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout/maxBodyBytes mirror pwreset's own client.go constants --
// same posture, same reasoning (see that package).
const (
	requestTimeout = 10 * time.Second
	maxBodyBytes   = 256 * 1024
)

// corsResult is the trimmed-down response shape every check reads: the
// three response headers CORS behavior actually turns on, plus enough of
// the rest (status/body length) to judge whether the request even landed
// somewhere meaningful.
type corsResult struct {
	StatusCode         int
	ContentLength      int
	AllowOrigin        string
	AllowOriginPresent bool
	AllowCredentials   string
	AllowMethods       string
	AllowHeaders       string
	// Request is exactly what was sent on the wire for this check -- method,
	// full URL, and the resolved header set (Origin/preflight headers/
	// extraHeaders all merged, the same way a browser or curl would show
	// them) -- so a Finding built from this result can hand the operator's
	// Tester an exact replay rather than an approximation.
	Request CapturedRequest
}

// CapturedRequest is the request a check actually sent, attached to any
// Finding it produced so "Send to Tester" (see web/src/components/
// ScanModuleResults.tsx) can load the exact request that triggered the
// finding rather than just the bare target URL.
type CapturedRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}

func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("corsscan: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("corsscan: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// doRequest issues one request against target. origin, when non-empty, is
// sent as the Origin header -- how every reflection check gets its
// attacker-controlled value in front of the server. preflight, when true,
// sends an OPTIONS request carrying Access-Control-Request-Method/-Headers
// instead of method/body -- a real preflight, not just an OPTIONS request
// with no CORS-specific headers.
func doRequest(ctx context.Context, client *http.Client, target *url.URL, method, origin string, preflight bool, reqMethod, reqHeaders string, extraHeaders map[string]string) (*corsResult, error) {
	httpMethod := method
	if preflight {
		httpMethod = http.MethodOptions
	}
	req, err := http.NewRequestWithContext(ctx, httpMethod, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-CORSScan")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if preflight {
		if reqMethod != "" {
			req.Header.Set("Access-Control-Request-Method", reqMethod)
		}
		if reqHeaders != "" {
			req.Header.Set("Access-Control-Request-Headers", reqHeaders)
		}
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	return &corsResult{
		StatusCode:         resp.StatusCode,
		ContentLength:      len(raw),
		AllowOrigin:        acao,
		AllowOriginPresent: acao != "" || headerPresent(resp.Header, "Access-Control-Allow-Origin"),
		AllowCredentials:   resp.Header.Get("Access-Control-Allow-Credentials"),
		AllowMethods:       resp.Header.Get("Access-Control-Allow-Methods"),
		AllowHeaders:       resp.Header.Get("Access-Control-Allow-Headers"),
		Request:            CapturedRequest{Method: httpMethod, URL: target.String(), Headers: sentHeaders},
	}, nil
}

func headerPresent(h http.Header, name string) bool {
	_, ok := h[http.CanonicalHeaderKey(name)]
	return ok
}

func (r Request) method() string {
	if r.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(r.Method)
}
