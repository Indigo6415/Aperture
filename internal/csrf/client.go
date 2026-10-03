package csrf

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

const (
	requestTimeout = 8 * time.Second
	maxBodyBytes   = 4 << 20 // 4 MiB -- same as internal/breach's crawler
)

func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, true)
}

func parseTarget(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("csrf: invalid URL %q (must include a scheme, e.g. https://)", rawURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("csrf: unsupported scheme %q", u.Scheme)
	}
	return u, nil
}

// apiResult is the trimmed response shape contentTypeBypassModule reads --
// separate from the crawler's own page-fetch helpers since this one sends a
// real state-changing request with an operator-supplied body under a
// specific Content-Type, not a page-crawling GET.
type apiResult struct {
	StatusCode int
	Body       string
	Request    CapturedRequest
}

// submitAPIRequest issues one request to target carrying body verbatim
// under contentType, plus whatever extraHeaders the operator supplied for
// the scan (typically a session cookie via a credential) -- the same
// headers the crawl's own GETs already carry, reused here so the replayed
// request represents the same authenticated state. User-Agent is set
// explicitly first so an operator-supplied header (map iteration order
// aside) can still override it, matching submit()'s own layering in
// internal/pwreset/client.go.
func submitAPIRequest(ctx context.Context, client *http.Client, target *url.URL, method, body, contentType string, extraHeaders map[string]string) (*apiResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-CSRF")
	req.Header.Set("Content-Type", contentType)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	captured := CapturedRequest{Method: method, URL: target.String(), Headers: sentHeaders, Body: body}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return &apiResult{StatusCode: resp.StatusCode, Body: string(raw), Request: captured}, nil
}
