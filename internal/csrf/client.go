package csrf

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

const (
	requestTimeout = 8 * time.Second
	maxBodyBytes   = 4 << 20 // 4 MiB -- same as internal/breach's crawler
	// minLengthTolerance is the smallest body-length change treated as noise
	// (a timestamp, a request id) when comparing a replayed response.
	minLengthTolerance = 64
)

// newClient is the crawl client. It follows redirects, since page discovery
// wants the page a link ultimately lands on.
func newClient() *http.Client {
	return netgov.NewClient(requestTimeout, true)
}

// newSubmitClient is the client for replayed state-changing requests. It does
// not follow redirects, so each check is judged on the exact response its own
// request produced. Following a 302 to a login page would make a rejected
// request look like an accepted one.
func newSubmitClient() *http.Client {
	return netgov.NewClient(requestTimeout, false)
}

// parseTarget validates rawURL: it must parse, carry an http or https scheme,
// and name a host.
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

// apiResult is the trimmed response shape the replay checks read. It is
// separate from the crawler's page fetch because these checks send real
// state-changing requests with an operator-supplied body, not page GETs.
type apiResult struct {
	StatusCode int
	Body       string
	Location   string
	Request    CapturedRequest
}

// submitAPIRequest sends one request to target with body verbatim under
// contentType, plus extraHeaders (typically a session cookie). Those headers
// are the same ones the crawl's GETs carry, so the replayed request represents
// the same authenticated state. They go through netgov.ApplyHeaders so a Host
// override is honored.
func submitAPIRequest(ctx context.Context, client *http.Client, target *url.URL, method, body, contentType string, extraHeaders map[string]string) (*apiResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Aperture-CSRF")
	req.Header.Set("Content-Type", contentType)
	netgov.ApplyHeaders(req, extraHeaders)
	sentHeaders := map[string]string{}
	for k := range req.Header {
		sentHeaders[k] = req.Header.Get(k)
	}
	if req.Host != "" {
		sentHeaders["Host"] = req.Host
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
	return &apiResult{StatusCode: resp.StatusCode, Body: string(raw), Location: resp.Header.Get("Location"), Request: captured}, nil
}

// rejectionPhrases are wordings an app uses to say a request was refused for a
// token or request-integrity reason. Many apps answer such a refusal with a
// 200 page, so the status code alone can't show it. A phrase counts only when
// it appears in the replayed response and not in the baseline (see
// outcomeDiffers).
var rejectionPhrases = []string{
	"csrf", "xsrf", "token mismatch", "invalid token", "token is invalid",
	"token missing", "token expired", "authenticity token", "page expired",
	"verification failed", "invalid request",
	// Content-Type refusals, which some apps also send as a 200 page.
	"unsupported media type", "unsupported content type", "content-type",
	"expected json", "invalid json",
}

// outcomeDiffers reports whether got is a different outcome from base, meaning
// the server treated the replayed request differently from the known-good
// baseline. Checks in order: an error status, a changed status, a changed
// redirect target, rejection wording absent from the baseline, and a body
// length change beyond noise. Each check is judged against the baseline, not
// against a fixed rule.
func outcomeDiffers(base, got *apiResult) (bool, string) {
	if got.StatusCode >= 400 {
		return true, fmt.Sprintf("HTTP %d", got.StatusCode)
	}
	if got.StatusCode != base.StatusCode {
		return true, fmt.Sprintf("status changed from %d to %d", base.StatusCode, got.StatusCode)
	}
	if base.StatusCode >= 300 && base.StatusCode < 400 && got.Location != base.Location {
		return true, "redirect target changed"
	}
	gotLower := strings.ToLower(got.Body)
	baseLower := strings.ToLower(base.Body)
	for _, p := range rejectionPhrases {
		if strings.Contains(gotLower, p) && !strings.Contains(baseLower, p) {
			return true, fmt.Sprintf("rejection wording %q appears only in this response", p)
		}
	}
	// The tolerance scales with the baseline so a large page's ordinary
	// variation is not mistaken for a different outcome.
	tol := len(base.Body) / 10
	if tol < minLengthTolerance {
		tol = minLengthTolerance
	}
	if d := len(got.Body) - len(base.Body); d > tol || -d > tol {
		return true, fmt.Sprintf("body length changed by %d bytes", d)
	}
	return false, ""
}
