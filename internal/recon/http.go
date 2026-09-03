package recon

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// maxBodyPeek caps how much of the response body checkHTTP reads while
// looking for a <title>, so a huge or slow-streaming page can't blow up
// memory or hang the check past its timeout.
const maxBodyPeek = 64 * 1024

// checkHTTP tries https://domain/ first and falls back to http://domain/ if
// TLS fails outright (connection refused/reset, not just a bad cert -- the
// client also skips certificate verification so a self-signed/expired cert
// doesn't cause an unnecessary fallback to plaintext).
//
// Data shape: {"scheme": string, "finalUrl": string, "statusCode": int,
// "server": string, "title": string, "headers": map[string]string,
// "redirects": []string}
func checkHTTP(ctx context.Context, domain string) (map[string]any, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		data, err := fetchOnce(ctx, scheme, domain)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func fetchOnce(ctx context.Context, scheme, domain string) (map[string]any, error) {
	var redirects []string
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		// Record every hop instead of silently following it, so the UI can
		// show the redirect chain; still bail out after 10 hops like the
		// default client would.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.URL.String())
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+domain+"/", nil)
	if err != nil {
		return nil, fmt.Errorf("http: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyPeek))
	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.TrimSpace(string(m[1]))
	}

	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	return map[string]any{
		"scheme":     scheme,
		"finalUrl":   resp.Request.URL.String(),
		"statusCode": resp.StatusCode,
		"server":     resp.Header.Get("Server"),
		"title":      title,
		"headers":    headers,
		"redirects":  redirects,
	}, nil
}
