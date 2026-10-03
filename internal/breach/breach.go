// Package breach checks whether an email address has appeared in a known
// data breach, via HaveIBeenPwned's breached-account API. The endpoint has
// required a per-installation subscription key since 2024 (see
// https://haveibeenpwned.com/API/Key) -- there is no keyless fallback the
// way internal/cve's NVD lookup has.
package breach

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
)

const breachedAccountEndpoint = "https://haveibeenpwned.com/api/v3/breachedaccount/"

// Breach is one breach an email address appeared in -- the subset of HIBP's
// own record shape Aperture surfaces.
type Breach struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Domain      string   `json:"domain,omitempty"`
	BreachDate  string   `json:"breachDate,omitempty"`
	PwnCount    int      `json:"pwnCount,omitempty"`
	DataClasses []string `json:"dataClasses,omitempty"`
	// IsVerified is false for a handful of unconfirmed/"fabricated" breaches
	// HIBP still lists -- surfaced so the UI can flag those as less certain
	// rather than presenting every hit with equal confidence.
	IsVerified bool `json:"isVerified"`
	// IsSensitive marks a breach HIBP itself withholds from its public
	// domain-search results (adult sites, etc.) -- still returned here since
	// this is the account-search endpoint, not domain search, but worth
	// calling out distinctly in the UI.
	IsSensitive bool `json:"isSensitive"`
}

// hibpBreach mirrors the fields of HIBP's breachedaccount response this
// package cares about; see
// https://haveibeenpwned.com/API/v3#BreachModel.
type hibpBreach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	PwnCount    int      `json:"PwnCount"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
	IsSensitive bool     `json:"IsSensitive"`
}

// Lookup returns every breach HIBP has on file for email, most recent first.
// A "no breaches found" result is HIBP's own 404 -- not an error here, just
// a nil/empty result -- so callers can render "no breaches" the same way a
// clean Probe/Secret Scanner run does.
func Lookup(ctx context.Context, email, apiKey string) ([]Breach, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("breach: an API key is required (see Settings)")
	}
	if err := limiter.wait(ctx); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("truncateResponse", "false")
	reqURL := breachedAccountEndpoint + url.PathEscape(email) + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("breach: build request: %w", err)
	}
	req.Header.Set("hibp-api-key", apiKey)
	// HIBP rejects any request with no User-Agent outright.
	req.Header.Set("User-Agent", "Aperture-Recon-Tool")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("breach: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("breach: HIBP API key rejected")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("breach: rate limited by HIBP, try again shortly")
	case http.StatusOK:
		// fall through
	default:
		return nil, fmt.Errorf("breach: unexpected status %d", resp.StatusCode)
	}

	var raw []hibpBreach
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("breach: decode: %w", err)
	}

	out := make([]Breach, len(raw))
	for i, b := range raw {
		out[i] = Breach{
			Name: b.Name, Title: b.Title, Domain: b.Domain, BreachDate: b.BreachDate,
			PwnCount: b.PwnCount, DataClasses: b.DataClasses, IsVerified: b.IsVerified, IsSensitive: b.IsSensitive,
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BreachDate > out[j].BreachDate })
	return out, nil
}
