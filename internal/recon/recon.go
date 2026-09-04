// Package recon runs fast, native (stdlib-only) reconnaissance checks
// against a domain -- DNS, TLS certificate inspection, HTTP fingerprinting,
// certificate-transparency subdomain discovery, and WHOIS/RDAP -- as a
// lightweight companion to the ffuf/feroxbuster adapters in
// internal/adapters. Every check finishes in seconds and streams its result
// back via a callback instead of blocking on the whole scan.
package recon

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CheckKind identifies which recon check a Check reports on.
type CheckKind string

const (
	KindDNS        CheckKind = "dns"
	KindTLS        CheckKind = "tls"
	KindHTTP       CheckKind = "http"
	KindSubdomains CheckKind = "subdomains"
	KindWHOIS      CheckKind = "whois"
	// KindTakeover is only ever emitted for a subdomain flagged as a
	// possible dangling-CNAME takeover (see fanOutSubdomains) -- a clean
	// subdomain gets no takeover Check at all, rather than one saying so.
	KindTakeover CheckKind = "takeover"
)

// Status is the lifecycle state of one Check.
type Status string

const (
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusError   Status = "error"
)

// Check is one recon result: either an apex-domain check or the same check
// re-run against a subdomain discovered via certificate transparency. Data's
// shape depends on Kind -- see the doc comment on each check function.
type Check struct {
	Domain     string         `json:"domain"`
	Kind       CheckKind      `json:"kind"`
	Status     Status         `json:"status"`
	Data       map[string]any `json:"data,omitempty"`
	Error      string         `json:"error,omitempty"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt time.Time      `json:"finishedAt,omitempty"`
}

// apexTimeout bounds each of the five top-level checks; subdomainTimeout
// bounds each per-subdomain check, kept shorter since there can be many.
const (
	apexTimeout      = 8 * time.Second
	subdomainTimeout = 4 * time.Second
	subdomainCap     = 40 // stop recursing after this many discovered subdomains
	subdomainWorkers = 8  // bounded concurrency for the subdomain fan-out
)

// NormalizeDomain strips a scheme/path/port the user may have pasted in and
// lowercases the result, so "https://Example.com/path" and "example.com"
// scan the same target.
func NormalizeDomain(input string) (string, error) {
	d := strings.TrimSpace(input)
	if d == "" {
		return "", fmt.Errorf("recon: domain is required")
	}
	// A bare domain has no scheme; url.Parse would otherwise treat it as a
	// relative path and leave Host empty, so only involve url.Parse when a
	// scheme is actually present.
	if strings.Contains(d, "://") {
		u, err := url.Parse(d)
		if err != nil {
			return "", fmt.Errorf("recon: invalid domain: %w", err)
		}
		d = u.Host
	}
	d = strings.TrimSuffix(strings.SplitN(d, "/", 2)[0], ".")
	if h, _, ok := strings.Cut(d, ":"); ok {
		d = h
	}
	d = strings.ToLower(d)
	if d == "" || !strings.Contains(d, ".") {
		return "", fmt.Errorf("recon: %q doesn't look like a domain", input)
	}
	return d, nil
}

// runCheck wraps a single check function with timing/status bookkeeping and
// timeout enforcement so every check function below only needs to worry
// about its own logic and can return a plain error.
func runCheck(ctx context.Context, domain string, kind CheckKind, timeout time.Duration, fn func(context.Context) (map[string]any, error)) Check {
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	data, err := fn(cctx)
	c := Check{Domain: domain, Kind: kind, StartedAt: start, FinishedAt: time.Now(), Data: data}
	if err != nil {
		c.Status = StatusError
		c.Error = err.Error()
	} else {
		c.Status = StatusDone
	}
	return c
}

// Scan runs the five apex-domain checks concurrently, invoking onCheck as
// each one completes (not batched, so slow checks like WHOIS never hold up
// fast ones like DNS), then fans the discovered scheme + subdomains out to
// bounded per-subdomain DNS/TLS/HTTP checks. It returns the HTTP scheme that
// worked for the apex domain ("https" or "http", defaulting to "https" if
// neither responded) and the deduped subdomain list, so the caller can build
// a content-discovery flow against the right scheme without re-probing.
func Scan(ctx context.Context, domain string, onCheck func(Check)) (scheme string, subdomains []string) {
	scheme = "https"

	var wg sync.WaitGroup
	var mu sync.Mutex // guards scheme/subdomains, written from two different goroutines below
	kinds := []CheckKind{KindDNS, KindTLS, KindHTTP, KindSubdomains, KindWHOIS}
	for _, kind := range kinds {
		kind := kind
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch kind {
			case KindDNS:
				onCheck(runCheck(ctx, domain, kind, apexTimeout, func(c context.Context) (map[string]any, error) { return checkDNS(c, domain) }))
			case KindTLS:
				onCheck(runCheck(ctx, domain, kind, apexTimeout, func(c context.Context) (map[string]any, error) { return checkTLS(c, domain) }))
			case KindHTTP:
				check := runCheck(ctx, domain, kind, apexTimeout, func(c context.Context) (map[string]any, error) { return checkHTTP(c, domain) })
				if check.Status == StatusDone {
					if s, ok := check.Data["scheme"].(string); ok {
						mu.Lock()
						scheme = s
						mu.Unlock()
					}
				}
				onCheck(check)
			case KindSubdomains:
				check, found := checkSubdomains(ctx, domain)
				mu.Lock()
				subdomains = found
				mu.Unlock()
				onCheck(check)
			case KindWHOIS:
				onCheck(runCheck(ctx, domain, kind, apexTimeout, func(c context.Context) (map[string]any, error) { return checkWHOIS(c, domain) }))
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	found := subdomains[:min(len(subdomains), subdomainCap)]
	mu.Unlock()
	if len(found) > 0 {
		fanOutSubdomains(ctx, found, onCheck)
	}
	return scheme, subdomains
}

// fanOutSubdomains re-runs DNS/TLS/HTTP (not the apex-only WHOIS/crt.sh
// checks) against every discovered subdomain, capped at subdomainWorkers
// concurrent goroutines so a domain with hundreds of CT log entries can't
// turn one scan into hundreds of simultaneous outbound connections.
func fanOutSubdomains(ctx context.Context, subdomains []string, onCheck func(Check)) {
	sem := make(chan struct{}, subdomainWorkers)
	var wg sync.WaitGroup
	for _, sub := range subdomains {
		sub := sub
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dnsCheck := runCheck(ctx, sub, KindDNS, subdomainTimeout, func(c context.Context) (map[string]any, error) { return checkDNS(c, sub) })
			onCheck(dnsCheck)
			onCheck(runCheck(ctx, sub, KindTLS, subdomainTimeout, func(c context.Context) (map[string]any, error) { return checkTLS(c, sub) }))
			httpCheck := runCheck(ctx, sub, KindHTTP, subdomainTimeout, func(c context.Context) (map[string]any, error) { return checkHTTP(c, sub) })
			onCheck(httpCheck)

			if takeover, flagged := detectTakeover(sub, dnsCheck, httpCheck); flagged {
				onCheck(takeover)
			}
		}()
	}
	wg.Wait()
}

// detectTakeover correlates a subdomain's already-completed DNS and HTTP
// checks (no extra lookups) to flag a possible dangling-CNAME takeover: the
// CNAME names a known cloud provider, and either DNS itself never resolved
// an IP for it (the classic dangling case) or the HTTP response body
// matches that provider's own "unclaimed" fingerprint. A subdomain that
// doesn't match is not flagged at all -- ok is false, and there's nothing
// for the caller to emit.
func detectTakeover(domain string, dnsCheck, httpCheck Check) (Check, bool) {
	if dnsCheck.Status != StatusDone {
		return Check{}, false
	}
	cname, _ := dnsCheck.Data["cname"].(string)
	provider, matchesProvider := detectDanglingCNAME(cname)
	if !matchesProvider {
		return Check{}, false
	}
	a, _ := dnsCheck.Data["a"].([]string)
	aaaa, _ := dnsCheck.Data["aaaa"].([]string)
	danglingDNS := len(a) == 0 && len(aaaa) == 0

	bodyConfirms := false
	if httpCheck.Status == StatusDone {
		body, _ := httpCheck.Data["bodySnippet"].(string)
		bodyConfirms = bodyMatchesProvider(provider, body)
	} else if httpCheck.Status == StatusError {
		// A dangling CNAME frequently can't even be connected to -- that
		// failure is itself corroborating evidence, not a reason to skip.
		bodyConfirms = true
	}

	if !danglingDNS && !bodyConfirms {
		return Check{}, false
	}

	return Check{
		Domain:    domain,
		Kind:      KindTakeover,
		Status:    StatusDone,
		StartedAt: time.Now(),
		Data: map[string]any{
			"cname":    cname,
			"provider": provider,
		},
		FinishedAt: time.Now(),
	}, true
}
