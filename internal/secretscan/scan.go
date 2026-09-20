package secretscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// requestTimeout bounds one page/script fetch -- same posture as
	// jwtscan/probescan's own per-request timeouts.
	requestTimeout = 8 * time.Second
	// maxBodyBytes caps how much of one response is read, so a
	// multi-gigabyte response can't blow up scan memory.
	maxBodyBytes = 4 << 20 // 4 MiB
	// defaultMaxPages/maxPagesCap bound total pages+scripts fetched across
	// one Run, regardless of how wide the link graph at RecursionDepth
	// turns out to be.
	defaultMaxPages   = 25
	maxPagesCap       = 50
	maxScriptsPerPage = 8
	entropyThreshold  = 4.5
	entropyMaxLen     = 200
	// maxMatchesPerPatternPerPage caps repeats of the same pattern on one
	// page -- one hit is signal, a hundred (e.g. a JWT appearing in every
	// row of a rendered table) is just noise multiplying the result count.
	maxMatchesPerPatternPerPage = 3
)

// Match is one secret found at one location.
type Match struct {
	Type     string `json:"type"`
	Method   string `json:"method"` // "regex" | "entropy"
	Value    string `json:"value"`
	Location string `json:"location"`
}

// Request is one secret-scan crawl's parameters.
type Request struct {
	URL string
	// RecursionDepth is how many hops of same-origin <a href> links to
	// follow beyond the seed page -- 0 (Snitch's own CLI default) scans
	// just the seed page and the same-origin scripts it references.
	RecursionDepth int
	// Entropy also runs Shannon-entropy detection for unlabeled secrets --
	// off by default, matching Snitch's own CLI default (--entropy is
	// opt-in there too).
	Entropy bool
	// MaxPages overrides defaultMaxPages, capped at maxPagesCap. Zero uses
	// the default.
	MaxPages int
	// Headers is applied to every page/script fetch this crawl makes --
	// e.g. a saved credential's Authorization/Cookie header, needed when
	// the target sits behind auth this crawl would otherwise never get
	// past the seed page's login redirect.
	Headers map[string]string
}

// Response is one crawl's full result.
type Response struct {
	PagesScanned   []string `json:"pagesScanned"`
	ScriptsScanned []string `json:"scriptsScanned"`
	Matches        []Match  `json:"matches"`
}

// newClient never verifies TLS -- this tool routinely targets self-signed
// lab/CTF/internal boxes, same posture as jwtscan/probescan's own clients.
func newClient() *http.Client {
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // deliberate: authorized testing against lab/CTF/self-signed targets
	}
}

var (
	scriptSrcPattern  = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	anchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
)

func fetch(ctx context.Context, client *http.Client, target string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Aperture SecretScan)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func scanText(text, location string, withEntropy bool) []Match {
	var matches []Match
	for _, p := range Patterns {
		for _, m := range p.Regex.FindAllString(text, maxMatchesPerPatternPerPage) {
			matches = append(matches, Match{Type: p.Name, Method: "regex", Value: truncate(m, 200), Location: location})
		}
	}
	if withEntropy {
		for _, s := range findHighEntropyStrings(text, entropyThreshold, entropyMaxLen) {
			matches = append(matches, Match{Type: "High-entropy string", Method: "entropy", Value: s, Location: location})
		}
	}
	return matches
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sameOrigin(base, candidate *url.URL) bool {
	return strings.EqualFold(candidate.Host, base.Host)
}

type queuedPage struct {
	url   string
	depth int
}

// Run crawls req.URL the way Snitch does: fetch a page, scan it for
// secrets, pull out its same-origin <script src> and (if RecursionDepth
// allows) <a href> targets, and repeat -- bounded overall by maxPages so an
// aggressive RecursionDepth against a large site can't run away.
func Run(ctx context.Context, req Request) (*Response, error) {
	seed, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || seed.Host == "" || (seed.Scheme != "http" && seed.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL %q", req.URL)
	}

	maxPages := req.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	if maxPages > maxPagesCap {
		maxPages = maxPagesCap
	}

	client := newClient()
	visitedPages := map[string]bool{}
	visitedScripts := map[string]bool{}
	// Initialized empty rather than left as a nil slice: encoding/json
	// marshals a nil slice as `null`, and the frontend always calls
	// .length on these -- a target that fails to fetch (unreachable,
	// timeout, TLS error) would otherwise crash the whole Secrets tab with
	// "Cannot read properties of null" instead of showing "0 pages scanned".
	pagesScanned := []string{}
	scriptsScanned := []string{}
	var matches []Match

	queue := []queuedPage{{seed.String(), 0}}

	for len(queue) > 0 && len(visitedPages) < maxPages {
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		if visitedPages[item.url] {
			continue
		}
		visitedPages[item.url] = true

		body, err := fetch(ctx, client, item.url, req.Headers)
		if err != nil {
			continue
		}
		pagesScanned = append(pagesScanned, item.url)
		matches = append(matches, scanText(body, item.url, req.Entropy)...)

		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}

		// Same-origin scripts, same posture as probescan's secretsModule:
		// bounded per page so a heavy SPA doesn't fetch hundreds of bundles.
		scriptCount := 0
		for _, m := range scriptSrcPattern.FindAllStringSubmatch(body, -1) {
			if scriptCount >= maxScriptsPerPage || len(visitedPages)+len(visitedScripts) >= maxPages {
				break
			}
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !sameOrigin(seed, resolved) || visitedScripts[resolved.String()] {
				continue
			}
			visitedScripts[resolved.String()] = true
			scriptCount++
			scriptBody, err := fetch(ctx, client, resolved.String(), req.Headers)
			if err != nil {
				continue
			}
			scriptsScanned = append(scriptsScanned, resolved.String())
			matches = append(matches, scanText(scriptBody, resolved.String(), req.Entropy)...)
		}

		if item.depth >= req.RecursionDepth {
			continue
		}
		for _, m := range anchorHrefPattern.FindAllStringSubmatch(body, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !sameOrigin(seed, resolved) || visitedPages[resolved.String()] {
				continue
			}
			resolved.Fragment = ""
			queue = append(queue, queuedPage{resolved.String(), item.depth + 1})
		}
	}

	return &Response{
		PagesScanned:   pagesScanned,
		ScriptsScanned: scriptsScanned,
		Matches:        dedupMatches(matches),
	}, nil
}

func dedupMatches(in []Match) []Match {
	seen := make(map[string]bool, len(in))
	out := make([]Match, 0, len(in))
	for _, m := range in {
		key := m.Type + "|" + m.Location + "|" + m.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}
