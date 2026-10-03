package secretscan

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
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

// Match is one secret found at one location. Value is always the masked form
// (see Mask); the raw secret is never stored or returned. Fingerprint is a
// SHA-256 of the raw value, which identifies the same secret across pages.
type Match struct {
	Type        string `json:"type"`
	Method      string `json:"method"` // "regex" | "entropy"
	Value       string `json:"value"`
	Fingerprint string `json:"fingerprint"`
	// Level is "secret" for credentials and "public-key" for keys designed to
	// ship in client code, which are informational rather than leaks.
	Level    string `json:"level"`
	Location string `json:"location"`
	// Engine is which pattern library produced this match: "core" (this
	// package's own conservative set) or "secretfinder" (the opt-in,
	// broader SecretFinderPatterns library -- see
	// Request.SecretFinderEngine). Entropy matches are always "core", since
	// SecretFinderPatterns has no entropy detector of its own.
	Engine string `json:"engine"`
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
	// SecretFinderEngine also matches every page/script against
	// SecretFinderPatterns (patterns_secretfinder.go), a second, broader
	// pattern library ported from the SecretFinder tool -- off by default,
	// same "opt-in, noisier" posture as Entropy, since it trades more false
	// positives for a higher chance of catching something Patterns' own
	// tighter, \b-bounded regexes miss.
	SecretFinderEngine bool
	// MaxPages overrides defaultMaxPages, capped at maxPagesCap. Zero uses
	// the default.
	MaxPages int
	// Headers is applied to every page/script fetch this crawl makes --
	// e.g. a saved credential's Authorization/Cookie header, needed when
	// the target sits behind auth this crawl would otherwise never get
	// past the seed page's login redirect.
	Headers map[string]string
	// Progress, when set, receives one check per page as the crawl reaches it.
	// Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
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
	return netgov.NewClient(requestTimeout, true)
}

var (
	scriptSrcPattern  = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	anchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
)

// fetch GETs one page or script and returns its body and Content-Type. Saved
// credential headers are applied through netgov.ApplyHeaders so a Host header
// is honored, not silently dropped.
func fetch(ctx context.Context, client *http.Client, target string, headers map[string]string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Aperture SecretScan)")
	netgov.ApplyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", "", err
	}
	return string(body), resp.Header.Get("Content-Type"), nil
}

// scanText runs every pattern over one body and, when asked, the entropy
// detector. Placeholder values are dropped, and every kept value is masked
// before it leaves this function.
func scanText(text, location string, patterns []Pattern, withEntropy bool) []Match {
	var matches []Match
	for _, p := range patterns {
		// Each hit keeps the secret group when the pattern has one, so the
		// value is the credential itself and not the key name around it.
		for _, idx := range p.Regex.FindAllStringSubmatchIndex(text, maxMatchesPerPatternPerPage) {
			raw := secretGroup(text, idx)
			if raw == "" || isPlaceholder(raw) {
				continue
			}
			matches = append(matches, newMatch(p.Name, "regex", raw, location, p.Engine, p.Public))
		}
	}
	if withEntropy {
		for _, s := range findHighEntropyStrings(text, entropyThreshold, entropyMaxLen) {
			matches = append(matches, newMatch("High-entropy string", "entropy", s, location, "core", false))
		}
	}
	return matches
}

// secretGroup returns the value a match should be judged by: the last
// non-empty capture group if the pattern has any, otherwise the whole match.
// Patterns put the credential in the last group (for example the value after
// "api_key:"), so this skips the surrounding key name.
func secretGroup(text string, idx []int) string {
	for g := len(idx)/2 - 1; g >= 1; g-- {
		if idx[2*g] >= 0 && idx[2*g+1] > idx[2*g] {
			return text[idx[2*g]:idx[2*g+1]]
		}
	}
	return text[idx[0]:idx[1]]
}

// newMatch builds a Match from a raw secret value. The raw value is hashed
// and masked here, so no caller can accidentally keep it.
func newMatch(name, method, raw, location, engine string, public bool) Match {
	level := "secret"
	if public {
		level = "public-key"
	}
	return Match{
		Type:        name,
		Method:      method,
		Value:       Mask(raw),
		Fingerprint: Fingerprint(raw),
		Level:       level,
		Location:    location,
		Engine:      engine,
	}
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
	rep := scanprogress.Or(req.Progress)

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

	patterns := Patterns
	if req.SecretFinderEngine {
		patterns = append(append([]Pattern{}, Patterns...), SecretFinderPatterns...)
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

		// Each page is its own check, planned the moment the crawl reaches it,
		// so the grid grows as more pages turn up.
		rep.Plan(scanprogress.Check{ID: item.url, Label: item.url, Group: "Pages"})
		rep.Start(item.url)
		matchesBefore := len(matches)

		body, contentType, err := fetch(ctx, client, item.url, req.Headers)
		if err != nil {
			rep.Done(item.url, 0, err)
			continue
		}
		pagesScanned = append(pagesScanned, item.url)
		// Binary responses (images, archives, fonts) cannot hold readable source,
		// so scanning them only produces noise.
		if !skippableContentType(contentType) {
			matches = append(matches, scanText(body, item.url, patterns, req.Entropy)...)
		}

		pageURL, err := url.Parse(item.url)
		if err != nil {
			rep.Done(item.url, len(matches)-matchesBefore, err)
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
			scriptBody, scriptType, err := fetch(ctx, client, resolved.String(), req.Headers)
			if err != nil {
				continue
			}
			scriptsScanned = append(scriptsScanned, resolved.String())
			if !skippableContentType(scriptType) {
				matches = append(matches, scanText(scriptBody, resolved.String(), patterns, req.Entropy)...)
			}
		}

		// The page and its own scripts are scanned by now, so its check is done
		// whether or not the crawl goes any deeper from here.
		rep.Done(item.url, len(matches)-matchesBefore, nil)
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

// dedupMatches keeps one match per distinct secret per location. Keying on the
// value fingerprint, not the pattern name, collapses overlapping patterns that
// all match the same credential (the three private-key patterns, for example).
func dedupMatches(in []Match) []Match {
	seen := make(map[string]bool, len(in))
	out := make([]Match, 0, len(in))
	for _, m := range in {
		key := m.Fingerprint + "|" + m.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}
