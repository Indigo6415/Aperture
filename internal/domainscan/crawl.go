package domainscan

import (
	"context"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/robots"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// This crawler exists for exactly one reason: retire.js's own CLI only
// scans a local directory (see retire.go) -- it has no idea how to fetch a
// live site. So before a module that needs "every script this domain
// serves" can run its tool, something has to walk the site and pull those
// scripts down first. Deliberately close in shape to secretscan.Run's own
// crawl (fetch a page, pull same-origin <a href> to keep going, collect
// <script src> along the way) with one deliberate difference: scripts are
// collected regardless of origin. secretscan only follows same-origin
// scripts because it's hunting for the target's own leaked secrets, but a
// vulnerable jQuery/Bootstrap/etc. served from a third-party CDN is exactly
// the kind of finding retire.js exists to catch, and it affects the
// target's security posture just as much as a self-hosted copy would.
const (
	crawlRequestTimeout  = 8 * time.Second
	crawlMaxBodyBytes    = 4 << 20 // 4 MiB, same cap as secretscan/breach's crawlers
	defaultCrawlMaxPages = 20
	crawlMaxPagesCap     = 50
	// defaultCrawlDepth is how many hops of same-origin <a href> links this
	// crawl follows beyond the seed page when the caller doesn't say
	// otherwise. Domain scan's whole premise is "cover the domain", not one
	// page -- unlike secretscan/probescan (whose zero-value default is "just
	// the seed page"), a bare depth of 0 here would defeat the point for
	// anything but a single-page site.
	defaultCrawlDepth = 2
	maxCrawlDepth     = 4
	// maxScripts bounds how many distinct script URLs one crawl will ever
	// fetch, regardless of how many pages/origins reference them -- retire.js
	// itself is fast, but an unbounded fan-out against a large SPA-heavy
	// site could still mean hundreds of downloads.
	maxScripts = 150
)

var (
	scriptSrcPattern  = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	anchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
)

// scriptFile is one downloaded script: the URL it was fetched from and its
// body, ready to be written out for a module (retire.js today) that needs
// files on disk rather than in-memory content.
type scriptFile struct {
	URL  string
	Body []byte
}

// crawlResult is what crawlDomain hands back: every page it visited (for
// the record/UI, even though nothing here scans page HTML itself) and every
// script it downloaded.
type crawlResult struct {
	PagesScanned []string
	Scripts      []scriptFile
}

// newCrawlClient never verifies TLS -- this tool routinely targets
// self-signed lab/CTF/internal boxes, same posture as every other scanner
// in Aperture (see probescan/secretscan/breach's own clients).
func newCrawlClient() *http.Client {
	return netgov.NewClient(crawlRequestTimeout, true)
}

func fetchBytes(ctx context.Context, client *http.Client, target string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Aperture DomainScan)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, crawlMaxBodyBytes))
}

func sameOrigin(base, candidate *url.URL) bool {
	return strings.EqualFold(candidate.Host, base.Host)
}

type queuedPage struct {
	url   string
	depth int
}

// crawlDomain walks t's site starting at t.URL -- following same-origin
// <a href> links up to depth hops, bounded by maxPages -- and downloads
// every distinct <script src> it finds along the way, same-origin or not
// (see this file's doc comment for why). Errors fetching an individual
// page/script are swallowed, same as secretscan.Run: a handful of dead
// links/blocked paths shouldn't sink the whole crawl, they just mean fewer
// scripts to hand the module that asked for them.
func crawlDomain(ctx context.Context, t *Target, depth, maxPages int, headers map[string]string) crawlResult {
	if depth <= 0 {
		depth = defaultCrawlDepth
	}
	if depth > maxCrawlDepth {
		depth = maxCrawlDepth
	}
	if maxPages <= 0 {
		maxPages = defaultCrawlMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	seed, err := url.Parse(t.URL)
	if err != nil || seed.Host == "" {
		return crawlResult{}
	}

	client := newCrawlClient()
	visitedPages := map[string]bool{}
	visitedScripts := map[string]bool{}
	var pagesScanned []string
	var scripts []scriptFile

	policy := robots.Load(ctx, newCrawlClient(), seed, headers)
	queue := []queuedPage{{seed.String(), 0}}

	for len(queue) > 0 && len(visitedPages) < maxPages && len(scripts) < maxScripts {
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		if visitedPages[item.url] {
			continue
		}
		visitedPages[item.url] = true

		body, err := fetchBytes(ctx, client, item.url, headers)
		if err != nil {
			continue
		}
		pagesScanned = append(pagesScanned, item.url)
		html := string(body)

		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}

		for _, m := range scriptSrcPattern.FindAllStringSubmatch(html, -1) {
			if len(scripts) >= maxScripts {
				break
			}
			resolved, err := pageURL.Parse(m[1])
			if err != nil || visitedScripts[resolved.String()] {
				continue
			}
			visitedScripts[resolved.String()] = true
			scriptBody, err := fetchBytes(ctx, client, resolved.String(), headers)
			if err != nil || len(scriptBody) == 0 {
				continue
			}
			scripts = append(scripts, scriptFile{URL: resolved.String(), Body: scriptBody})
		}

		if item.depth >= depth {
			continue
		}
		for _, m := range anchorHrefPattern.FindAllStringSubmatch(html, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !sameOrigin(seed, resolved) || visitedPages[resolved.String()] {
				continue
			}
			resolved.Fragment = ""
			if !policy.Allowed(resolved) {
				continue
			}
			queue = append(queue, queuedPage{resolved.String(), item.depth + 1})
		}
	}

	if pagesScanned == nil {
		pagesScanned = []string{}
	}
	return crawlResult{PagesScanned: pagesScanned, Scripts: scripts}
}
