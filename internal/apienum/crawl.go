package apienum

import (
	"context"
	"github.com/Indigo6415/Aperture/internal/robots"
	"net/url"
	"regexp"
	"strings"
)

// Crawl bounds -- same defaults/caps as domainscan's own crawler (see its
// crawl.go doc comment), reused here for the same reason: route discovery
// needs "every script and every same-origin link this site serves", not
// just a seed page.
const (
	defaultCrawlDepth    = 2
	maxCrawlDepth        = 4
	defaultCrawlMaxPages = 20
	crawlMaxPagesCap     = 50
	maxScripts           = 150
)

var (
	scriptSrcPattern  = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	anchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	formActionPattern = regexp.MustCompile(`(?is)<form[^>]+action\s*=\s*["']([^"']*)["']`)
)

type scriptFile struct {
	URL  string
	Body []byte
}

// crawlResult is what crawlSite hands back: every page it visited (link-
// discovery routes get folded into the route list directly from this),
// every script it downloaded (jsmine.go mines these), and every form
// action it saw along the way (a form submitting to an API path is exactly
// the kind of route a crawl-only tool would otherwise miss).
type crawlResult struct {
	Pages       []string
	Scripts     []scriptFile
	FormActions []string
}

// crawlSite walks t's site starting at t.URL, following same-origin
// <a href> links up to depth hops (bounded by maxPages), downloading every
// distinct same-origin <script src> and recording every <form action>
// along the way. Modeled closely on domainscan's own crawlDomain -- same
// bounds, same "errors fetching one page/script don't sink the crawl"
// posture -- but same-origin-only for scripts too (unlike domainscan's
// retire.js use case, a third-party CDN script's own routes aren't this
// target's attack surface) and additionally collects page URLs and form
// actions, since both feed route discovery directly here.
func crawlSite(ctx context.Context, c *apiClient, t *Target, depth, maxPages int) crawlResult {
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

	visitedPages := map[string]bool{}
	visitedScripts := map[string]bool{}
	var result crawlResult

	type queuedPage struct {
		url   string
		depth int
	}
	policy := robots.Load(ctx, c.http, seed, c.headers)
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

		res, err := c.get(ctx, item.url)
		if err != nil {
			continue
		}
		result.Pages = append(result.Pages, item.url)
		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}

		for _, m := range scriptSrcPattern.FindAllStringSubmatch(res.Text, -1) {
			if len(result.Scripts) >= maxScripts {
				break
			}
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !inScope(seed, resolved) || visitedScripts[resolved.String()] {
				continue
			}
			visitedScripts[resolved.String()] = true
			scriptRes, err := c.get(ctx, resolved.String())
			if err != nil || len(scriptRes.Body) == 0 {
				continue
			}
			result.Scripts = append(result.Scripts, scriptFile{URL: resolved.String(), Body: scriptRes.Body})
		}

		for _, m := range formActionPattern.FindAllStringSubmatch(res.Text, -1) {
			if m[1] == "" {
				continue
			}
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !inScope(seed, resolved) {
				continue
			}
			result.FormActions = append(result.FormActions, resolved.String())
		}

		if item.depth >= depth {
			continue
		}
		for _, m := range anchorHrefPattern.FindAllStringSubmatch(res.Text, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !inScope(seed, resolved) || visitedPages[resolved.String()] {
				continue
			}
			resolved.Fragment = ""
			if !policy.Allowed(resolved) {
				continue
			}
			queue = append(queue, queuedPage{resolved.String(), item.depth + 1})
		}
	}
	return result
}

// inScope is the hard scope guardrail every discovered URL -- from
// crawling, JS mining, or brute forcing -- is checked against before it's
// ever turned into a probe request: only a candidate on the same host as
// the target is in play, so route brute-forcing and JS crawling can't
// wander off-host onto a third-party CDN, an OAuth provider, or anything
// else a page happens to link to (see the package doc's scope guardrail
// goal).
func inScope(target, candidate *url.URL) bool {
	return strings.EqualFold(candidate.Host, target.Host)
}
