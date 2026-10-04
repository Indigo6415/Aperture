package breach

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/robots"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// This crawler is internal/secretscan.Run's own crawl (fetch a page, pull
// its same-origin <script src> and, if RecursionDepth allows, <a href>
// targets, repeat) with its secret-pattern regexes swapped for an
// email-address one -- the on-ramp into Lookup for an operator who doesn't
// have a starting list of addresses yet. See secretscan/scan.go for the
// original; constants/behavior here are deliberately kept in step with it.
const (
	crawlRequestTimeout    = 8 * time.Second
	crawlMaxBodyBytes      = 4 << 20 // 4 MiB
	crawlDefaultMaxPages   = 25
	crawlMaxPagesCap       = 50
	crawlMaxScriptsPerPage = 8
)

// emailRe is a standard RFC-5322-ish local-part/domain pattern -- loose by
// design, since this runs over raw HTML/JS text rather than a context where
// stricter validation would reject real-world addresses.
var emailRe = regexp.MustCompile(`[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+`)

var (
	crawlScriptSrcPattern  = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	crawlAnchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
)

// nonEmailLabelExts filters out email-shaped matches whose final label is
// actually an asset extension -- sprite@2x.png and icon@3x.svg turn up
// constantly in CSS/JS bundles and would otherwise pass as a plausible
// address.
var nonEmailLabelExts = map[string]bool{
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true, "bmp": true, "ico": true,
	"avif": true, "css": true, "js": true, "mjs": true, "map": true, "json": true, "xml": true,
	"html": true, "htm": true, "php": true, "pdf": true, "mp4": true, "webm": true, "mp3": true,
	"woff": true, "woff2": true, "ttf": true, "eot": true, "otf": true,
}

// placeholderEmailDomains are the reserved and documentation domains that
// appear in code, docs, and sample configs. An address at one of them is not
// a person's contact, so it is dropped rather than reported as a finding.
var placeholderEmailDomains = map[string]bool{
	"example.com": true, "example.org": true, "example.net": true, "example.edu": true,
	"test.com": true, "domain.com": true, "email.com": true, "yourdomain.com": true,
	"yourcompany.com": true, "company.com": true, "localhost": true, "invalid": true,
}

// CrawlRequest is one email-crawl's parameters -- same shape/reasoning as
// secretscan.Request.
type CrawlRequest struct {
	URL string
	// RecursionDepth is how many hops of same-origin <a href> links to
	// follow beyond the seed page -- 0 scans just the seed page and the
	// same-origin scripts it references.
	RecursionDepth int
	// MaxPages overrides crawlDefaultMaxPages, capped at crawlMaxPagesCap.
	// Zero uses the default.
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

// CrawlResponse is one crawl's full result.
type CrawlResponse struct {
	PagesScanned   []string `json:"pagesScanned"`
	ScriptsScanned []string `json:"scriptsScanned"`
	Emails         []string `json:"emails"`
	// EmailSources maps each address in Emails to every page/script URL it
	// was found on -- lets the frontend show not just that an address turned
	// up but where, which matters when a crawl covers many pages.
	EmailSources map[string][]string `json:"emailSources"`
}

func crawlClient() *http.Client {
	return netgov.NewClient(crawlRequestTimeout, true)
}

func crawlFetch(ctx context.Context, client *http.Client, target string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	// Same UA as Lookup -- HIBP rejects a blank one outright, and plenty of
	// sites' WAFs treat a blank/default Go UA as a bot signal worth
	// blocking regardless.
	req.Header.Set("User-Agent", "Aperture-Recon-Tool")
	// ApplyHeaders honors a Host override; a plain Header.Set silently drops it.
	netgov.ApplyHeaders(req, headers)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, crawlMaxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// collectEmails regex-scans text and records every plausible address it
// finds (see normalizeEmail) into into, keyed by address with source added
// to that address's set of pages/scripts it was found on.
func collectEmails(text, source string, into map[string]map[string]bool) {
	for _, m := range emailRe.FindAllString(text, -1) {
		if e := normalizeEmail(m); e != "" {
			if into[e] == nil {
				into[e] = map[string]bool{}
			}
			into[e][source] = true
		}
	}
}

// normalizeEmail lowercases a raw regex match and drops it if its
// top-level label is actually a static-asset extension (see
// nonEmailLabelExts).
func normalizeEmail(raw string) string {
	e := strings.ToLower(strings.TrimSpace(raw))
	at := strings.LastIndex(e, "@")
	if at < 0 || at == len(e)-1 {
		return ""
	}
	domainPart := e[at+1:]
	dot := strings.LastIndex(domainPart, ".")
	if dot < 0 {
		return ""
	}
	tld := domainPart[dot+1:]
	// A real top-level domain has letters. A version such as "pkg@1.2.3" or an
	// image density suffix such as "icon@2.0" ends in digits, so it is not an address.
	if !hasLetter(tld) {
		return ""
	}
	if nonEmailLabelExts[tld] {
		return ""
	}
	if placeholderEmailDomains[domainPart] {
		return ""
	}
	return e
}

// hasLetter reports whether s contains at least one ASCII letter.
func hasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func crawlSameOrigin(base, candidate *url.URL) bool {
	return strings.EqualFold(candidate.Host, base.Host)
}

type crawlQueuedPage struct {
	url   string
	depth int
}

// CrawlForEmails crawls req.URL exactly the way secretscan.Run crawls for
// secrets: fetch a page, scan it (and its same-origin scripts) for email
// addresses, and -- if RecursionDepth allows -- follow its same-origin
// <a href> links and repeat, bounded overall by MaxPages so an aggressive
// RecursionDepth against a large site can't run away.
func CrawlForEmails(ctx context.Context, req CrawlRequest) (*CrawlResponse, error) {
	rep := scanprogress.Or(req.Progress)

	seed, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || seed.Host == "" || (seed.Scheme != "http" && seed.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL %q", req.URL)
	}

	maxPages := req.MaxPages
	if maxPages <= 0 {
		maxPages = crawlDefaultMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	client := crawlClient()
	visitedPages := map[string]bool{}
	visitedScripts := map[string]bool{}
	// Initialized empty rather than left as a nil slice -- same reasoning
	// as secretscan.Run: the frontend always calls .length on these, and a
	// target that fails to fetch shouldn't crash the whole tab over a null.
	pagesScanned := []string{}
	scriptsScanned := []string{}
	// emails maps each found address to the set of page/script URLs it
	// turned up on (see collectEmails).
	emails := map[string]map[string]bool{}

	policy := robots.Load(ctx, client, seed, req.Headers)
	queue := []crawlQueuedPage{{seed.String(), 0}}

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
		emailsBefore := len(emails)

		body, err := crawlFetch(ctx, client, item.url, req.Headers)
		if err != nil {
			rep.Done(item.url, 0, err)
			continue
		}
		pagesScanned = append(pagesScanned, item.url)
		collectEmails(body, item.url, emails)

		pageURL, err := url.Parse(item.url)
		if err != nil {
			rep.Done(item.url, len(emails)-emailsBefore, err)
			continue
		}

		// Same-origin scripts, same posture as secretscan.Run: bounded per
		// page so a heavy SPA doesn't fetch hundreds of bundles.
		scriptCount := 0
		for _, m := range crawlScriptSrcPattern.FindAllStringSubmatch(body, -1) {
			if scriptCount >= crawlMaxScriptsPerPage || len(visitedPages)+len(visitedScripts) >= maxPages {
				break
			}
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !crawlSameOrigin(seed, resolved) || visitedScripts[resolved.String()] {
				continue
			}
			visitedScripts[resolved.String()] = true
			scriptCount++
			scriptBody, err := crawlFetch(ctx, client, resolved.String(), req.Headers)
			if err != nil {
				continue
			}
			scriptsScanned = append(scriptsScanned, resolved.String())
			collectEmails(scriptBody, resolved.String(), emails)
		}

		// The page and its own scripts are scanned by now, so its check is done
		// whether or not the crawl goes any deeper from here.
		rep.Done(item.url, len(emails)-emailsBefore, nil)
		if item.depth >= req.RecursionDepth {
			continue
		}
		for _, m := range crawlAnchorHrefPattern.FindAllStringSubmatch(body, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !crawlSameOrigin(seed, resolved) || visitedPages[resolved.String()] {
				continue
			}
			resolved.Fragment = ""
			if !policy.Allowed(resolved) {
				continue
			}
			queue = append(queue, crawlQueuedPage{resolved.String(), item.depth + 1})
		}
	}

	emailList := make([]string, 0, len(emails))
	emailSources := make(map[string][]string, len(emails))
	for e, sources := range emails {
		emailList = append(emailList, e)
		emailSources[e] = sortedKeys(sources)
	}
	sort.Strings(emailList)

	return &CrawlResponse{
		PagesScanned:   pagesScanned,
		ScriptsScanned: scriptsScanned,
		Emails:         emailList,
		EmailSources:   emailSources,
	}, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
