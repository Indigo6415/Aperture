package ssrf

import (
	"context"
	"github.com/Indigo6415/Aperture/internal/robots"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// crawlDefaultMaxPages/crawlMaxPagesCap mirror internal/csrf's own crawler
// sizing (see that package's crawl.go) -- same reasoning: bounded so an
// aggressive RecursionDepth against a large site can't run away.
const (
	crawlDefaultMaxPages = 25
	crawlMaxPagesCap     = 50
)

var (
	crawlAnchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	crawlFormPattern       = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	crawlFormActionPattern = regexp.MustCompile(`(?is)action\s*=\s*["']([^"']*)["']`)
	crawlFormMethodPattern = regexp.MustCompile(`(?is)method\s*=\s*["']([^"']*)["']`)
	// crawlFormFieldNamePattern covers every element type that submits a
	// named value -- not just <input>, since a <select> or <textarea> field
	// is just as legitimate a candidate parameter name.
	crawlFormFieldNamePattern = regexp.MustCompile(`(?is)<(?:input|select|textarea)[^>]+name\s*=\s*["']([^"']+)["']`)
)

type crawlQueuedPage struct {
	url   string
	depth int
}

// formTarget is one <form>'s own action endpoint and method, discovered
// during the AutoDiscover crawl -- a form found on seed often targets a
// completely different path (e.g. a <form action="/fetch"> found while
// crawling "/"), so its fields need testing against that action directly
// rather than just folding their names into the flat candidate-parameter set
// tested against the page they were found on.
type formTarget struct {
	method string
	url    *url.URL
	params []string
}

// discoverParams walks seed the same same-origin breadth-first way as
// internal/csrf.crawl -- up to recursionDepth hops, bounded by maxPages --
// and returns two things: the flat set of parameter names it turns up
// (query-string keys on same-origin <a href> links, every <form>'s own
// action query keys, and every <input>/<select>/<textarea> field's name
// attribute -- folded into the candidate set tested against URL itself,
// same as before), and one formTarget per distinct (method, action) pair it
// found, so Run can additionally test each form's own fields against its
// actual action endpoint. Used by Run when Request.AutoDiscover is set.
func discoverParams(ctx context.Context, client *http.Client, seed *url.URL, maxPages, recursionDepth int, headers map[string]string) ([]string, []formTarget) {
	if maxPages <= 0 {
		maxPages = crawlDefaultMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	visited := map[string]bool{}
	found := map[string]bool{}
	// formFields/formOrder key each distinct form target as "METHOD url" so
	// the same action hit from several pages (e.g. a shared search form in a
	// nav bar) is only tested once, with every page's field names merged in.
	formFields := map[string]map[string]bool{}
	formMethods := map[string]string{}
	formURLs := map[string]*url.URL{}
	var formOrder []string
	policy := robots.Load(ctx, client, seed, headers)
	queue := []crawlQueuedPage{{seed.String(), 0}}

	for len(queue) > 0 && len(visited) < maxPages {
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		if visited[item.url] {
			continue
		}
		visited[item.url] = true

		body, err := fetchPageBody(ctx, client, item.url, headers)
		if err != nil {
			continue
		}
		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}

		for _, m := range crawlAnchorHrefPattern.FindAllStringSubmatch(body, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !strings.EqualFold(resolved.Host, seed.Host) {
				continue
			}
			for k := range resolved.Query() {
				found[k] = true
			}
			resolved.Fragment = ""
			if item.depth < recursionDepth && !visited[resolved.String()] {
				if !policy.Allowed(resolved) {
					continue
				}
				queue = append(queue, crawlQueuedPage{resolved.String(), item.depth + 1})
			}
		}

		for _, m := range crawlFormPattern.FindAllStringSubmatch(body, -1) {
			attrs, inner := m[1], m[2]

			method := http.MethodGet
			if mm := crawlFormMethodPattern.FindStringSubmatch(attrs); mm != nil && strings.EqualFold(strings.TrimSpace(mm[1]), "post") {
				method = http.MethodPost
			}

			// An absent/empty action submits back to the page itself, per
			// the HTML spec -- same resolution a browser would do.
			resolved := pageURL
			if am := crawlFormActionPattern.FindStringSubmatch(attrs); am != nil {
				if raw := strings.TrimSpace(am[1]); raw != "" {
					r, err := pageURL.Parse(raw)
					if err != nil || !strings.EqualFold(r.Host, seed.Host) {
						continue
					}
					resolved = r
				}
			}
			for k := range resolved.Query() {
				found[k] = true
			}

			fields := crawlFormFieldNamePattern.FindAllStringSubmatch(inner, -1)
			if len(fields) == 0 {
				continue
			}
			key := method + " " + resolved.String()
			if formFields[key] == nil {
				formFields[key] = map[string]bool{}
				formMethods[key] = method
				formURLs[key] = resolved
				formOrder = append(formOrder, key)
			}
			for _, fm := range fields {
				formFields[key][fm[1]] = true
				found[fm[1]] = true
			}
		}
	}

	out := make([]string, 0, len(found))
	for p := range found {
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)

	targets := make([]formTarget, 0, len(formOrder))
	for _, key := range formOrder {
		params := make([]string, 0, len(formFields[key]))
		for p := range formFields[key] {
			if p != "" {
				params = append(params, p)
			}
		}
		if len(params) == 0 {
			continue
		}
		sort.Strings(params)
		targets = append(targets, formTarget{method: formMethods[key], url: formURLs[key], params: params})
	}
	return out, targets
}

func fetchPageBody(ctx context.Context, client *http.Client, target string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Aperture-SSRF")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
