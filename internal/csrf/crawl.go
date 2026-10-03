package csrf

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

// Crawl sizing mirrors internal/breach's own email-crawler (see its
// crawl.go doc comment) -- same reasoning: bounded so an aggressive
// RecursionDepth against a large site can't run away.
const (
	crawlDefaultMaxPages = 25
	crawlMaxPagesCap     = 50
)

var (
	crawlAnchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	formPattern            = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	formActionPattern      = regexp.MustCompile(`(?is)action\s*=\s*["']([^"']*)["']`)
	formMethodPattern      = regexp.MustCompile(`(?is)method\s*=\s*["']([^"']*)["']`)
	// methodOverridePattern catches the Rails-style (and equivalent-framework)
	// convention of a hidden "_method" field carrying the real HTTP verb --
	// plain HTML forms can only natively submit GET or POST, so a form that
	// actually performs a PUT/DELETE/PATCH almost always looks like this
	// under the hood.
	methodOverridePattern = regexp.MustCompile(`(?is)<input[^>]+name\s*=\s*["']_method["'][^>]+value\s*=\s*["']([^"']+)["']`)
	// csrfFieldPattern mirrors pwreset.csrfFieldRe -- same pattern, kept as
	// its own copy for the same reason pwreset's own doc comment gives for
	// not sharing types across scanners.
	csrfFieldPattern = regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']*(?:csrf|_token|authenticity_token)[^"']*)["']`)
	// csrfMetaPattern covers the alternative some SPAs use: a page-level
	// <meta name="csrf-token" content="..."> that JS reads and attaches as
	// a request header instead of a hidden form field.
	csrfMetaPattern = regexp.MustCompile(`(?i)<meta[^>]+name=["'](?:csrf-token|csrf-param)["'][^>]+content=["']([^"']*)["']`)
)

// stateChangingMethods is which effective methods this scanner treats as
// "performs a state change, so CSRF protection actually matters here" --
// a plain GET form (a search box, a filter) isn't a CSRF target, since
// nothing it does should have a side effect to forge in the first place.
var stateChangingMethods = map[string]bool{"POST": true, "PUT": true, "DELETE": true, "PATCH": true}

// discoveredForm is one state-changing form found during the crawl. Never
// submitted -- see the package doc comment -- so HasToken/HasMetaToken are
// judged entirely from the page's own markup.
type discoveredForm struct {
	PageURL      string
	Action       string
	Method       string
	HasToken     bool
	HasMetaToken bool
}

// discoveredCookie is one Set-Cookie seen anywhere during the crawl, kept
// the first time it's seen (a cookie set identically on every page isn't
// more informative the second time).
type discoveredCookie struct {
	Name, RawValue, SeenOn string
}

type crawlResult struct {
	PagesScanned []string
	Forms        []discoveredForm
	Cookies      []discoveredCookie
}

type crawlQueuedPage struct {
	url   string
	depth int
}

// crawl fetches seed, extracts its state-changing forms and any cookies it
// sets, then -- up to req.RecursionDepth hops, bounded by MaxPages -- does
// the same for every same-origin <a href> link it finds, exactly the same
// breadth-first same-origin pattern as internal/breach.CrawlForEmails (see
// that function's own doc comment).
func crawl(ctx context.Context, client *http.Client, seed *url.URL, req Request) (*crawlResult, error) {
	maxPages := req.MaxPages
	if maxPages <= 0 {
		maxPages = crawlDefaultMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	visited := map[string]bool{}
	pagesScanned := []string{}
	var forms []discoveredForm
	seenCookies := map[string]bool{}
	var cookies []discoveredCookie

	policy := robots.Load(ctx, client, seed, req.Headers)
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

		body, header, err := fetchPage(ctx, client, item.url, req.Headers)
		if err != nil {
			continue
		}
		pagesScanned = append(pagesScanned, item.url)

		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}
		forms = append(forms, extractForms(body, pageURL)...)

		for _, raw := range header.Values("Set-Cookie") {
			name := raw
			if i := strings.Index(raw, "="); i > 0 {
				name = raw[:i]
			}
			if seenCookies[name] {
				continue
			}
			seenCookies[name] = true
			cookies = append(cookies, discoveredCookie{Name: name, RawValue: raw, SeenOn: item.url})
		}

		if item.depth >= req.RecursionDepth {
			continue
		}
		for _, m := range crawlAnchorHrefPattern.FindAllStringSubmatch(body, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !strings.EqualFold(resolved.Host, seed.Host) || visited[resolved.String()] {
				continue
			}
			resolved.Fragment = ""
			if !policy.Allowed(resolved) {
				continue
			}
			queue = append(queue, crawlQueuedPage{resolved.String(), item.depth + 1})
		}
	}

	sort.Slice(forms, func(i, j int) bool {
		if forms[i].PageURL != forms[j].PageURL {
			return forms[i].PageURL < forms[j].PageURL
		}
		return forms[i].Action < forms[j].Action
	})

	return &crawlResult{PagesScanned: pagesScanned, Forms: forms, Cookies: cookies}, nil
}

func fetchPage(ctx context.Context, client *http.Client, target string, headers map[string]string) (string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Aperture-CSRFScan")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", nil, err
	}
	return string(raw), resp.Header, nil
}

// extractForms pulls every <form> out of body and -- for each one whose
// effective method is state-changing (see stateChangingMethods) -- records
// whether it carries a CSRF-token-looking hidden field or page-level meta
// tag. A form with no action attribute submits to its own page, per the
// HTML spec, so Action falls back to pageURL in that case.
func extractForms(body string, pageURL *url.URL) []discoveredForm {
	hasMetaToken := csrfMetaPattern.MatchString(body)

	var out []discoveredForm
	for _, m := range formPattern.FindAllStringSubmatch(body, -1) {
		attrs, inner := m[1], m[2]

		method := "GET"
		if mm := formMethodPattern.FindStringSubmatch(attrs); mm != nil {
			method = strings.ToUpper(strings.TrimSpace(mm[1]))
		}
		// A _method override hidden field (Rails/Laravel/etc. convention)
		// is the actual verb the server acts on, regardless of what the
		// <form method> attribute itself says (browsers only submit
		// GET/POST natively).
		if om := methodOverridePattern.FindStringSubmatch(inner); om != nil {
			method = strings.ToUpper(strings.TrimSpace(om[1]))
		}
		if !stateChangingMethods[method] {
			continue
		}

		action := pageURL.String()
		if am := formActionPattern.FindStringSubmatch(attrs); am != nil && strings.TrimSpace(am[1]) != "" {
			if resolved, err := pageURL.Parse(strings.TrimSpace(am[1])); err == nil {
				action = resolved.String()
			}
		}

		out = append(out, discoveredForm{
			PageURL:      pageURL.String(),
			Action:       action,
			Method:       method,
			HasToken:     csrfFieldPattern.MatchString(inner),
			HasMetaToken: hasMetaToken,
		})
	}
	return out
}
