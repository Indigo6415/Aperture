package csrf

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/robots"
)

// Crawl sizing mirrors internal/breach's own email-crawler (see its
// crawl.go doc comment) -- same reasoning: bounded so an aggressive
// RecursionDepth against a large site can't run away.
const (
	crawlDefaultMaxPages = 25
	crawlMaxPagesCap     = 50
)

// stateChangingMethods is which effective methods this scanner treats as
// "performs a state change, so CSRF protection actually matters here" --
// a plain GET form (a search box, a filter) isn't a CSRF target, since
// nothing it does should have a side effect to forge in the first place.
var stateChangingMethods = map[string]bool{"POST": true, "PUT": true, "DELETE": true, "PATCH": true}

// discoveredForm is one state-changing form submission found during the crawl.
// Never submitted -- see the package doc comment -- so HasToken/HasMetaToken are
// judged entirely from the page's own markup.
type discoveredForm struct {
	PageURL      string
	Action       string
	Method       string
	HasToken     bool
	HasMetaToken bool
}

// discoveredCookie is one Set-Cookie seen anywhere during the crawl. A cookie
// is kept once per distinct name and SameSite value, so a cookie set the same
// way on every page is not reported repeatedly.
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

	// Breadth-first walk: each pass takes the next queued page, stopping at
	// the page budget or when the context is cancelled.
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

		// Record each cookie once per name and SameSite value. Keeping the
		// SameSite value in the key means a weaker variant of the same cookie
		// is still reported even when a stronger one was seen first.
		for _, raw := range header.Values("Set-Cookie") {
			info := parseSetCookie(raw)
			key := info.Name + "|" + info.SameSite
			if seenCookies[key] {
				continue
			}
			seenCookies[key] = true
			cookies = append(cookies, discoveredCookie{Name: info.Name, RawValue: raw, SeenOn: item.url})
		}

		if item.depth >= req.RecursionDepth {
			continue
		}
		// Queue every same-origin link the policy allows, dropping fragments
		// and anything already visited.
		for _, link := range extractLinks(body, pageURL) {
			resolved, err := url.Parse(link)
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

// fetchPage GETs target and returns its body (capped at maxBodyBytes) and
// response headers. The caller's headers are applied through netgov so a Host
// override is honored, which a plain Header.Set would silently drop.
func fetchPage(ctx context.Context, client *http.Client, target string, headers map[string]string) (string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Aperture-CSRFScan")
	netgov.ApplyHeaders(req, headers)
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

// submission is one way a form can be sent: the verb the browser uses and
// the URL it goes to. A form can have several, one per submit button that
// overrides formmethod/formaction.
type submission struct {
	method string
	action *url.URL
}

// extractForms returns every state-changing form submission in body, as a
// browser would send it. Each form's controls are read from its start tag to
// its </form> (or to the next <form> if the closing tag is missing). It
// handles:
//   - method="post" only; other values fall back to GET, as browsers do;
//   - a hidden _method field (Rails/Laravel) when the form posts;
//   - submit buttons with formmethod="post", which send a POST even from a
//     GET form;
//   - relative actions resolved against <base href>;
//   - actions pointing at another origin, which are skipped: a third-party
//     form cannot forge a request to this site, so it is not this site's CSRF.
//
// A form with no action attribute submits to its own page, per the HTML spec,
// so Action falls back to pageURL in that case.
func extractForms(body string, pageURL *url.URL) []discoveredForm {
	doc := stripComments(body)
	tags := scanTags(doc)
	base := documentBase(tags, pageURL)

	hasMetaToken := false
	for _, t := range tags {
		if t.Name == "meta" && isTokenMetaName(t.Attrs["name"]) {
			hasMetaToken = true
			break
		}
	}
	closes := formClosePattern.FindAllStringIndex(doc, -1)

	var out []discoveredForm
	// Walk every start tag, handling each <form> together with its controls.
	for i, ft := range tags {
		if ft.Name != "form" {
			continue
		}
		// End the form at its </form>, or at the next <form> when the closing
		// tag is missing, whichever comes first.
		end := len(doc)
		for _, c := range closes {
			if c[0] >= ft.End {
				end = c[0]
				break
			}
		}
		// Shorten the form's range if a nested <form> starts inside it, since a
		// browser closes the outer form there.
		for k := i + 1; k < len(tags) && tags[k].Start < end; k++ {
			if tags[k].Name == "form" {
				end = tags[k].Start
				break
			}
		}
		// Collect the controls that sit inside the form's range.
		var controls []htmlTag
		for k := i + 1; k < len(tags) && tags[k].Start < end; k++ {
			controls = append(controls, tags[k])
		}

		// Read the form's hidden token field and _method override from its controls.
		hasToken := false
		override := ""
		for _, c := range controls {
			if c.Name != "input" {
				continue
			}
			if strings.EqualFold(c.Attrs["type"], "hidden") && isTokenFieldName(c.Attrs["name"]) {
				hasToken = true
			}
			if c.Attrs["name"] == "_method" {
				override = strings.ToUpper(strings.TrimSpace(c.Attrs["value"]))
			}
		}

		// The form's own submission, to its action (or its own page when no
		// action is given).
		formMethod := "GET"
		if strings.EqualFold(strings.TrimSpace(ft.Attrs["method"]), "post") {
			formMethod = "POST"
		}
		formAction := pageURL
		if a := strings.TrimSpace(ft.Attrs["action"]); a != "" {
			if resolved, err := base.Parse(a); err == nil {
				formAction = resolved
			}
		}
		subs := []submission{{method: formMethod, action: formAction}}

		// A submit button with formmethod="post" sends a POST even when the
		// form itself is GET. Its formaction, if any, replaces the action.
		for _, c := range controls {
			if !isSubmitControl(c) {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(c.Attrs["formmethod"]), "post") {
				continue
			}
			act := formAction
			if fa := strings.TrimSpace(c.Attrs["formaction"]); fa != "" {
				if resolved, err := base.Parse(fa); err == nil {
					act = resolved
				}
			}
			subs = append(subs, submission{method: "POST", action: act})
		}

		// Emit each distinct, same-origin, state-changing submission once.
		seen := map[string]bool{}
		for _, s := range subs {
			method := resolveMethod(s.method, override)
			if !stateChangingMethods[method] {
				continue
			}
			if !strings.EqualFold(s.action.Host, pageURL.Host) {
				continue
			}
			key := method + " " + s.action.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, discoveredForm{
				PageURL:      pageURL.String(),
				Action:       s.action.String(),
				Method:       method,
				HasToken:     hasToken,
				HasMetaToken: hasMetaToken,
			})
		}
	}
	return out
}
