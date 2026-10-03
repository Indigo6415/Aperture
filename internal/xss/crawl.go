package xss

import (
	"context"
	"github.com/Indigo6415/Aperture/internal/robots"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// crawlDefaultMaxPages/crawlMaxPagesCap mirror internal/sstiscan's own
// crawler sizing -- same reasoning: bounded so an aggressive
// RecursionDepth against a large site can't run away.
const (
	crawlDefaultMaxPages = 25
	crawlMaxPagesCap     = 50
)

var (
	crawlAnchorHrefPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	crawlFormPattern       = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	crawlFormActionPattern = regexp.MustCompile(`(?is)action\s*=\s*["']([^"']*)["']`)
	crawlFormMethodPattern = regexp.MustCompile(`(?is)method\s*=\s*["']([^"']*)["']`)
	// crawlFieldPattern covers every element type that submits a named
	// value -- not just <input>, since a <select> or <textarea> field is
	// just as legitimate an injection point.
	crawlFieldPattern     = regexp.MustCompile(`(?is)<(?:input|select|textarea)([^>]*)>`)
	fieldNameAttrPattern  = regexp.MustCompile(`(?is)name\s*=\s*["']([^"']+)["']`)
	fieldValueAttrPattern = regexp.MustCompile(`(?is)value\s*=\s*["']([^"']*)["']`)
	fieldTypeAttrPattern  = regexp.MustCompile(`(?is)type\s*=\s*["']([^"']*)["']`)
)

// injectionHeaders is the fixed set of request headers commonly logged,
// echoed into an error/debug page, or rendered into an admin-facing
// "recent visitors"/access-log view -- a classic reflected-XSS vector
// entirely outside any visible form field (see internal/sstiscan's own
// injectionHeaders, which this mirrors). Tested once, against the seed page
// only (see crawl below), not every crawled page, to keep the payload
// fan-out bounded the same way commonInputParams is a fixed list rather
// than growing with every page visited.
var injectionHeaders = []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "Accept-Language", "Origin"}

type injectionKind string

const (
	kindQuery  injectionKind = "query parameter"
	kindForm   injectionKind = "form field"
	kindHeader injectionKind = "request header"
)

// injectionPoint is one place a payload can be placed: a query-string
// parameter, a discovered <form> field (GET or POST), or a request header --
// "every input box and every place user-controlled data may be
// displayed/used". Shaped like internal/sstiscan.injectionPoint, which this
// mirrors field-for-field.
type injectionPoint struct {
	Kind    injectionKind
	PageURL string // where this was discovered, for reporting
	URL     string // the request URL (query/header target, or form action)
	Method  string // GET or POST
	Param   string // the field/param/header name
	// Defaults carries every other field's (query or form) value, so
	// fetchWithFields can submit a realistic, complete request with only
	// Param itself replaced by the payload. Unused for header points.
	Defaults url.Values
}

func pointKey(p injectionPoint) string {
	return string(p.Kind) + "|" + p.Method + "|" + p.URL + "|" + p.Param
}

// pointDescriptor renders pt for a Finding's Label/Detail.
func pointDescriptor(pt injectionPoint) string {
	switch pt.Kind {
	case kindHeader:
		return "the " + quote(pt.Param) + " request header on " + pt.URL
	case kindForm:
		return "form field " + quote(pt.Param) + " (" + pt.Method + " " + pt.URL + ")"
	default:
		return "query parameter " + quote(pt.Param) + " on " + pt.URL
	}
}

func quote(s string) string { return `"` + s + `"` }

type crawlQueuedPage struct {
	url   string
	depth int
}

// crawledPage is one same-origin page fetched during the crawl -- its raw
// body feeds runDomSinkModule's static analysis, which (unlike the other
// modules here) needs the page's own markup/script content directly rather
// than a derived injectionPoint.
type crawledPage struct {
	URL, Body string
}

type crawlResult struct {
	PagesScanned []string
	Points       []injectionPoint
	Pages        []crawledPage
}

// crawl fetches seed, extracts every injection point its own URL/forms
// carry (plus, on the seed page only, the fixed injectionHeaders set) and
// the page's raw body, then -- up to req.RecursionDepth hops, bounded by
// MaxPages -- does the same for every same-origin <a href> link it finds.
// Same same-origin breadth-first pattern as internal/csrf.crawl /
// internal/sstiscan.crawl.
func crawl(ctx context.Context, client *http.Client, seed *url.URL, req Request) (*crawlResult, error) {
	maxPages := req.MaxPages
	if maxPages <= 0 {
		maxPages = crawlDefaultMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	visited := map[string]bool{}
	var pagesScanned []string
	var pages []crawledPage
	seenPoints := map[string]bool{}
	var points []injectionPoint
	addPoint := func(p injectionPoint) {
		key := pointKey(p)
		if seenPoints[key] {
			return
		}
		seenPoints[key] = true
		points = append(points, p)
	}

	policy := robots.Load(ctx, client, seed, req.Headers)
	queue := []crawlQueuedPage{{seed.String(), 0}}
	firstPage := true

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

		res := fetchPlain(ctx, client, item.url, req.Headers)
		if res.Err != nil {
			continue
		}
		body := res.Body
		pagesScanned = append(pagesScanned, item.url)
		pages = append(pages, crawledPage{URL: item.url, Body: body})

		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}

		if pageURL.RawQuery != "" {
			base := *pageURL
			base.RawQuery = ""
			base.Fragment = ""
			query := pageURL.Query()
			for k := range query {
				addPoint(injectionPoint{Kind: kindQuery, PageURL: item.url, URL: base.String(), Method: http.MethodGet, Param: k, Defaults: query})
			}
		}

		for _, fp := range extractFormPoints(body, pageURL) {
			addPoint(fp)
		}

		if firstPage {
			for _, h := range injectionHeaders {
				addPoint(injectionPoint{Kind: kindHeader, PageURL: item.url, URL: item.url, Method: http.MethodGet, Param: h})
			}
			firstPage = false
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

	sort.Slice(points, func(i, j int) bool {
		if points[i].URL != points[j].URL {
			return points[i].URL < points[j].URL
		}
		return points[i].Param < points[j].Param
	})

	return &crawlResult{PagesScanned: pagesScanned, Points: points, Pages: pages}, nil
}

// extractFormPoints pulls every <form> out of body and returns one
// injectionPoint per named field -- every field's harmless default value
// (its own value="" attribute if present, else a generic filler) becomes
// that form's Defaults, shared across all of that form's points so
// fetchWithFields can submit the whole form with only the one field under
// test replaced. Same approach (and the same "submitting a form is the
// point of this scanner, not a side effect to avoid" reasoning) as
// internal/sstiscan.extractFormPoints -- unlike internal/csrf, which
// deliberately never submits a discovered form (see that package's doc
// comment), testing whether input validation actually holds requires
// exercising the real input mechanism, GET or POST alike.
func extractFormPoints(body string, pageURL *url.URL) []injectionPoint {
	var out []injectionPoint

	for _, m := range crawlFormPattern.FindAllStringSubmatch(body, -1) {
		attrs, inner := m[1], m[2]

		method := http.MethodGet
		if mm := crawlFormMethodPattern.FindStringSubmatch(attrs); mm != nil && strings.EqualFold(strings.TrimSpace(mm[1]), "post") {
			method = http.MethodPost
		}

		action := *pageURL
		action.RawQuery = ""
		action.Fragment = ""
		if am := crawlFormActionPattern.FindStringSubmatch(attrs); am != nil && strings.TrimSpace(am[1]) != "" {
			if resolved, err := pageURL.Parse(strings.TrimSpace(am[1])); err == nil {
				resolved.RawQuery = ""
				resolved.Fragment = ""
				action = *resolved
			}
		}

		defaults := url.Values{}
		var fieldNames []string
		for _, fm := range crawlFieldPattern.FindAllStringSubmatch(inner, -1) {
			fieldAttrs := fm[1]
			nm := fieldNameAttrPattern.FindStringSubmatch(fieldAttrs)
			if nm == nil || nm[1] == "" {
				continue
			}
			name := nm[1]
			value := "aperture"
			if tm := fieldTypeAttrPattern.FindStringSubmatch(fieldAttrs); tm != nil && strings.EqualFold(tm[1], "email") {
				value = "test@aperture.local"
			}
			if vm := fieldValueAttrPattern.FindStringSubmatch(fieldAttrs); vm != nil && vm[1] != "" {
				value = vm[1]
			}
			defaults.Set(name, value)
			fieldNames = append(fieldNames, name)
		}

		for _, name := range fieldNames {
			out = append(out, injectionPoint{Kind: kindForm, PageURL: pageURL.String(), URL: action.String(), Method: method, Param: name, Defaults: defaults})
		}
	}
	return out
}
