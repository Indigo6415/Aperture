package xxe

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/Indigo6415/Aperture/internal/robots"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// discovered is one endpoint the run will test, and where it came from.
// evidence is set only for endpoints discovery classified as XML-capable.
type discovered struct {
	target   *url.URL
	source   string
	evidence string
}

// crawlItem is one page waiting in the discovery crawl's queue, with how many
// same-origin hops it is from the seed.
type crawlItem struct {
	url   string
	depth int
}

// crawlDefaultMaxPages/crawlMaxPagesCap mirror the other scanners' crawlers, so
// a large site can't make discovery run away.
const (
	crawlDefaultMaxPages = 25
	crawlMaxPagesCap     = 50
)

// maxScriptsFetched caps how many script files discovery downloads to read
// for endpoint paths. Inline scripts are read regardless, since they cost
// nothing extra.
const maxScriptsFetched = 10

// commonXMLPaths are paths that often take XML: XML-RPC, SOAP, WSDL-style
// services, and generic import endpoints. They are tried at the origin root.
// Paths that would only make sense as GET-only pages are left out, since every
// probe here is a POST.
var commonXMLPaths = []string{
	"/xmlrpc.php", "/xmlrpc", "/soap", "/soap/", "/ws", "/wsdl", "/services",
	"/webservices", "/rpc", "/api/rpc", "/xml", "/api/xml", "/api/soap",
	"/api/import", "/import", "/axis2/services", "/api/v1/xml",
}

var (
	discoverAnchorPattern = regexp.MustCompile(`(?is)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	discoverFormPattern   = regexp.MustCompile(`(?is)<form([^>]*)>`)
	discoverActionPattern = regexp.MustCompile(`(?is)action\s*=\s*["']([^"']*)["']`)
	discoverScriptSrc     = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	discoverInlineScript  = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	// discoverURLLiteral matches a root-relative path written as a string
	// literal in script, e.g. fetch("/api/import"). Only those whose path
	// suggests XML are kept (see looksXMLish).
	discoverURLLiteral = regexp.MustCompile(`["'](/[A-Za-z0-9_\-./?=&%]{1,200})["']`)
	discoverXMLishRe   = regexp.MustCompile(`(?i)xml|soap|wsdl|rpc|import|upload|feed|service|api|/ws`)
)

// XML probes sent to each candidate to tell whether it parses XML. A
// well-formed document shows whether it answers with XML. A malformed one shows
// whether a parser complains about it. The plain-text control shows whether
// that complaint is just part of a generic error page.
const (
	probeWellFormed = `<?xml version="1.0"?><aperture-probe>1</aperture-probe>`
	probeMalformed  = `<aperture-probe`
	probePlain      = "aperture-probe"
)

// parserErrorRe matches the wording the common XML parsers use for a document
// they reject: libxml2 ("parser error : ..."), Java SAX ("must be terminated
// by the matching end-tag"), .NET ("'>' expected"), PHP and Python expat
// ("not well-formed"). It is only ever checked against a response to a
// malformed probe, with the plain-text control as the baseline.
var parserErrorRe = regexp.MustCompile(`(?i)xml ?parse|xmlparse|xmlsyntax|saxparse|parser error|couldn't find end|not well-formed|well-formed|premature end of|unexpected end of|must be terminated|end-tag|tag mismatch|expected '>'|'>' expected|root level is invalid|xmlexception|xml syntax|syntax error|lxml|expat|org\.xml\.sax|system\.xml|javax\.xml|doctype is not allowed|xml declaration|xml document structures`)

// discoverEndpoints crawls seed's own origin the same breadth-first way as
// the other scanners' crawlers, collects every endpoint it can find (form
// actions, paths named in script, common XML paths), and keeps only those that
// answer XML. The seed itself is always a candidate.
func discoverEndpoints(ctx context.Context, client *http.Client, sem chan struct{}, seed *url.URL, headers map[string]string, contentType, method string, recursionDepth, maxPages int, rep scanprogress.Reporter) []discovered {
	if maxPages <= 0 {
		maxPages = crawlDefaultMaxPages
	}
	if maxPages > crawlMaxPagesCap {
		maxPages = crawlMaxPagesCap
	}

	policy := robots.Load(ctx, client, seed, headers)
	candidates := []discovered{{target: seed, source: "seed"}}
	seen := map[string]bool{seed.String(): true}
	add := func(u *url.URL, source string) {
		// Only same-origin endpoints are probed. Following a form or a script
		// to a third-party host would send XML there.
		if u == nil || !strings.EqualFold(u.Host, seed.Host) || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		key := u.String()
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, discovered{target: u, source: source})
	}

	// scriptsLeft bounds how many script files this crawl downloads.
	scriptsLeft := maxScriptsFetched
	visited := map[string]bool{}
	queue := []crawlItem{{seed.String(), 0}}

	// Every page the crawl fetches is read for links, forms and script
	// references. The queue is bounded by depth and by how many pages are
	// visited.
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

		page, err := fetchBody(ctx, client, item.url, headers)
		if err != nil {
			continue
		}
		pageURL, err := url.Parse(item.url)
		if err != nil {
			continue
		}

		// A form's action is a candidate even though its fields are never
		// used. The probe sends its own XML body, so only the endpoint matters.
		for _, m := range discoverFormPattern.FindAllStringSubmatch(page, -1) {
			action := ""
			if am := discoverActionPattern.FindStringSubmatch(m[1]); am != nil {
				action = am[1]
			}
			if resolved, err := pageURL.Parse(action); err == nil {
				add(resolved, "form action")
			}
		}

		// Paths written as string literals in script are the usual way an
		// XML endpoint is called from JavaScript. Inline scripts are read here,
		// and external ones are fetched up to the cap below.
		for _, m := range discoverInlineScript.FindAllStringSubmatch(page, -1) {
			addScriptPaths(pageURL, m[1], add)
		}
		for _, m := range discoverScriptSrc.FindAllStringSubmatch(page, -1) {
			if scriptsLeft <= 0 {
				break
			}
			src, err := pageURL.Parse(m[1])
			if err != nil || !strings.EqualFold(src.Host, seed.Host) {
				continue
			}
			scriptsLeft--
			if js, err := fetchBody(ctx, client, src.String(), headers); err == nil {
				addScriptPaths(pageURL, js, add)
			}
		}

		// Links only feed the crawl, not the candidate list, since a GET link
		// is not an XML endpoint. A page is queued only when depth allows, its
		// host matches, and robots.txt permits it.
		for _, m := range discoverAnchorPattern.FindAllStringSubmatch(page, -1) {
			resolved, err := pageURL.Parse(m[1])
			if err != nil || !strings.EqualFold(resolved.Host, seed.Host) {
				continue
			}
			resolved.Fragment = ""
			if item.depth < recursionDepth && !visited[resolved.String()] && policy.Allowed(resolved) {
				queue = append(queue, crawlItem{resolved.String(), item.depth + 1})
			}
		}
	}

	for _, p := range commonXMLPaths {
		if u, err := seed.Parse(p); err == nil {
			// Common paths sit at the origin root, not beside the seed page.
			u.Path = p
			u.RawQuery = ""
			add(u, "common path")
		}
	}

	// Each candidate is classified concurrently. The results are written back
	// by index, so the output keeps the discovery order.
	type verdict struct {
		reason string
		ok     bool
	}
	verdicts := make([]verdict, len(candidates))
	var wg sync.WaitGroup
	for i, c := range candidates {
		if !policy.Allowed(c.target) {
			continue
		}
		wg.Add(1)
		go func(i int, target *url.URL) {
			defer wg.Done()
			reason, ok := classify(ctx, sem, client, method, target, contentType, headers)
			verdicts[i] = verdict{reason, ok}
		}(i, c.target)
	}
	wg.Wait()

	rep.Phase("Checking which endpoints answer XML")
	var out []discovered
	for i, c := range candidates {
		if verdicts[i].ok {
			c.evidence = verdicts[i].reason
			out = append(out, c)
		}
	}
	return out
}

// addScriptPaths scans script text for root-relative string literals whose
// path suggests XML and passes each resolved URL to add.
func addScriptPaths(base *url.URL, script string, add func(*url.URL, string)) {
	for _, m := range discoverURLLiteral.FindAllStringSubmatch(script, -1) {
		if !discoverXMLishRe.MatchString(m[1]) {
			continue
		}
		if resolved, err := base.Parse(m[1]); err == nil {
			add(resolved, "script reference")
		}
	}
}

// classify reports whether target answers XML, and if so why. An endpoint
// counts when it returns an XML document for a well-formed request, or when it
// rejects a malformed one with a parser error that the plain-text control
// doesn't produce. Both checks use the method and content type the run will
// use, so a yes here means the real run will get XML back too.
func classify(ctx context.Context, sem chan struct{}, client *http.Client, method string, target *url.URL, contentType string, headers map[string]string) (string, bool) {
	well := send(ctx, sem, client, method, target, contentType, probeWellFormed, headers)
	if well.Err == nil && answersXML(well) {
		return "answers a well-formed XML request with an XML document", true
	}

	malformed := send(ctx, sem, client, method, target, contentType, probeMalformed, headers)
	if malformed.Err == nil && parserErrorRe.MatchString(malformed.Body) {
		// The control uses a plain-text body, so any parser error it shows is
		// unrelated to XML and the malformed-XML error doesn't count.
		plain := send(ctx, sem, client, method, target, "text/plain", probePlain, headers)
		if plain.Err != nil || !parserErrorRe.MatchString(plain.Body) {
			return "rejects malformed XML with a parser error", true
		}
	}
	return "", false
}

// answersXML reports whether a response is XML rather than HTML or plain
// text. An error status doesn't count, since an error page proves nothing
// about how the body is parsed.
func answersXML(r *sendResult) bool {
	if r.StatusCode >= 400 {
		return false
	}
	ct := strings.ToLower(r.ContentType)
	if strings.Contains(ct, "html") {
		return false
	}
	trimmed := strings.TrimSpace(r.Body)
	if strings.HasPrefix(trimmed, "<?xml") {
		return true
	}
	if strings.Contains(ct, "xml") {
		return true
	}
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(trimmed, "<") && !strings.HasPrefix(lower, "<!doctype html") && !strings.HasPrefix(lower, "<html")
}

// fetchBody GETs a page or script for discovery and returns its body. Any
// error or non-2xx status returns an error, so a broken page is skipped
// rather than parsed.
func fetchBody(ctx context.Context, client *http.Client, rawURL string, headers map[string]string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Aperture-XXE")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
		return "", io.ErrUnexpectedEOF
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
