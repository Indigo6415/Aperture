// Package techfp fingerprints the web server/framework/CMS stack behind an
// HTTP response -- headers, body markup, and script tags -- similar in
// spirit to Wappalyzer, but a small hand-curated signature set rather than
// a bundled third-party database. It runs entirely on data recon/http.go
// already fetched (no extra requests).
package techfp

import "regexp"

// Category buckets a Detection for grouping in the UI.
type Category string

const (
	CategoryWebServer Category = "web-server"
	CategoryLanguage  Category = "language"
	CategoryFramework Category = "js-framework"
	CategoryCMS       Category = "cms"
	CategoryCDN       Category = "cdn-proxy"
)

// Detection is one identified technology, with Version left empty when a
// signature matched but no version could be extracted from the response.
type Detection struct {
	Name     string   `json:"name"`
	Category Category `json:"category"`
	Version  string   `json:"version,omitempty"`
}

// pattern is one way to recognize (and optionally version) a technology.
// Exactly one of Header/re should be set. When re has a capture group, its
// first submatch is used as the version.
type pattern struct {
	header string // header name to match re against; "" means match the HTML body instead
	re     *regexp.Regexp
}

// signature is one technology's full set of detection patterns -- any one
// matching is enough to report the technology; the version comes from
// whichever pattern matched first among those with a capture group.
type signature struct {
	name     string
	category Category
	patterns []pattern
}

// verRe builds a header/body pattern whose first capture group is the
// version, scoped with (?i) since header casing/vendor capitalization
// varies across servers.
func verRe(expr string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + expr) }

// signatures is intentionally small and curated (not a scraped third-party
// database) -- covers the products explicitly asked for (Apache, nginx,
// Google's frontend, Vue.js) plus enough common others to be broadly
// useful. Extend this list rather than reaching for an external db.
var signatures = []signature{
	{name: "Apache httpd", category: CategoryWebServer, patterns: []pattern{
		{header: "Server", re: verRe(`^Apache(?:/(\d[\w.]*))?`)},
	}},
	{name: "nginx", category: CategoryWebServer, patterns: []pattern{
		{header: "Server", re: verRe(`^nginx(?:/(\d[\w.]*))?`)},
	}},
	{name: "Microsoft-IIS", category: CategoryWebServer, patterns: []pattern{
		{header: "Server", re: verRe(`^Microsoft-IIS(?:/(\d[\w.]*))?`)},
	}},
	{name: "LiteSpeed", category: CategoryWebServer, patterns: []pattern{
		{header: "Server", re: verRe(`^LiteSpeed(?:/(\d[\w.]*))?`)},
	}},
	{name: "Caddy", category: CategoryWebServer, patterns: []pattern{
		{header: "Server", re: verRe(`^Caddy(?:/(\d[\w.]*))?`)},
	}},
	{name: "Varnish", category: CategoryWebServer, patterns: []pattern{
		{header: "Via", re: verRe(`varnish`)},
		{header: "X-Varnish", re: verRe(`.`)},
	}},
	{name: "Google Frontend", category: CategoryWebServer, patterns: []pattern{
		{header: "Server", re: verRe(`^(?:gws|Google Frontend)$`)},
	}},
	{name: "Cloudflare", category: CategoryCDN, patterns: []pattern{
		{header: "Server", re: verRe(`^cloudflare$`)},
		{header: "Cf-Ray", re: verRe(`.`)},
	}},
	{name: "PHP", category: CategoryLanguage, patterns: []pattern{
		{header: "X-Powered-By", re: verRe(`^PHP/(\d[\w.]*)`)},
	}},
	{name: "ASP.NET", category: CategoryLanguage, patterns: []pattern{
		{header: "X-Powered-By", re: verRe(`^ASP\.NET`)},
		{header: "X-AspNet-Version", re: verRe(`^(\d[\w.]*)`)},
	}},
	{name: "Express", category: CategoryLanguage, patterns: []pattern{
		{header: "X-Powered-By", re: verRe(`^Express`)},
	}},
	{name: "Vue.js", category: CategoryFramework, patterns: []pattern{
		{re: verRe(`data-v-[0-9a-f]{8}`)},
		{re: verRe(`vue(?:\.runtime)?(?:\.min)?\.js\?ver=(\d[\w.]*)`)},
		{re: verRe(`/vue@(\d[\w.]*)`)},
	}},
	{name: "React", category: CategoryFramework, patterns: []pattern{
		{re: verRe(`data-reactroot`)},
		{re: verRe(`/react@(\d[\w.]*)`)},
		{re: verRe(`react(?:-dom)?(?:\.production\.min)?\.js\?ver=(\d[\w.]*)`)},
	}},
	{name: "Angular", category: CategoryFramework, patterns: []pattern{
		{re: verRe(`\bng-version="(\d[\w.]*)"`)},
	}},
	{name: "jQuery", category: CategoryFramework, patterns: []pattern{
		{re: verRe(`jquery[.-](\d[\w.]*?)(?:\.min)?\.js`)},
	}},
	{name: "Bootstrap", category: CategoryFramework, patterns: []pattern{
		{re: verRe(`bootstrap[.-](\d[\w.]*?)(?:\.min)?\.(?:css|js)`)},
	}},
	{name: "WordPress", category: CategoryCMS, patterns: []pattern{
		{re: verRe(`<meta name="generator" content="WordPress ([\d.]+)"`)},
		{re: verRe(`/wp-content/`)},
		{re: verRe(`/wp-includes/`)},
	}},
	{name: "Drupal", category: CategoryCMS, patterns: []pattern{
		{re: verRe(`<meta name="generator" content="Drupal ([\d.]+)`)},
		{re: verRe(`/sites/default/files/`)},
	}},
	{name: "Joomla", category: CategoryCMS, patterns: []pattern{
		{re: verRe(`<meta name="generator" content="Joomla! ([\d.]+)`)},
		{re: verRe(`/media/jui/`)},
	}},
}

// Detect fingerprints headers/body against every curated signature,
// returning one Detection per technology that matched at least one
// pattern. finalURL is accepted for future host-based signatures (e.g.
// path-only CDNs) but unused today.
func Detect(headers map[string]string, body, finalURL string) []Detection {
	var out []Detection
	for _, sig := range signatures {
		version := ""
		matched := false
		for _, p := range sig.patterns {
			haystack := body
			if p.header != "" {
				v, ok := headers[p.header]
				if !ok {
					continue
				}
				haystack = v
			}
			m := p.re.FindStringSubmatch(haystack)
			if m == nil {
				continue
			}
			matched = true
			if len(m) > 1 && m[1] != "" && version == "" {
				version = m[1]
			}
		}
		if matched {
			out = append(out, Detection{Name: sig.name, Category: sig.category, Version: version})
		}
	}
	return out
}
