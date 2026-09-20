package probescan

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

// sqlErrorStrings ports injections.py's SQL_ERRORS table.
var sqlErrorStrings = map[string][]string{
	"MySQL":      {"you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "mysql_num_rows"},
	"PostgreSQL": {"pg_query", "pg_exec", "postgresql error", "unterminated quoted string"},
	"MSSQL":      {"microsoft sql server", "odbc sql server", "sqlserver", "unclosed quotation mark"},
	"Oracle":     {"ora-01756", "ora-00933", "ora-00907", "quoted string not properly terminated"},
	"SQLite":     {"sqlite3::query", "sqlite_query", "sqliteexception"},
	"Generic":    {"sql syntax", "sql error", "database error", "query failed", "syntax error"},
}

// traversalPayloads ports injections.py's TRAVERSAL_PAYLOADS table.
var traversalPayloads = []struct{ payload, indicator string }{
	{"../../../../etc/passwd", "root:x:"},
	{"../../../../etc/shadow", "root:$"},
	{"../../../../windows/win.ini", "[fonts]"},
	{"../../../../windows/system32/drivers/etc/hosts", "localhost"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:"},
	{"....//....//....//etc/passwd", "root:x:"},
}

// sstiPayloads ports injections.py's SSTI_PAYLOADS table.
var sstiPayloads = []struct{ payload, expected string }{
	{"{{123*123}}", "15129"},
	{"${123*123}", "15129"},
	{"#{123*123}", "15129"},
	{"<%= 123*123 %>", "15129"},
	{"{{123*'123'}}", "15129"},
}

var hrefPattern = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)

// paramTarget is one URL discovered with query parameters to fuzz -- either
// the target URL itself, or a linked page scraped from its homepage.
type paramTarget struct {
	url    string
	params url.Values
}

// collectParamTargets ports injections.py's _collect_parameters: the target
// URL's own query string (if any), plus up to 10 hrefs scraped from the
// homepage that carry a query string of their own.
func collectParamTargets(ctx context.Context, t *Target, c *probeClient) []paramTarget {
	var targets []paramTarget

	base, err := url.Parse(t.URL)
	if err != nil {
		return targets
	}
	if base.RawQuery != "" {
		targets = append(targets, paramTarget{url: t.URL, params: base.Query()})
	}

	r, err := c.get(ctx, t.URL, true)
	if err != nil {
		return targets
	}

	seen := 0
	for _, m := range hrefPattern.FindAllStringSubmatch(r.Text, -1) {
		if seen >= 10 {
			break
		}
		href := m[1]
		if !strings.Contains(href, "?") {
			continue
		}
		full, err := base.Parse(href)
		if err != nil || full.RawQuery == "" {
			continue
		}
		targets = append(targets, paramTarget{url: full.String(), params: full.Query()})
		seen++
	}
	return targets
}

// withParam returns rawURL with param overridden to value, leaving every
// other query parameter untouched.
func withParam(rawURL string, params url.Values, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := url.Values{}
	for k, v := range params {
		q[k] = append([]string(nil), v...)
	}
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// firstSQLError returns the first (db, errorString) pair found in body, or
// ("", "") if none matched -- one finding per parameter is enough, mirroring
// the Python check's early return.
func firstSQLError(body string) (db, errStr string) {
	for db, errs := range sqlErrorStrings {
		for _, e := range errs {
			if strings.Contains(body, e) {
				return db, e
			}
		}
	}
	return "", ""
}

func checkSQLInjection(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	var findings []Finding
	for param, values := range target.params {
		original := ""
		if len(values) > 0 {
			original = values[0]
		}
		injected := withParam(target.url, target.params, param, original+"'")
		r, err := c.get(ctx, injected, true)
		if err != nil {
			continue
		}
		if db, errStr := firstSQLError(r.textLower()); db != "" {
			findings = append(findings, Finding{
				Label:      "Possible " + db + " SQL injection via parameter '" + param + "' at " + target.url,
				URL:        target.url,
				Method:     "GET",
				StatusCode: r.StatusCode,
				Evidence:   errStr,
				Detail:     "Appended a bare `'` to the '" + param + "' parameter; the response's body then contained a " + db + " error string",
			})
		}
	}
	return findings
}

func checkPathTraversal(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	var findings []Finding
	for param := range target.params {
		for _, tp := range traversalPayloads {
			injected := withParam(target.url, target.params, param, tp.payload)
			r, err := c.get(ctx, injected, true)
			if err != nil {
				continue
			}
			if strings.Contains(r.Text, tp.indicator) {
				findings = append(findings, Finding{
					Label:      "Path traversal via parameter '" + param + "' at " + target.url,
					URL:        target.url,
					Method:     "GET",
					StatusCode: r.StatusCode,
					Evidence:   tp.indicator,
					Detail:     "Set the '" + param + "' parameter to the payload `" + tp.payload + "`; the response's body then contained the expected traversal-target content",
				})
				break
			}
		}
	}
	return findings
}

func checkSSTI(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	var findings []Finding
	for param := range target.params {
		for _, sp := range sstiPayloads {
			injected := withParam(target.url, target.params, param, sp.payload)
			r, err := c.get(ctx, injected, true)
			if err != nil {
				continue
			}
			if strings.Contains(r.Text, sp.expected) && !strings.Contains(r.Text, sp.payload) {
				findings = append(findings, Finding{
					Label:      "Possible SSTI via parameter '" + param + "' at " + target.url,
					URL:        target.url,
					Method:     "GET",
					StatusCode: r.StatusCode,
					Evidence:   sp.expected,
					Detail:     "Set the '" + param + "' parameter to the template expression `" + sp.payload + "`; the response's body reflected its evaluated result rather than the literal text -- meaning the server executed it as a template",
				})
				break
			}
		}
	}
	return findings
}

func checkPathTraversalDirect(ctx context.Context, c *probeClient, t *Target) []Finding {
	var findings []Finding
	for _, tp := range traversalPayloads {
		url := t.URL + "/" + tp.payload
		r, err := c.get(ctx, url, false)
		if err != nil || r.StatusCode != 200 {
			continue
		}
		if strings.Contains(r.Text, tp.indicator) {
			findings = append(findings, Finding{
				Label: "Path traversal in URL path at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
				Evidence: tp.indicator,
				Detail:   "Requested `/" + tp.payload + "` directly in the URL path; the response's body then contained the expected traversal-target content",
			})
		}
	}
	return findings
}

// injectionsModule ports modules/injections.py. This actively sends SQLi,
// path-traversal, and SSTI payloads against every parameter it can find --
// the same authorized-testing posture the rest of Aperture already takes
// with JWT forgery and ffuf/feroxbuster brute-forcing. The frontend surfaces
// the same "authorized testing only" disclaimer JWT Scanner shows.
var injectionsModule = moduleDef{
	id:       "injections",
	name:     "Injection & Input Handling",
	severity: "critical",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		targets := collectParamTargets(ctx, t, c)

		if len(targets) == 0 {
			return checkPathTraversalDirect(ctx, c, t)
		}

		var findings []Finding
		for _, pt := range targets {
			findings = append(findings, checkSQLInjection(ctx, c, pt)...)
			findings = append(findings, checkPathTraversal(ctx, c, pt)...)
			findings = append(findings, checkSSTI(ctx, c, pt)...)
		}
		findings = append(findings, checkPathTraversalDirect(ctx, c, t)...)
		return findings
	},
}
