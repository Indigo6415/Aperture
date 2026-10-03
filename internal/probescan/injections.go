package probescan

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/netgov"
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

// firstSQLError returns the (db, errorString) pair found in body, or ("", "")
// if none matched. Databases are checked in sorted order so the same body
// always reports the same engine, even when two signatures match.
func firstSQLError(body string) (db, errStr string) {
	names := make([]string, 0, len(sqlErrorStrings))
	for name := range sqlErrorStrings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, e := range sqlErrorStrings[name] {
			if strings.Contains(body, e) {
				return name, e
			}
		}
	}
	return "", ""
}

// baselineFor fetches the target with its original parameter values. Every
// injection check compares against this, so text that the page already shows
// (a docs page quoting an SQL error, a sample /etc/passwd excerpt) is never
// reported as a reflection of the payload.
func baselineFor(ctx context.Context, c *probeClient, target paramTarget) *httpResult {
	r, err := c.get(ctx, target.url, true)
	if err != nil {
		return nil
	}
	return r
}

// checkSQLInjection appends a bare quote to each parameter and looks for a
// database error string. A page that already shows such an error on its
// original request is skipped for that whole target, since it says nothing
// about the injected value.
func checkSQLInjection(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	baseline := baselineFor(ctx, c, target)
	if baseline != nil {
		if db, _ := firstSQLError(baseline.textLower()); db != "" {
			return nil
		}
	}
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
				Detail:     "Appended a bare `'` to the '" + param + "' parameter; the response's body then contained a " + db + " error string that the original request did not contain",
				Confidence: ConfidenceLikely,
			})
		}
	}
	return findings
}

// timeDelaySeconds is the sleep each time-based payload requests. It stays
// below probeTimeout so a real delay completes instead of timing out.
const timeDelaySeconds = 3

// timeSQLPayloads are sleep-style payloads for the common engines. Each is
// appended to the parameter's original value.
var timeSQLPayloads = []struct{ engine, suffix string }{
	{"MySQL", fmt.Sprintf("' AND SLEEP(%d)-- -", timeDelaySeconds)},
	{"PostgreSQL", fmt.Sprintf("'||pg_sleep(%d)-- -", timeDelaySeconds)},
	{"MSSQL", fmt.Sprintf("';WAITFOR DELAY '0:0:%d'-- -", timeDelaySeconds)},
}

// checkTimeBasedSQLi detects blind SQL injection by timing. A payload counts
// only when it is slower than the original request by most of the requested
// delay, and the same result repeats on a second send. Timing is unreliable
// while the host is throttled, so the check is skipped whenever the governor
// has tagged responses as suspect.
func checkTimeBasedSQLi(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	var findings []Finding
	for param, values := range target.params {
		original := ""
		if len(values) > 0 {
			original = values[0]
		}
		baselineStart := time.Now()
		base, err := c.get(ctx, target.url, true)
		baseElapsed := time.Since(baselineStart)
		if err != nil || suspectResponse(base) {
			continue
		}
		for _, p := range timeSQLPayloads {
			injected := withParam(target.url, target.params, param, original+p.suffix)
			hits := 0
			for attempt := 0; attempt < 2; attempt++ {
				start := time.Now()
				r, err := c.get(ctx, injected, true)
				elapsed := time.Since(start)
				if err != nil || suspectResponse(r) {
					break
				}
				if elapsed-baseElapsed >= (timeDelaySeconds-1)*time.Second {
					hits++
				}
			}
			if hits == 2 {
				findings = append(findings, Finding{
					Label:      "Possible " + p.engine + " time-based SQL injection via parameter '" + param + "' at " + target.url,
					URL:        target.url,
					Method:     "GET",
					Evidence:   fmt.Sprintf("payload delayed the response by about %ds on two consecutive sends", timeDelaySeconds),
					Detail:     "Appended a " + p.engine + " sleep payload to '" + param + "'. The response was consistently about " + fmt.Sprint(timeDelaySeconds) + " seconds slower than the original request, twice in a row. Network jitter does not usually repeat like that; confirm manually before treating it as exploitable.",
					Confidence: ConfidenceLikely,
				})
				break
			}
		}
	}
	return findings
}

// suspectResponse reports whether the governor tagged a response as taken
// during a drift window, in which case its timing and content are unreliable.
func suspectResponse(r *httpResult) bool {
	return r != nil && r.Header.Get(netgov.SuspectHeader) != ""
}

// checkPathTraversal sends traversal payloads through each parameter. A marker
// already present in the original response is not evidence of traversal.
func checkPathTraversal(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	baseline := baselineFor(ctx, c, target)
	var findings []Finding
	for param := range target.params {
		for _, tp := range traversalPayloads {
			if baseline != nil && strings.Contains(baseline.Text, tp.indicator) {
				break
			}
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
					Detail:     "Set the '" + param + "' parameter to the payload `" + tp.payload + "`; the response's body then contained the expected traversal-target content, which the original response did not",
					Confidence: ConfidenceConfirmed,
				})
				break
			}
		}
	}
	return findings
}

// checkSSTI sends template expressions through each parameter and flags a
// response that shows the evaluated result. A result already present in the
// original response (a page that happens to print the same number) is skipped.
func checkSSTI(ctx context.Context, c *probeClient, target paramTarget) []Finding {
	baseline := baselineFor(ctx, c, target)
	var findings []Finding
	for param := range target.params {
		for _, sp := range sstiPayloads {
			if baseline != nil && strings.Contains(baseline.Text, sp.expected) {
				break
			}
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
					Confidence: ConfidenceLikely,
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
			findings = append(findings, checkTimeBasedSQLi(ctx, c, pt)...)
			findings = append(findings, checkPathTraversal(ctx, c, pt)...)
			findings = append(findings, checkSSTI(ctx, c, pt)...)
		}
		findings = append(findings, checkPathTraversalDirect(ctx, c, t)...)
		return findings
	},
}
