package probescan

import (
	"context"
	"strings"
)

// wordpressChecks ports wordpress.py's CHECKS table.
var wordpressChecks = []pathCheck{
	{"/wp-json/wp/v2/users", "WordPress REST API user enumeration", containsAll("[", "slug")},
	{"/?author=1", "WordPress author enumeration", nil}, // special-cased below (checks the final URL, not the body)
	{"/wp-content/debug.log", "WordPress debug log", containsAny("php", "error", "warning")},
	{"/wp-content/uploads/", "WordPress uploads directory listing", containsAny("index of")},
	{"/wp-config.php~", "WordPress config backup", containsCase("DB_")},
	{"/wp-config.php.bak", "WordPress config backup", containsCase("DB_")},
	{"/wp-config.php.old", "WordPress config backup", containsCase("DB_")},
	{"/wp-config.php.save", "WordPress config backup", containsCase("DB_")},
	{"/wp-config.bak", "WordPress config backup", containsCase("DB_")},
	{"/xmlrpc.php", "WordPress XML-RPC enabled", containsAll("xml", "rpc")},
	{"/readme.html", "WordPress readme exposes version", containsAny("wordpress")},
	{"/license.txt", "WordPress license file", containsAny("wordpress")},
	{"/wp-admin/install.php", "WordPress install page accessible", containsAny("installation", "wordpress")},
	{"/wp-admin/upgrade.php", "WordPress upgrade page accessible", containsAny("wordpress")},
	{"/wp-content/plugins/", "WordPress plugins directory listing", containsAny("index of")},
	{"/wp-content/themes/", "WordPress themes directory listing", containsAny("index of")},
}

func isWordPress(ctx context.Context, t *Target, c *probeClient) bool {
	r, err := c.get(ctx, t.URL, true)
	if err != nil {
		return false
	}
	body := r.textLower()
	return strings.Contains(body, "wp-content") || strings.Contains(body, "wp-json") ||
		strings.Contains(body, "wordpress") || strings.Contains(strings.ToLower(r.Header.Get("X-Powered-By")), "wordpress")
}

// wordpressModule ports modules/wordpress.py: skips entirely unless the
// target's homepage looks like WordPress.
var wordpressModule = moduleDef{
	id:       "wordpress",
	name:     "WordPress",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		if !isWordPress(ctx, t, c) {
			return nil
		}

		var findings []Finding
		for _, chk := range wordpressChecks {
			url := t.URL + chk.path
			r, err := c.get(ctx, url, false)
			if err != nil || r.StatusCode != 200 {
				continue
			}
			if chk.path == "/?author=1" {
				// Author enumeration is detected by WordPress redirecting
				// the request to /?author=1 landing on an author-slug URL,
				// not by anything in the body -- mirrors the Python
				// check's `"author" in r.url.lower()`.
				if strings.Contains(strings.ToLower(r.FinalURL), "author") {
					findings = append(findings, Finding{
						Label: chk.label + " at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
						Detail: "Requesting `/?author=1` redirected to " + r.FinalURL + ", which names an author's login slug",
					})
				}
				continue
			}
			if chk.valid(r) {
				findings = append(findings, Finding{Label: chk.label + " at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode})
			}
		}

		// WP_DEBUG leaking PHP notices/warnings/fatals into the page.
		if r, err := c.get(ctx, t.URL, true); err == nil {
			for _, tag := range []string{"<b>Notice</b>", "<b>Warning</b>", "<b>Fatal error</b>"} {
				if strings.Contains(r.Text, tag) {
					findings = append(findings, Finding{
						Label: "WP_DEBUG appears enabled -- PHP errors exposed in page source at " + t.URL, URL: t.URL,
						Method: "GET", StatusCode: r.StatusCode, Evidence: tag,
						Detail: "Homepage response body contains a raw PHP error tag instead of a production-safe page",
					})
					break
				}
			}
		}

		// XML-RPC pingback -- can be abused for DDoS amplification.
		pingbackPayload := []byte(`<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>`)
		xmlrpcURL := t.URL + "/xmlrpc.php"
		if r, err := c.post(ctx, xmlrpcURL, "text/xml", pingbackPayload); err == nil && r.StatusCode == 200 && containsCase("pingback.ping")(r) {
			findings = append(findings, Finding{
				Label:      "XML-RPC pingback enabled at " + xmlrpcURL,
				URL:        xmlrpcURL,
				Method:     "POST",
				StatusCode: r.StatusCode,
				Detail:     "POSTed a system.listMethods XML-RPC call; the response advertised pingback.ping, a method abusable for DDoS amplification against third-party sites",
			})
		}

		return findings
	},
}
