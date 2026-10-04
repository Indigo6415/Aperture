package probescan

import (
	"context"
	"regexp"
	"strings"
)

// wordpressChecks ports wordpress.py's CHECKS table. Config backups and the
// debug log are not listed here: sensitive_files judges those files by their
// content, so keeping them here as well would report one file twice.
var wordpressChecks = []pathCheck{
	{"/wp-json/wp/v2/users", "WordPress REST API user enumeration", validJSONArrayHasKey("slug")},
	{"/?rest_route=/wp/v2/users", "WordPress REST API user enumeration", validJSONArrayHasKey("slug")},
	{"/wp-content/uploads/", "WordPress uploads directory listing", isDirectoryListing},
	{"/wp-content/plugins/", "WordPress plugins directory listing", isDirectoryListing},
	{"/wp-content/themes/", "WordPress themes directory listing", isDirectoryListing},
	{"/wp-includes/", "WordPress includes directory listing", isDirectoryListing},
	{"/wp-content/backup-db/", "WordPress database backup directory listing", isDirectoryListing},
	{"/wp-content/backups/", "WordPress backups directory listing", isDirectoryListing},
	{"/xmlrpc.php", "WordPress XML-RPC enabled", containsAny("xml-rpc server accepts post requests only")},
	{"/readme.html", "WordPress readme exposes version", containsAll("wordpress", "readme")},
	{"/license.txt", "WordPress license file", containsAll("wordpress", "gnu general public license")},
	{"/wp-admin/install.php", "WordPress install page accessible", containsAll("wordpress", "installation")},
	{"/wp-admin/upgrade.php", "WordPress upgrade page accessible", containsAll("wordpress", "upgrade")},
}

// wpMarker matches the markup that only a WordPress front end emits: its
// content and include directories, its REST API link, or its generator tag.
var wpMarker = regexp.MustCompile(`(?i)wp-content/|wp-includes/|wp-json|<meta name="generator" content="wordpress`)

// authorSlug captures the author slug from a redirected author archive URL.
var authorSlug = regexp.MustCompile(`/author/([^/?#]+)`)

// isWordPress reports whether the homepage carries a WordPress marker. The bare
// word "wordpress" is not used: blogs and articles mention it constantly.
func isWordPress(ctx context.Context, t *Target, c *probeClient) bool {
	r, err := c.get(ctx, t.URL, true)
	if err != nil {
		return false
	}
	return wpMarker.MatchString(r.Text) ||
		strings.Contains(strings.ToLower(r.Header.Get("X-Powered-By")), "wordpress")
}

// wordpressModule ports modules/wordpress.py: skips entirely unless the
// target's homepage looks like WordPress. Every path check runs through the
// catch-all gate, so a host that answers each path with the same page reports
// nothing.
var wordpressModule = moduleDef{
	id:       "wordpress",
	name:     "WordPress",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		if !isWordPress(ctx, t, c) {
			return nil
		}

		findings := runPathChecks(ctx, c, t.URL, wordpressChecks, false, "at")

		// Author enumeration: /?author=1 redirects to /author/<slug>/ on a
		// WordPress that leaks its usernames. The redirect is only visible when
		// the request follows it, so this check must follow.
		authorURL := t.URL + "/?author=1"
		if r, err := c.get(ctx, authorURL, true); err == nil && r.StatusCode == 200 && !c.isCatchAll(r) {
			if m := authorSlug.FindStringSubmatch(r.FinalURL); m != nil {
				findings = append(findings, Finding{
					Label: "WordPress author enumeration at " + authorURL, URL: authorURL, Method: "GET", StatusCode: r.StatusCode,
					Detail: "Requesting `/?author=1` redirected to " + r.FinalURL + ", which names an author's login slug (\"" + m[1] + "\")",
				})
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
