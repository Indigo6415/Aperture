package probescan

import (
	"context"
	"regexp"
	"strings"
)

// adminPanel is one admin interface path. signatures are lowercase phrases
// that name the product on its login or landing page; a 200 that contains one
// is a product match. An empty signatures list means the path is generic and
// is only confirmed by a password field.
type adminPanel struct {
	path       string
	label      string
	signatures []string
}

// adminPanels ports admin_panels.py's PANELS table and adds product panels
// that are common on exposed hosts. The generic entries keep their original
// labels, except that a path that is not really a WordPress login now says so.
var adminPanels = []adminPanel{
	// --- Generic admin paths ---
	{path: "/admin", label: "Generic admin panel"},
	{path: "/admin/", label: "Generic admin panel"},
	{path: "/administrator", label: "Generic administrator panel"},
	{path: "/administrator/", label: "Generic administrator panel"},
	{path: "/adminpanel", label: "Generic admin panel"},
	{path: "/admin.php", label: "Generic admin panel"},
	{path: "/admincp", label: "Generic admin control panel"},
	{path: "/admin_area/", label: "Generic admin area"},
	{path: "/controlpanel", label: "Generic control panel"},
	{path: "/manage/", label: "Generic management panel"},
	{path: "/admin/login", label: "Generic admin login"},
	{path: "/admin/dashboard", label: "Generic admin dashboard"},
	{path: "/login.php", label: "Generic login page"},
	{path: "/log-in", label: "Generic login page"},

	// --- CMS panels ---
	{path: "/wp-admin", label: "WordPress admin panel", signatures: []string{"wp-submit", "wp-login"}},
	{path: "/wp-admin/", label: "WordPress admin panel", signatures: []string{"wp-submit", "wp-login"}},
	{path: "/wp-login.php", label: "WordPress login page", signatures: []string{"wp-submit", "wp-login"}},
	{path: "/administrator/index.php", label: "Joomla admin panel", signatures: []string{"joomla"}},
	{path: "/user/login", label: "Drupal login page", signatures: []string{"drupal"}},
	{path: "/admin/config", label: "Drupal config panel", signatures: []string{"drupal"}},

	// --- Framework and PHP tools ---
	{path: "/nova", label: "Laravel Nova admin panel", signatures: []string{"laravel nova"}},
	{path: "/horizon", label: "Laravel Horizon dashboard", signatures: []string{"laravel horizon"}},
	{path: "/telescope", label: "Laravel Telescope debugger", signatures: []string{"laravel telescope"}},
	{path: "/django-admin", label: "Django admin panel", signatures: []string{"django site admin", "django administration"}},
	{path: "/django-admin/", label: "Django admin panel", signatures: []string{"django site admin", "django administration"}},
	{path: "/phpmyadmin", label: "phpMyAdmin panel", signatures: []string{"phpmyadmin"}},
	{path: "/phpmyadmin/", label: "phpMyAdmin panel", signatures: []string{"phpmyadmin"}},
	{path: "/pma", label: "phpMyAdmin panel", signatures: []string{"phpmyadmin"}},
	{path: "/pma/", label: "phpMyAdmin panel", signatures: []string{"phpmyadmin"}},
	{path: "/mysql", label: "MySQL admin panel"},
	{path: "/mysqladmin", label: "MySQL admin panel"},
	{path: "/adminer.php", label: "Adminer database manager", signatures: []string{"adminer"}},
	{path: "/adminer/", label: "Adminer database manager", signatures: []string{"adminer"}},
	{path: "/roundcube/", label: "Roundcube webmail", signatures: []string{"roundcube"}},
	{path: "/webmail", label: "Webmail panel"},

	// --- Application servers and dashboards ---
	{path: "/manager/html", label: "Tomcat manager panel", signatures: []string{"tomcat web application manager"}},
	{path: "/host-manager/html", label: "Tomcat host manager panel", signatures: []string{"tomcat virtual host manager"}},
	{path: "/jenkins", label: "Jenkins dashboard", signatures: []string{"jenkins"}},
	{path: "/jenkins/login", label: "Jenkins login", signatures: []string{"jenkins"}},
	{path: "/grafana", label: "Grafana dashboard", signatures: []string{"grafana"}},
	{path: "/grafana/login", label: "Grafana login", signatures: []string{"grafana"}},
	{path: "/kibana", label: "Kibana dashboard", signatures: []string{"kibana"}},
	{path: "/app/kibana", label: "Kibana dashboard", signatures: []string{"kibana"}},
	{path: "/portainer", label: "Portainer container manager", signatures: []string{"portainer"}},
	{path: "/solr/", label: "Apache Solr admin", signatures: []string{"solr admin"}},
	{path: "/rundeck", label: "Rundeck console", signatures: []string{"rundeck"}},
	{path: "/nexus/", label: "Sonatype Nexus repository", signatures: []string{"nexus repository"}},
	{path: "/artifactory/", label: "JFrog Artifactory", signatures: []string{"artifactory"}},
	{path: "/airflow/login/", label: "Apache Airflow login", signatures: []string{"airflow"}},
	{path: "/superset/login/", label: "Apache Superset login", signatures: []string{"superset"}},
	{path: "/prometheus/", label: "Prometheus UI", signatures: []string{"prometheus time series"}},
	{path: "/minio/login", label: "MinIO console login", signatures: []string{"minio"}},
	{path: "/consul/ui/", label: "HashiCorp Consul UI", signatures: []string{"consul"}},
	{path: "/cockpit/", label: "Cockpit server console", signatures: []string{"cockpit"}},
	{path: "/webmin/", label: "Webmin panel", signatures: []string{"webmin"}},
	{path: "/gitlab/users/sign_in", label: "GitLab sign-in", signatures: []string{"gitlab"}},
	{path: "/users/sign_in", label: "GitLab sign-in", signatures: []string{"gitlab"}},
	{path: "/owa/", label: "Outlook Web App sign-in", signatures: []string{"outlook"}},
	{path: "/ecp/", label: "Exchange admin center", signatures: []string{"exchange admin center"}},
	{path: "/rdweb/", label: "Remote Desktop Web Access", signatures: []string{"rd web access"}},

	// --- Hosting panels ---
	{path: "/cpanel", label: "cPanel hosting panel", signatures: []string{"cpanel"}},
	{path: "/plesk", label: "Plesk hosting panel", signatures: []string{"plesk"}},
}

// passwordInput matches an HTML password field, the one element every login
// form has and most other pages do not.
var passwordInput = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)

// hasLoginForm reports whether the body carries a password input.
func hasLoginForm(r *httpResult) bool {
	return passwordInput.MatchString(r.Text)
}

// matchedSignature returns the first of the panel's product signatures that
// appears in the body, or "" when none does.
func matchedSignature(p adminPanel, r *httpResult) string {
	body := r.textLower()
	for _, sig := range p.signatures {
		if strings.Contains(body, sig) {
			return sig
		}
	}
	return ""
}

// adminPanelsModule ports modules/admin_panels.py. Each path is judged against
// the host's catch-all baseline, so a host that answers every path with the
// same 200 or 403 page reports nothing. A 200 is confirmed as a panel by a
// product signature or a password field. A bare 200 is only a lead, and a 401
// or 403 shows the path exists even though access is refused.
var adminPanelsModule = moduleDef{
	id:       "admin_panels",
	name:     "Admin panels",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		type result struct {
			idx     int
			finding *Finding
		}
		out := make(chan result, len(adminPanels))
		for i, p := range adminPanels {
			go func(i int, p adminPanel) {
				url := t.URL + p.path
				r, err := c.get(ctx, url, true)
				// A network error or a page that matches the catch-all carries no signal.
				if err != nil || c.isCatchAll(r) {
					out <- result{idx: i}
					return
				}
				out <- result{idx: i, finding: adminPanelFinding(p, url, r)}
			}(i, p)
		}
		found := make([]*Finding, len(adminPanels))
		for range adminPanels {
			r := <-out
			found[r.idx] = r.finding
		}
		var findings []Finding
		for _, f := range found {
			if f != nil {
				findings = append(findings, *f)
			}
		}
		return findings
	},
}

// adminPanelFinding grades one response to an admin path. It returns nil for
// responses that show nothing about the panel: anything other than 200, 401,
// or 403.
func adminPanelFinding(p adminPanel, url string, r *httpResult) *Finding {
	switch {
	case r.StatusCode == 200:
		// A product signature identifies the panel by name, which is strong
		// evidence even without a login form.
		if sig := matchedSignature(p, r); sig != "" {
			return &Finding{
				Label: p.label + " accessible at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
				Detail:     "Response names the product (matched \"" + sig + "\")",
				Confidence: ConfidenceLikely,
			}
		}
		if hasLoginForm(r) {
			return &Finding{
				Label: p.label + " accessible at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
				Detail:     "Response contains a password input, so this is a sign-in form",
				Confidence: ConfidenceLikely,
			}
		}
		return &Finding{
			Label: p.label + " returned 200 at " + url + " (no login form detected)", URL: url, Method: "GET", StatusCode: r.StatusCode,
			Detail:     "The path answers with 200 and does not look like the host's catch-all page, but no login form or product name was found",
			Confidence: ConfidenceHeuristic,
		}
	case r.StatusCode == 401:
		// 401 means the server is guarding the path, which confirms it exists.
		return &Finding{
			Label: p.label + " requires authentication at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
			Detail:     "A 401 response confirms the path exists and asks for credentials",
			Confidence: ConfidenceHeuristic,
		}
	case r.StatusCode == 403:
		return &Finding{
			Label: p.label + " exists but is forbidden at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
			Detail:     "A 403 response still confirms the path exists, unlike a 404",
			Confidence: ConfidenceHeuristic,
		}
	}
	return nil
}
