package probescan

import "context"

// adminPanelPaths ports admin_panels.py's PANELS table.
var adminPanelPaths = []struct{ path, label string }{
	{"/admin", "Generic admin panel"},
	{"/admin/", "Generic admin panel"},
	{"/administrator", "Generic administrator panel"},
	{"/administrator/", "Generic administrator panel"},
	{"/adminpanel", "Generic admin panel"},
	{"/admin/login", "Generic admin login"},
	{"/admin/dashboard", "Generic admin dashboard"},
	{"/wp-admin", "WordPress admin panel"},
	{"/wp-admin/", "WordPress admin panel"},
	{"/wp-login.php", "WordPress login page"},
	{"/log-in", "WordPress login page"},
	{"/administrator/index.php", "Joomla admin panel"},
	{"/user/login", "Drupal login page"},
	{"/admin/config", "Drupal config panel"},
	{"/nova", "Laravel Nova admin panel"},
	{"/horizon", "Laravel Horizon dashboard"},
	{"/telescope", "Laravel Telescope debugger"},
	{"/django-admin", "Django admin panel"},
	{"/django-admin/", "Django admin panel"},
	{"/phpmyadmin", "phpMyAdmin panel"},
	{"/phpmyadmin/", "phpMyAdmin panel"},
	{"/pma", "phpMyAdmin panel"},
	{"/pma/", "phpMyAdmin panel"},
	{"/mysql", "MySQL admin panel"},
	{"/mysqladmin", "MySQL admin panel"},
	{"/manager/html", "Tomcat manager panel"},
	{"/host-manager/html", "Tomcat host manager panel"},
	{"/jenkins", "Jenkins dashboard"},
	{"/jenkins/login", "Jenkins login"},
	{"/grafana", "Grafana dashboard"},
	{"/grafana/login", "Grafana login"},
	{"/kibana", "Kibana dashboard"},
	{"/app/kibana", "Kibana dashboard"},
	{"/portainer", "Portainer container manager"},
	{"/adminer.php", "Adminer database manager"},
	{"/cpanel", "cPanel hosting panel"},
	{"/plesk", "Plesk hosting panel"},
	{"/webmail", "Webmail panel"},
}

func looksLikeLoginPage(r *httpResult) bool {
	return containsAny("login", "log in", "sign in", "username", "password", "admin", "dashboard", "panel", "authenticate")(r)
}

// adminPanelsModule ports modules/admin_panels.py.
var adminPanelsModule = moduleDef{
	id:       "admin_panels",
	name:     "Admin panels",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		type result struct {
			idx     int
			finding *Finding
		}
		out := make(chan result, len(adminPanelPaths))
		for i, p := range adminPanelPaths {
			go func(i int, p struct{ path, label string }) {
				url := t.URL + p.path
				r, err := c.get(ctx, url, true)
				if err != nil {
					out <- result{idx: i}
					return
				}
				switch {
				case r.StatusCode == 200 && looksLikeLoginPage(r):
					out <- result{idx: i, finding: &Finding{
						Label: p.label + " accessible at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
						Detail: "Response body contains login-form wording (e.g. \"username\", \"password\", \"sign in\")",
					}}
				case r.StatusCode == 200:
					out <- result{idx: i, finding: &Finding{
						Label: p.label + " returned 200 at " + url + " (no login form detected)", URL: url, Method: "GET", StatusCode: r.StatusCode,
					}}
				case r.StatusCode == 403:
					out <- result{idx: i, finding: &Finding{
						Label: p.label + " exists but is forbidden at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
						Detail: "A 403 response still confirms the path exists, unlike a 404",
					}}
				default:
					out <- result{idx: i}
				}
			}(i, p)
		}
		found := make([]*Finding, len(adminPanelPaths))
		for range adminPanelPaths {
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
