package probescan

import (
	"context"
	"strings"
)

// miscellaneousModule ports modules/miscellaneous.py: robots/sitemap,
// security.txt, cross-domain policies, server status pages, changelogs,
// licenses, API specs, and monitoring endpoints.
var miscellaneousModule = moduleDef{
	id:       "miscellaneous",
	name:     "Miscellaneous",
	severity: "low",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		checks := []pathCheck{
			{"/robots.txt", "Robots.txt file", containsAny("disallow", "allow")},
			{"/sitemap.xml", "Sitemap file", containsAny("<url>")},
			{"/sitemap_index.xml", "Sitemap index file", containsAny("<sitemap>")},
			{"/security.txt", "Security.txt file", containsAny("contact:")},
			{"/.well-known/security.txt", "Security.txt file", containsAny("contact:")},
			{"/crossdomain.xml", "Cross-domain policy", containsAny("<cross-domain-policy>")},
			{"/clientaccesspolicy.xml", "Client access policy", containsAny("<access-policy>")},
			{"/server-status", "Apache server status page", containsAll("apache", "server")},
			{"/server-info", "Apache server info page", containsAny("apache")},
			{"/nginx_status", "Nginx status page", containsAny("active connections")},
			{"/stub_status", "Nginx stub status page", containsAny("active connections")},
			{"/CHANGELOG.md", "Changelog file", nonEmptyBody},
			{"/CHANGELOG.txt", "Changelog file", nonEmptyBody},
			{"/CHANGELOG", "Changelog file", nonEmptyBody},
			{"/README.md", "Readme file", nonEmptyBody},
			{"/README.txt", "Readme file", nonEmptyBody},
			{"/README", "Readme file", nonEmptyBody},
			{"/VERSION", "Version file", func(r *httpResult) bool { return len(strings.TrimSpace(r.Text)) > 0 }},
			{"/version.txt", "Version file", func(r *httpResult) bool { return len(strings.TrimSpace(r.Text)) > 0 }},
			{"/LICENSE", "License file", containsAny("license")},
			{"/LICENSE.txt", "License file", containsAny("license")},
			{"/LICENSE.md", "License file", containsAny("license")},
			{"/swagger.json", "Swagger API spec", containsAny("swagger")},
			{"/swagger.yaml", "Swagger API spec", containsAny("swagger")},
			{"/openapi.json", "OpenAPI spec", containsAny("openapi")},
			{"/openapi.yaml", "OpenAPI spec", containsAny("openapi")},
			{"/api-docs", "API documentation", containsAny("swagger", "api")},
			{"/api/swagger.json", "Swagger API spec", containsAny("swagger")},
			{"/v1/swagger.json", "Swagger API spec (v1)", containsAny("swagger")},
			{"/v2/swagger.json", "Swagger API spec (v2)", containsAny("swagger")},
			{"/metrics", "Prometheus metrics endpoint", containsAny("# help", "# type")},
			{"/actuator", "Spring Boot actuator", containsCase("_links")},
			{"/actuator/health", "Spring Boot health endpoint", containsAny("status")},
			{"/actuator/env", "Spring Boot env endpoint", containsCase("propertySources")},
			{"/actuator/mappings", "Spring Boot mappings endpoint", containsCase("dispatcherServlet")},
			{"/health", "Health check endpoint", containsAny("status", "ok")},
		}
		return runPathChecks(ctx, c, t.URL, checks, false, "found at")
	},
}
