package probescan

import (
	"context"
	"regexp"
)

// miscellaneousModule ports modules/miscellaneous.py: robots/sitemap,
// security.txt, cross-domain policies, server status pages, changelogs,
// licenses, API specs, and monitoring endpoints. Each check keys on the format
// of its file, not on a common word, so an ordinary page does not match.
var miscellaneousModule = moduleDef{
	id:       "miscellaneous",
	name:     "Miscellaneous",
	severity: "low",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		checks := []pathCheck{
			{"/robots.txt", "Robots.txt file", validRegexp(robotsDirective)},
			{"/sitemap.xml", "Sitemap file", containsAny("<urlset")},
			{"/sitemap_index.xml", "Sitemap index file", containsAny("<sitemapindex")},
			{"/security.txt", "Security.txt file", validRegexp(securityTxtContact)},
			{"/.well-known/security.txt", "Security.txt file", validRegexp(securityTxtContact)},
			{"/crossdomain.xml", "Cross-domain policy", containsAny("<cross-domain-policy")},
			{"/clientaccesspolicy.xml", "Client access policy", containsAny("<access-policy")},
			{"/server-status", "Apache server status page", containsAny("apache server status", "total accesses:")},
			{"/server-info", "Apache server info page", containsAny("apache server information")},
			{"/nginx_status", "Nginx status page", containsAll("active connections", "server accepts handled requests")},
			{"/stub_status", "Nginx stub status page", containsAll("active connections", "server accepts handled requests")},
			{"/CHANGELOG.md", "Changelog file", validPlainText},
			{"/CHANGELOG.txt", "Changelog file", validPlainText},
			{"/CHANGELOG", "Changelog file", validPlainText},
			{"/README.md", "Readme file", validPlainText},
			{"/README.txt", "Readme file", validPlainText},
			{"/README", "Readme file", validPlainText},
			{"/VERSION", "Version file", validRegexp(versionStringLine)},
			{"/version.txt", "Version file", validRegexp(versionStringLine)},
			{"/LICENSE", "License file", notHTML(containsAny("license"))},
			{"/LICENSE.txt", "License file", notHTML(containsAny("license"))},
			{"/LICENSE.md", "License file", notHTML(containsAny("license"))},
			{"/swagger.json", "Swagger API spec", validJSONKeys("swagger", "openapi")},
			{"/swagger.yaml", "Swagger API spec", validYAMLAny("swagger", "openapi")},
			{"/openapi.json", "OpenAPI spec", validJSONKeys("openapi", "swagger")},
			{"/openapi.yaml", "OpenAPI spec", validYAMLAny("openapi", "swagger")},
			{"/api-docs", "API documentation", containsAny("swagger", "openapi")},
			{"/api/swagger.json", "Swagger API spec", validJSONKeys("swagger", "openapi")},
			{"/v1/swagger.json", "Swagger API spec (v1)", validJSONKeys("swagger", "openapi")},
			{"/v2/swagger.json", "Swagger API spec (v2)", validJSONKeys("swagger", "openapi")},
			// Springfox serves its spec at /v2/api-docs as JSON.
			{"/v2/api-docs", "Swagger API spec (Springfox)", validJSONKeys("swagger", "openapi")},
			{"/swagger-ui.html", "Swagger UI", containsAll("swagger", "swagger-ui")},
			{"/metrics", "Prometheus metrics endpoint", validRegexp(prometheusMetricLine)},
			// Spring Boot actuator endpoints. Each returns a JSON object with a
			// member that only that endpoint produces.
			{"/actuator", "Spring Boot actuator", validJSONKeys("_links")},
			{"/actuator/health", "Spring Boot health endpoint", validJSONKeys("status")},
			{"/actuator/env", "Spring Boot env endpoint", validJSONKeys("propertySources")},
			{"/actuator/mappings", "Spring Boot mappings endpoint", validJSONKeys("contexts")},
			{"/actuator/beans", "Spring Boot beans endpoint", validJSONKeys("contexts")},
			{"/actuator/configprops", "Spring Boot configuration properties endpoint", validJSONKeys("contexts")},
			{"/actuator/loggers", "Spring Boot loggers endpoint", validJSONKeys("levels", "loggers")},
			{"/actuator/metrics", "Spring Boot metrics endpoint", validJSONKeys("names")},
			{"/actuator/httptrace", "Spring Boot HTTP trace endpoint", validJSONKeys("traces")},
			{"/actuator/threaddump", "Spring Boot thread dump endpoint", validJSONKeys("threads")},
			// Alibaba Druid's monitoring console, which exposes SQL and session data.
			{"/druid/index.html", "Druid monitoring console", containsAny("druid stat index", "druid monitor")},
			{"/health", "Health check endpoint", validHealthBody},
		}
		return runPathChecks(ctx, c, t.URL, checks, false, "found at")
	},
}

// prometheusMetricLine matches a Prometheus exposition HELP or TYPE comment,
// which every metrics page begins with.
var prometheusMetricLine = regexp.MustCompile(`(?m)^# (HELP|TYPE) `)
