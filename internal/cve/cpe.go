package cve

// vendorProduct maps a fingerprinted technology name (as techfp reports it) to
// the vendor and product of its CPE in the NVD dictionary. Only technologies
// whose NVD product name is well established are listed. A technology missing
// from this table falls back to keyword search, and its results say so.
//
// Versions only ever match through CPE: NVD's virtualMatchString checks the
// version against each CVE's affected range, which keyword search never does.
var vendorProduct = map[string]string{
	"Apache httpd":  "apache:http_server",
	"Drupal":        "drupal:drupal",
	"Express":       "expressjs:express",
	"Joomla":        "joomla:joomla",
	"jQuery":        "jquery:jquery",
	"Microsoft-IIS": "microsoft:internet_information_services",
	"nginx":         "nginx:nginx",
	"PHP":           "php:php",
	"WordPress":     "wordpress:wordpress",
	"Varnish":       "varnish-software:varnish_cache",
	"Caddy":         "caddyserver:caddy",
}

// Match types recorded on each CVE, so the UI can say how a result was found.
const (
	// MatchRange means NVD matched the exact product and version against the
	// CVE's affected version range.
	MatchRange = "range-confirmed"
	// MatchKeyword means the result came from a free-text search and may
	// concern a different product with a similar name, or a version outside
	// the affected range.
	MatchKeyword = "keyword-only"
)

// cpeMatchString builds the NVD virtualMatchString for a product and version,
// or returns false when the product has no known CPE.
func cpeMatchString(product, version string) (string, bool) {
	vp, ok := vendorProduct[product]
	if !ok {
		return "", false
	}
	return "cpe:2.3:a:" + vp + ":" + version + ":*:*:*:*:*:*:*", true
}
