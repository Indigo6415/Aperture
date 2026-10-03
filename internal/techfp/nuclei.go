package techfp

// detectionConfidence grades one detection: a version is the strongest evidence,
// a response header is next, and body markup alone is the weakest.
func detectionConfidence(version string, viaHeader bool) string {
	switch {
	case version != "":
		return "high"
	case viaHeader:
		return "medium"
	}
	return "low"
}

// nucleiTagFor maps a detected technology to the tag nuclei uses for its
// templates. The mapping is best-effort: a technology without an entry adds
// nothing, which means the templates for it are simply not selected.
var nucleiTagFor = map[string]string{
	"WordPress":     "wordpress",
	"Drupal":        "drupal",
	"Joomla":        "joomla",
	"Apache httpd":  "apache",
	"nginx":         "nginx",
	"PHP":           "php",
	"jQuery":        "jquery",
	"Express":       "express",
	"Microsoft-IIS": "iis",
	"Varnish":       "varnish",
	"Caddy":         "caddy",
	"ASP.NET":       "aspnet",
}

// NucleiTags returns the nuclei template tags for the given detected technology
// names, deduplicated and in the order given. Pass the result as a nuclei
// config's Tags to run only templates that fit what the host actually runs.
func NucleiTags(detections []Detection) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range detections {
		tag, ok := nucleiTagFor[d.Name]
		if !ok || seen[tag] {
			continue
		}
		seen[tag] = true
		out = append(out, tag)
	}
	return out
}
