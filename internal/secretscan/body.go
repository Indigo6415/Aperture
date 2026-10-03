package secretscan

// ScanBody runs the core pattern library over one response body and returns
// masked matches, deduplicated by value. It is the entry point for scanners
// that already hold a body and do not crawl (probescan's secrets module), so
// every consumer shares one pattern library and one masking rule.
func ScanBody(text, location string) []Match {
	return dedupMatches(scanText(text, location, Patterns, false))
}
