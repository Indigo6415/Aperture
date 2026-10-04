package probescan

import (
	"context"
	"sync"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// directoryNames are the backup/upload/dev/config paths probe checks for an
// open listing or bare accessibility -- ported from
// modules/exposed_directories.py's DIRECTORIES table.
var directoryNames = []struct{ path, label string }{
	{"/backup", "Backup directory"},
	{"/backups", "Backup directory"},
	{"/old", "Old files directory"},
	{"/archive", "Archive directory"},
	{"/archives", "Archive directory"},
	{"/uploads", "Uploads directory"},
	{"/upload", "Upload directory"},
	{"/files", "Files directory"},
	{"/media", "Media directory"},
	{"/assets", "Assets directory"},
	{"/src", "Source directory"},
	{"/source", "Source directory"},
	{"/dev", "Development directory"},
	{"/test", "Test directory"},
	{"/tests", "Tests directory"},
	{"/temp", "Temporary files directory"},
	{"/tmp", "Temporary files directory"},
	{"/logs", "Logs directory"},
	{"/log", "Log directory"},
	{"/config", "Config directory"},
	{"/configs", "Config directory"},
	{"/data", "Data directory"},
	{"/db", "Database directory"},
	{"/sql", "SQL directory"},
	{"/dump", "Dump directory"},
	{"/private", "Private directory"},
	{"/secret", "Secret directory"},
	{"/hidden", "Hidden directory"},
	// Dependency and build trees, whose listing exposes the full stack.
	{"/vendor", "Vendor dependencies directory"},
	{"/node_modules", "Node modules directory"},
	{"/bower_components", "Bower components directory"},
	// Installer, setup, and CGI directories that are meant to be removed after use.
	{"/install", "Installer directory"},
	{"/setup", "Setup directory"},
	{"/cgi-bin", "CGI scripts directory"},
	{"/includes", "Includes directory"},
	{"/lib", "Library directory"},
	// Staging, export, and report directories that often hold business data.
	{"/staging", "Staging directory"},
	{"/export", "Export directory"},
	{"/exports", "Exports directory"},
	{"/reports", "Reports directory"},
	{"/storage", "Storage directory"},
	{"/debug", "Debug directory"},
	{"/new", "New files directory"},
}

// isDirectoryListing reports whether a body is a server-generated autoindex
// page. Those phrases only appear in directory listings, so they are a
// structural check, not a guess.
func isDirectoryListing(r *httpResult) bool {
	return containsAny("index of /", "directory listing for", "parent directory", "<title>index of")(r)
}

// directoryProbe is one attempt at a directory path: its response summary,
// whether it is a listing, and whether it passed the catch-all gate.
type directoryProbe struct {
	obs     fingerprint.Observation
	listing bool
	hit     bool
}

// directoriesModule ports modules/exposed_directories.py. Each path is
// checked twice, with and without a trailing slash, matching the original (a
// bare path often 30x-redirects while the slash variant serves the listing
// directly, or vice versa). A 200 that matches the host's catch-all page is
// never a hit, and when the two variants serve the same page only the slash
// variant is reported, so one directory yields one finding.
var directoriesModule = moduleDef{
	id:       "directories",
	name:     "Directory listing",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		probes := make([]directoryProbe, len(directoryNames)*2)
		var wg sync.WaitGroup
		// Both variants of every directory fire concurrently; the shared
		// client's semaphore bounds how many are in flight at once.
		for i, d := range directoryNames {
			base := t.URL + d.path
			for v, url := range []string{base, base + "/"} {
				wg.Add(1)
				go func(idx int, url string) {
					defer wg.Done()
					r, err := c.get(ctx, url, false)
					if err != nil || r.StatusCode != 200 {
						return
					}
					probes[idx] = directoryProbe{
						obs:     r.observation(),
						listing: isDirectoryListing(r),
						hit:     !c.isCatchAll(r),
					}
				}(i*2+v, url)
			}
		}
		wg.Wait()

		var findings []Finding
		for i, d := range directoryNames {
			bare, slash := probes[i*2], probes[i*2+1]
			base := t.URL + d.path
			// Prefer the slash variant, which is where directories actually
			// live. Drop the bare one when both serve the same page.
			if slash.hit && bare.hit && fingerprint.Similar(bare.obs, slash.obs) {
				bare.hit = false
			}
			if bare.hit {
				findings = append(findings, directoryFinding(d.label, base, bare))
			}
			if slash.hit {
				findings = append(findings, directoryFinding(d.label, base+"/", slash))
			}
		}
		if findings == nil {
			findings = []Finding{}
		}
		return findings
	},
}

// directoryFinding builds the finding for one hit. A real listing is
// confirmed by its markup. A bare 200 with no listing only shows that the path
// answers, so it is reported as heuristic.
func directoryFinding(label, url string, p directoryProbe) Finding {
	if p.listing {
		return Finding{
			Label:      label + " with open listing at " + url,
			URL:        url,
			Method:     "GET",
			StatusCode: p.obs.Status,
			Detail:     "Response body is an autoindex page (\"Index of /\", \"Parent Directory\", ...)",
			Confidence: ConfidenceConfirmed,
		}
	}
	return Finding{
		Label:      label + " accessible (no listing) at " + url,
		URL:        url,
		Method:     "GET",
		StatusCode: p.obs.Status,
		Detail:     "The path returns 200 and does not look like the host's catch-all page, but no directory listing is shown. Confirm the contents by requesting a known file inside it.",
		Confidence: ConfidenceHeuristic,
	}
}
