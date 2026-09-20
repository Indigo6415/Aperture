package probescan

import "context"

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
}

func isDirectoryListing(r *httpResult) bool {
	return containsAny("index of /", "directory listing for", "parent directory", "<title>index of")(r)
}

// directoriesModule ports modules/exposed_directories.py. Each path is
// checked twice, with and without a trailing slash, matching the original
// (a bare path often 30x-redirects while the slash variant serves the
// listing directly, or vice versa depending on the server).
var directoriesModule = moduleDef{
	id:       "directories",
	name:     "Directory listing",
	severity: "medium",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		type result struct {
			idx     int
			finding *Finding
		}
		total := len(directoryNames) * 2
		out := make(chan result, total)

		probe := func(idx int, url, label string) {
			r, err := c.get(ctx, url, false)
			if err != nil || r.StatusCode != 200 {
				out <- result{idx: idx}
				return
			}
			switch {
			case isDirectoryListing(r):
				out <- result{idx: idx, finding: &Finding{
					Label: label + " with open listing at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode,
					Detail: "Response body looks like an autoindex page (\"Index of /\", \"Parent Directory\", ...)",
				}}
			default:
				out <- result{idx: idx, finding: &Finding{Label: label + " accessible (no listing) at " + url, URL: url, Method: "GET", StatusCode: r.StatusCode}}
			}
		}

		for i, d := range directoryNames {
			base := t.URL + d.path
			go probe(i*2, base, d.label)
			go probe(i*2+1, base+"/", d.label)
		}

		found := make([]*Finding, total)
		for range total {
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
