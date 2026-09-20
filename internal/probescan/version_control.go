package probescan

import (
	"context"
	"strings"
)

// isDigits reports whether s is non-empty and consists entirely of ASCII
// digits -- Go equivalent of Python's str.isdigit() as used by the SVN
// format-file check.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// versionControlModule ports modules/version_control.py: checks for
// publicly exposed Git/SVN/Mercurial/Bazaar/CVS repository files.
var versionControlModule = moduleDef{
	id:       "version_control",
	name:     "Version control",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		checks := []pathCheck{
			{"/.git/HEAD", "Git HEAD file", func(r *httpResult) bool { return strings.HasPrefix(r.Text, "ref:") }},
			{"/.git/config", "Git config file", containsCase("[core]")},
			{"/.git/index", "Git index file", bodyPrefix([]byte("DIRC"))},
			{"/.git/COMMIT_EDITMSG", "Git commit message", nonEmptyBody},
			{"/.git/logs/HEAD", "Git commit log", containsAny("commit")},
			{"/.git/description", "Git description file", nonEmptyBody},
			{"/.git/packed-refs", "Git packed refs", containsCase("# pack-refs")},
			{"/.git/refs/heads", "Git branch refs", containsAny("index of")},
			{"/.gitignore", "Git ignore file", nonEmptyBody},
			{"/.gitmodules", "Git submodules file", containsCase("[submodule")},
			{"/.gitattributes", "Git attributes file", nonEmptyBody},
			{"/.svn/entries", "SVN entries file", func(r *httpResult) bool {
				return containsCase("dir")(r) || strings.HasPrefix(r.Text, "10")
			}},
			{"/.svn/wc.db", "SVN working copy database", bodyPrefix([]byte("SQLite"))},
			{"/.svn/format", "SVN format file", func(r *httpResult) bool {
				return isDigits(strings.TrimSpace(r.Text))
			}},
			{"/.hg/dirstate", "Mercurial dirstate", func(r *httpResult) bool { return len(r.Body) > 0 }},
			{"/.hg/hgrc", "Mercurial config", containsCase("[paths]", "[ui]")},
			{"/.hg/store/fncache", "Mercurial file cache", nonEmptyBody},
			{"/.hgignore", "Mercurial ignore file", nonEmptyBody},
			{"/.bzr/README", "Bazaar repository", containsAny("bazaar")},
			{"/.bzrignore", "Bazaar ignore file", nonEmptyBody},
			{"/CVS/Root", "CVS root file", containsCase(":")},
			{"/CVS/Entries", "CVS entries file", containsCase("/")},
		}
		return runPathChecks(ctx, c, t.URL, checks, false, "exposed at")
	},
}
