package probescan

import (
	"context"
	"regexp"
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

// gitLogLine matches one reflog line: two object hashes, an identity, and a
// timestamp. A real .git/logs/HEAD is made entirely of these.
var gitLogLine = regexp.MustCompile(`(?m)^[0-9a-f]{40} [0-9a-f]{40} .+<.*> \d+ [+-]\d{4}`)

// validGitLog requires at least one well-formed reflog entry.
func validGitLog(r *httpResult) bool {
	return notHTML(func(r *httpResult) bool { return gitLogLine.MatchString(r.Text) })(r)
}

// validSVNEntries accepts the legacy SVN "entries" text format, which opens
// with a format number and lists entry kinds such as "dir" and "file".
func validSVNEntries(r *httpResult) bool {
	t := strings.TrimSpace(r.Text)
	if looksHTML(r) || t == "" {
		return false
	}
	firstLine := strings.SplitN(t, "\n", 2)[0]
	return isDigits(strings.TrimSpace(firstLine)) && strings.Contains(r.Text, "\ndir\n")
}

// validHgRC requires a Mercurial config section header on its own line.
var validHgRC = validINIMatch(`\[(paths|ui)\]`)

// versionControlModule ports modules/version_control.py: checks for
// publicly exposed Git/SVN/Mercurial/Bazaar/CVS repository files. Each check
// parses the format it claims to find; weak plain-text checks are reported
// separately with confidence "likely".
var versionControlModule = moduleDef{
	id:       "version_control",
	name:     "Version control",
	severity: "high",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		strong := []pathCheck{
			{"/.git/HEAD", "Git HEAD file", validGitHEAD},
			{"/.git/config", "Git config file", validINIMatch(`\[core\]`)},
			{"/.git/index", "Git index file", bodyPrefix([]byte("DIRC"))},
			{"/.git/logs/HEAD", "Git commit log", validGitLog},
			{"/.git/packed-refs", "Git packed refs", notHTML(containsCase("# pack-refs"))},
			{"/.gitmodules", "Git submodules file", validINIMatch(`\[submodule "[^"]+"\]`)},
			{"/.svn/entries", "SVN entries file", validSVNEntries},
			{"/.svn/wc.db", "SVN working copy database", validSQLiteDB},
			{"/.hg/hgrc", "Mercurial config", validHgRC},
		}
		// Plain-text checks: the file is text, but nothing else about it can
		// be verified, so these findings are reported as "likely".
		weak := []pathCheck{
			{"/.git/COMMIT_EDITMSG", "Git commit message", validPlainText},
			{"/.git/description", "Git description file", validPlainText},
			{"/.gitignore", "Git ignore file", validPlainText},
			{"/.gitattributes", "Git attributes file", validPlainText},
			{"/.svn/format", "SVN format file", notHTML(func(r *httpResult) bool {
				return isDigits(strings.TrimSpace(r.Text))
			})},
			{"/.hg/dirstate", "Mercurial dirstate", validPlainText},
			{"/.hg/store/fncache", "Mercurial file cache", validPlainText},
			{"/.hgignore", "Mercurial ignore file", validPlainText},
			{"/.bzrignore", "Bazaar ignore file", validPlainText},
			{"/CVS/Root", "CVS root file", notHTML(containsCase(":"))},
			{"/CVS/Entries", "CVS entries file", notHTML(containsCase("/"))},
		}

		findings := runFileChecks(ctx, c, t.URL, strong, ConfidenceConfirmed)
		findings = append(findings, runFileChecks(ctx, c, t.URL, weak, ConfidenceLikely)...)

		// Directory listings are HTML by nature, so they go through the
		// non-strict path. The catch-all gate still applies to them.
		listings := []pathCheck{
			{"/.git/refs/heads", "Git branch refs", containsAny("index of")},
			{"/.bzr/README", "Bazaar repository", containsAny("bazaar")},
		}
		return append(findings, runPathChecks(ctx, c, t.URL, listings, false, "exposed at")...)
	},
}
