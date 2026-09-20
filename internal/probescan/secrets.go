package probescan

import (
	"context"
	"net/url"
	"regexp"
)

// secretPattern is one named regex for a recognizable secret/credential
// format -- kept deliberately high-signal (specific key prefixes/shapes)
// rather than a broad "anything after a word like 'key'" match, which would
// bury real findings in false positives from minified JS. group is the
// capture group holding the actual secret value (0 -- the whole match --
// for patterns that don't need to separate a value from its surrounding
// syntax, e.g. a bare AWS access key ID).
type secretPattern struct {
	name    string
	pattern *regexp.Regexp
	group   int
}

var secretPatterns = []secretPattern{
	{"AWS Access Key ID", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), 0},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws_secret_access_key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`), 1},
	{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), 0},
	{"Slack Token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,72}\b`), 0},
	{"Stripe Live Secret Key", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`), 0},
	{"GitHub Token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`), 0},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`), 0},
	{"Generic API Key Assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']`), 2},
	{"JWT-shaped Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), 0},
}

var scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// scanForSecrets regex-scans text for every pattern in secretPatterns,
// keeping the actual matched value (Finding.Evidence) alongside which
// pattern matched and which URL the text came from -- e.g. "which key was
// found in which file" is Evidence + URL, not just the pattern's name.
func scanForSecrets(text, sourceURL string, statusCode int) []Finding {
	var findings []Finding
	seen := map[string]bool{} // one finding per pattern per source is enough
	for _, sp := range secretPatterns {
		if seen[sp.name] {
			continue
		}
		m := sp.pattern.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		seen[sp.name] = true
		evidence := m[0]
		if sp.group > 0 && sp.group < len(m) {
			evidence = m[sp.group]
		}
		findings = append(findings, Finding{
			Label:      "Possible " + sp.name + " found in " + sourceURL,
			URL:        sourceURL,
			Evidence:   evidence,
			Detail:     "Regex match for the " + sp.name + " pattern in the response body",
			Method:     "GET",
			StatusCode: statusCode,
		})
	}
	return findings
}

// secretsModule is a real implementation of modules/exposed_secrets.py --
// the Python original is an unimplemented stub (`_run` always returns
// False, with a literal `# TODO: Implement...` comment), so there was no
// existing behavior to preserve. This fetches the homepage and up to 5
// same-origin <script src> files it links, and regex-scans each for
// recognizable secret/credential formats left in frontend code.
var secretsModule = moduleDef{
	id:       "secrets",
	name:     "Secrets",
	severity: "critical",
	run: func(ctx context.Context, t *Target, c *probeClient) []Finding {
		r, err := c.get(ctx, t.URL, true)
		if err != nil {
			return nil
		}
		findings := scanForSecrets(r.Text, t.URL, r.StatusCode)

		base, err := url.Parse(t.URL)
		if err != nil {
			return findings
		}

		checked := 0
		for _, m := range scriptSrcPattern.FindAllStringSubmatch(r.Text, -1) {
			if checked >= 5 {
				break
			}
			src, err := base.Parse(m[1])
			if err != nil || src.Host != base.Host {
				continue // same-origin only -- not fetching third-party CDN scripts
			}
			checked++
			sr, err := c.get(ctx, src.String(), true)
			if err != nil {
				continue
			}
			findings = append(findings, scanForSecrets(sr.Text, src.String(), sr.StatusCode)...)
		}

		return findings
	},
}
