package probescan

import (
	"context"
	"net/url"
	"regexp"

	"github.com/Indigo6415/Aperture/internal/secretscan"
)

// scriptSrcPattern pulls the src of every script tag out of a page.
var scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// scanForSecrets runs the shared secretscan pattern library over one body.
// Publishable keys (Stripe pk_, browser map keys) are skipped here: they are
// meant to ship in client code, so reporting them as a critical leak would be
// a false positive. The matched value is masked by secretscan before it
// reaches a finding.
func scanForSecrets(text, sourceURL string, statusCode int) []Finding {
	var findings []Finding
	for _, m := range secretscan.ScanBody(text, sourceURL) {
		if m.Level == "public-key" {
			continue
		}
		confidence := ConfidenceLikely
		// A complete PEM block is structural; the other patterns are
		// shape-based guesses that only confirmation can settle.
		if m.Type == "Private Key Block" || m.Type == "PKCS8 Private Key Block" {
			confidence = ConfidenceConfirmed
		}
		findings = append(findings, Finding{
			Label:      "Possible " + m.Type + " found in " + sourceURL,
			URL:        sourceURL,
			Evidence:   m.Value,
			Detail:     "Pattern match for the " + m.Type + " format in the response body. The value is masked; its SHA-256 fingerprint is " + m.Fingerprint[:16] + "… so the same secret can be recognized across pages.",
			Method:     "GET",
			StatusCode: statusCode,
			Confidence: confidence,
		})
	}
	return findings
}

// secretsModule fetches the homepage and up to 5 same-origin <script src>
// files it links, and scans each for recognizable secret formats left in
// frontend code. It uses the same pattern library as the Secrets tab, so the
// two cannot disagree about what a key looks like.
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
