package secretscan

import (
	"math"
	"regexp"
)

// entropyCandidatePattern pulls out base64/hex-alphabet runs worth
// entropy-scoring -- mirrors Snitch's EntropySnitcher, which draws its
// candidates from the same character class.
var entropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)

// shannonEntropy computes a string's Shannon entropy in bits/char -- high
// entropy is what separates a random-looking key/token from ordinary
// English or code text.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, len(s))
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// findHighEntropyStrings flags candidate strings whose entropy clears
// threshold -- an unlabeled fallback for secrets that don't match any named
// Pattern. Same posture as Snitch's own CLI: off unless explicitly
// requested (see Request.Entropy), since it's noisy against minified
// JS/CSS/hashed asset filenames.
func findHighEntropyStrings(text string, threshold float64, maxLen int) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range entropyCandidatePattern.FindAllString(text, -1) {
		if len(m) > maxLen || seen[m] {
			continue
		}
		if shannonEntropy(m) >= threshold {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
