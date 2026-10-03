package secretscan

import (
	"math"
	"regexp"
	"strings"
)

// entropyCandidatePattern pulls out base64/hex-alphabet runs worth
// entropy-scoring -- mirrors Snitch's EntropySnitcher, which draws its
// candidates from the same character class.
var entropyCandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)

// hexOnlyPattern matches candidates drawn entirely from the hex alphabet.
var hexOnlyPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// hexThreshold is the entropy floor for hex candidates. A hex string has at
// most 16 distinct symbols, so its Shannon entropy can never exceed 4 bits;
// the base64 threshold (4.5) therefore never fires on a hex secret, and hex
// keys were invisible to this detector. 3.0 bits is about what random hex of
// this length produces.
const hexThreshold = 3.0

// hexMinLength is the shortest hex candidate considered. Shorter hex strings
// are too often ordinary identifiers, hashes of content, or colors.
const hexMinLength = 32

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

// findHighEntropyStrings flags candidate strings whose entropy clears the
// threshold for their alphabet -- an unlabeled fallback for secrets that don't
// match any named Pattern. Off unless requested (see Request.Entropy), since
// it is noisy against minified JS/CSS.
//
// Candidates are skipped when they sit inside a data: URI, a sourcemap
// reference, or a URL path (preceded by "/" or "."), since those are
// base64 image bytes, build hashes, and file names rather than credentials.
func findHighEntropyStrings(text string, threshold float64, maxLen int) []string {
	seen := make(map[string]bool)
	var out []string
	for _, loc := range entropyCandidatePattern.FindAllStringIndex(text, -1) {
		m := text[loc[0]:loc[1]]
		if len(m) > maxLen || seen[m] {
			continue
		}
		if isInsideNonCredentialContext(text, loc[0]) {
			continue
		}
		if isPlaceholder(m) {
			continue
		}
		if shannonEntropy(m) < thresholdFor(m, threshold) {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// thresholdFor returns the entropy floor for a candidate. Hex candidates use
// the lower hex floor, and a hex candidate shorter than hexMinLength is never
// considered; every other candidate uses the caller's threshold.
func thresholdFor(candidate string, threshold float64) float64 {
	if hexOnlyPattern.MatchString(candidate) {
		if len(candidate) < hexMinLength {
			return math.Inf(1)
		}
		return hexThreshold
	}
	return threshold
}

// isInsideNonCredentialContext reports whether the candidate starting at
// offset is part of a data URI, a sourcemap comment, or a path segment.
func isInsideNonCredentialContext(text string, offset int) bool {
	// A candidate that begins with "/" is a URL path. The candidate character
	// class includes "/", so a path arrives as one candidate and the check
	// below would otherwise miss it.
	if offset < len(text) && text[offset] == '/' {
		return true
	}
	// Look at the characters just before the candidate.
	if offset > 0 {
		prev := text[offset-1]
		if prev == '/' || prev == '.' {
			return true
		}
	}
	// Examine the rest of the current line, which is where a data URI or a
	// sourcemap reference would sit.
	lineStart := strings.LastIndexByte(text[:offset], '\n') + 1
	lineEnd := strings.IndexByte(text[offset:], '\n')
	if lineEnd < 0 {
		lineEnd = len(text)
	} else {
		lineEnd += offset
	}
	line := text[lineStart:lineEnd]
	return strings.Contains(line, "data:") || strings.Contains(line, "sourceMappingURL")
}
