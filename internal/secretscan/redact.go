package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// placeholderMarkers are substrings that mark a value as documentation,
// a template, or a stand-in rather than a live credential. Matching is
// case-insensitive. AWS's published example key is covered by "example".
var placeholderMarkers = []string{
	"example", "xxxx", "your_", "your-", "your ", "your api", "yourapi", "yourkey",
	"yoursecret", "yourtoken", "<your", "placeholder", "dummy", "changeme",
	"redacted", "<", "${", "{{", "lorem", "sample", "insert_", "insert-",
	"fake", "not_real", "notreal", "replace_me", "replace-me", "replaceme",
	"put_your", "enter_your", "enter-your", "my_secret", "mysecret",
	"api_key_here", "secret_here", "token_here", "key_here",
	// Counting and keyboard-row strings that test values and templates use.
	"0123456789", "9876543210", "12345678", "87654321", "abcdefgh", "qwertyui", "asdfghjk",
}

// isPlaceholder reports whether value looks like documentation or a template
// rather than a real secret: a known placeholder marker, a value made of a
// single repeated character, a value that repeats a short unit, or one that
// counts through the alphabet or digits in order.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return isRepeated(value) || isPeriodic(value) || longestSequentialRun(value) >= sequentialRunMin
}

// sequentialRunMin is how many characters in a row must step by exactly one
// code point (ascending or descending) before a value is treated as a counting
// placeholder. It is set above the length of a run that real keys can contain
// by chance (the "QRSTUVWXYZ" in a real-looking AWS key fixture is 10), so the
// short counting strings are caught by placeholderMarkers instead.
const sequentialRunMin = 11

// isRepeated reports whether every character of s is the same, such as
// "aaaaaaaaaaaaaaaa", which no generator produces.
func isRepeated(s string) bool {
	if s == "" {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// maxPeriodicUnit is the longest repeated unit isPeriodic looks for. Longer
// units would need a value many times longer than any real key to be detected.
const maxPeriodicUnit = 12

// isPeriodic reports whether s is made of a short unit repeated at least three
// times, such as "abcabcabc" or "1234 1234 1234" with no spaces. A random value
// of realistic length matches a period this short only by coincidence.
func isPeriodic(s string) bool {
	// Try each candidate unit length, shortest first, and stop at the first that
	// repeats through the whole value.
	for p := 1; p <= maxPeriodicUnit && 3*p <= len(s); p++ {
		periodic := true
		// Compare every byte with the one a unit earlier; any mismatch rules out this unit length.
		for i := p; i < len(s); i++ {
			if s[i] != s[i-p] {
				periodic = false
				break
			}
		}
		if periodic {
			return true
		}
	}
	return false
}

// longestSequentialRun returns the length, in characters, of the longest run
// in s where each character is exactly one code point above (or below) the
// one before it. A run of 1 means no two neighbors are consecutive.
func longestSequentialRun(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	best, run := 1, 1
	prevStep := 0
	// Walk the value once, extending the current run while the step between
	// neighbors stays +1 or stays -1, and restarting it on any other step.
	for i := 1; i < len(s); i++ {
		step := int(s[i]) - int(s[i-1])
		if (step == 1 || step == -1) && (prevStep == 0 || step == prevStep) {
			run++
			prevStep = step
		} else if step == 1 || step == -1 {
			// The direction flipped, so this pair starts a new run of two.
			run = 2
			prevStep = step
		} else {
			run = 1
			prevStep = 0
		}
		if run > best {
			best = run
		}
	}
	// run already counts characters (not steps), so the best run is returned as is.
	return best
}

// Mask returns the display form of a secret: enough of each end to recognize
// which key it is, never enough to use. Short values are fully hidden.
func Mask(value string) string {
	if len(value) <= 12 {
		return "••••••••"
	}
	return value[:4] + "••••••••" + value[len(value)-4:]
}

// Fingerprint returns a stable SHA-256 of the raw value. It lets the same
// secret be recognized across pages and runs without storing the secret.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// skippableContentType reports whether a response's Content-Type means its
// body cannot contain readable source or configuration: images, fonts, media,
// archives, and generic binary streams. Empty and unknown types are scanned,
// since a misconfigured server often omits the header.
func skippableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	for _, prefix := range []string{"image/", "font/", "video/", "audio/"} {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	for _, exact := range []string{"application/octet-stream", "application/zip", "application/pdf", "application/wasm", "application/gzip"} {
		if strings.HasPrefix(ct, exact) {
			return true
		}
	}
	return false
}
