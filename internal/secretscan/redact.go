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
	"example", "xxxx", "your_", "your-", "your ", "placeholder", "dummy",
	"changeme", "redacted", "<", "${", "{{", "lorem", "sample", "insert_",
}

// isPlaceholder reports whether value looks like documentation or a template
// rather than a real secret: a known placeholder marker, or a value made of a
// single repeated character.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return isRepeated(value)
}

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
