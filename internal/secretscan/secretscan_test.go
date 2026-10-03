package secretscan

import (
	"strings"
	"testing"
)

// TestMatchNeverCarriesTheRawSecret checks that a scanned secret comes back
// masked, with only a fingerprint of the raw value.
func TestMatchNeverCarriesTheRawSecret(t *testing.T) {
	const secret = "AKIAQRSTUVWXYZ234567"
	matches := ScanBody(`var k = "`+secret+`";`, "https://h/app.js")
	if len(matches) == 0 {
		t.Fatal("AWS key not found")
	}
	for _, m := range matches {
		if strings.Contains(m.Value, secret) {
			t.Errorf("match value leaks the secret: %q", m.Value)
		}
		if m.Fingerprint != Fingerprint(secret) {
			t.Errorf("fingerprint does not identify the secret")
		}
	}
}

// TestMaskKeepsOnlyEdges checks the display form: enough to tell keys apart,
// never enough to use one.
func TestMaskKeepsOnlyEdges(t *testing.T) {
	got := Mask("ABCD1234567890WXYZ")
	if strings.Contains(got, "1234567890") {
		t.Errorf("middle of the value survived masking: %q", got)
	}
	if !strings.HasPrefix(got, "ABCD") || !strings.HasSuffix(got, "WXYZ") {
		t.Errorf("mask lost the recognizable edges: %q", got)
	}
	if strings.Contains(Mask("short"), "short") {
		t.Errorf("short value was not hidden: %q", Mask("short"))
	}
}

// TestPlaceholdersAreNotSecrets checks that documentation values are dropped,
// including AWS's published example key.
func TestPlaceholdersAreNotSecrets(t *testing.T) {
	for _, v := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"your_api_key_goes_here_123456",
		"xxxxxxxxxxxxxxxxxxxxxxxx",
		"${SECRET_TOKEN_VALUE_HERE}",
	} {
		if !isPlaceholder(v) {
			t.Errorf("isPlaceholder(%q) = false, want true", v)
		}
	}
	if isPlaceholder("q8Zt2LmW0pXc7RvB4nYe9KdA") {
		t.Error("a random-looking value was treated as a placeholder")
	}
}

// TestPublishableKeysAreMarkedPublic checks that a publishable key is kept
// as informational, while a secret key is classed as a secret.
func TestPublishableKeysAreMarkedPublic(t *testing.T) {
	matches := ScanBody(`var pk = "pk_live_51HqRealLookingPublishableKeyValue";`, "https://h/x.js")
	if len(matches) != 1 || matches[0].Level != "public-key" {
		t.Errorf("publishable key matches = %+v, want one public-key", matches)
	}
	secret := ScanBody(`var sk = "sk_live_51HqRealLookingSecretKeyValueXYZ";`, "https://h/x.js")
	if len(secret) != 1 || secret[0].Level != "secret" {
		t.Errorf("secret key matches = %+v, want one secret", secret)
	}
}

// TestHexSecretIsReachableByEntropy checks the fix for the unreachable hex
// threshold: a random-looking 40-character hex value is now found, and short
// hex strings are not considered at all.
func TestHexSecretIsReachableByEntropy(t *testing.T) {
	hexSecret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
	found := findHighEntropyStrings(`token = "`+hexSecret+`"`, entropyThreshold, entropyMaxLen)
	if len(found) != 1 || found[0] != hexSecret {
		t.Errorf("hex secret not found by entropy detector: %v", found)
	}
	if got := findHighEntropyStrings(`x = "a1b2c3d4e5f6"`, entropyThreshold, entropyMaxLen); len(got) != 0 {
		t.Errorf("short hex string was considered: %v", got)
	}
}

// TestEntropySkipsDataURIsAndPaths checks that base64 image bytes, sourcemaps,
// and URL path segments do not become secret candidates.
func TestEntropySkipsDataURIsAndPaths(t *testing.T) {
	cases := map[string]string{
		"data uri":     `img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="`,
		"sourcemap":    `//# sourceMappingURL=app.js.map?v=QzI5MzRmYWJjZDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3`,
		"path segment": `load("/static/Qz29MzRmYWJjZDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ZWFw.js")`,
	}
	for name, text := range cases {
		if got := findHighEntropyStrings(text, entropyThreshold, entropyMaxLen); len(got) != 0 {
			t.Errorf("%s produced entropy candidates: %v", name, got)
		}
	}
}

// TestBinaryContentTypesAreSkipped checks the content-type gate.
func TestBinaryContentTypesAreSkipped(t *testing.T) {
	for ct, want := range map[string]bool{
		"image/png":                true,
		"application/octet-stream": true,
		"font/woff2":               true,
		"text/html; charset=utf-8": false,
		"application/javascript":   false,
		"":                         false,
	} {
		if got := skippableContentType(ct); got != want {
			t.Errorf("skippableContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

// TestOverlappingPatternsDedupeToOneMatch checks that a private key matched
// by several overlapping patterns is reported once per location.
func TestOverlappingPatternsDedupeToOneMatch(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	matches := ScanBody(body, "https://h/key.pem")
	seen := map[string]int{}
	for _, m := range matches {
		seen[m.Fingerprint+"|"+m.Location]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("secret reported %d times: %s", n, k)
		}
	}
}
