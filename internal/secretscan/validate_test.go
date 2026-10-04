package secretscan

import (
	"math/rand"
	"strings"
	"testing"
)

// fakeToken returns a deterministic pseudo-random string of n characters drawn
// from alphabet. Test fixtures use it so each synthetic key has the shape of a
// real one while staying repeatable and free of any real credential.
func fakeToken(alphabet string, n int, seed int64) string {
	r := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

const (
	alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	hexLo = "0123456789abcdef"
)

// findByType returns the matches whose pattern name is name.
func findByType(matches []Match, name string) []Match {
	var out []Match
	for _, m := range matches {
		if m.Type == name {
			out = append(out, m)
		}
	}
	return out
}

// TestPlaceholderFirstDoesNotHideRealSecret checks that a page whose first
// matches of a pattern are documentation placeholders still reports a real key
// that appears after them. Before the fix the per-pattern cap counted the
// placeholders, so the real key was never examined.
func TestPlaceholderFirstDoesNotHideRealSecret(t *testing.T) {
	body := `AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE AKIAQRSTUVWXYZ234567`
	matches := ScanBody(body, "https://h/x.js")
	aws := findByType(matches, "AWS Access Key ID")
	if len(aws) != 1 {
		t.Fatalf("real key after three placeholders: got %d AWS matches, want 1", len(aws))
	}
	if aws[0].Fingerprint != Fingerprint("AKIAQRSTUVWXYZ234567") {
		t.Errorf("the kept match is not the real key")
	}
}

// TestCountingAndRepeatingValuesArePlaceholders checks the structural
// placeholder detectors: ascending runs, short repeated units, and repeated
// characters are not secrets, while a random token is.
func TestCountingAndRepeatingValuesArePlaceholders(t *testing.T) {
	for _, v := range []string{
		"0123456789abcdef0123",
		"abcdefghijklmnop",
		"abcabcabcabc",
		"1212121212121212",
		"aaaaaaaaaaaaaaaaaaaa",
	} {
		if !isPlaceholder(v) {
			t.Errorf("isPlaceholder(%q) = false, want true", v)
		}
	}
	random := fakeToken(alnum, 32, 7)
	if isPlaceholder(random) {
		t.Errorf("isPlaceholder(random %q) = true, want false", random)
	}
}

// TestSequentialRunCountsCharacters checks the run-length helper on runs that
// go up, go down, and break.
func TestSequentialRunCountsCharacters(t *testing.T) {
	cases := map[string]int{
		"":           0,
		"a":          1,
		"abcdefgh":   8,
		"hgfedcba":   8,
		"axbycz":     1,
		"0123456789": 10,
		"abcXYZ":     3,
	}
	for in, want := range cases {
		if got := longestSequentialRun(in); got != want {
			t.Errorf("longestSequentialRun(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestGenericAssignmentNeedsGeneratedLookingValue checks that the loose
// api_key assignment pattern keeps a generated-looking value and drops a
// string of plain words, which an undefined-variable placeholder produces.
func TestGenericAssignmentNeedsGeneratedLookingValue(t *testing.T) {
	words := ScanBody(`const api_key = "undefinedundefinedundefined";`, "https://h/app.js")
	if got := findByType(words, "Generic API Key Assignment"); len(got) != 0 {
		t.Errorf("word-only api_key value was kept: %+v", got)
	}
	real := `const api_key = "` + fakeToken(alnum, 28, 11) + `";`
	if got := findByType(ScanBody(real, "https://h/app.js"), "Generic API Key Assignment"); len(got) != 1 {
		t.Errorf("generated api_key value not kept: %d matches", len(got))
	}
}

// TestJWTRequiresJSONHeader checks that a dotted random string is not a JWT,
// while a token whose header decodes to JSON with an alg member is.
func TestJWTRequiresJSONHeader(t *testing.T) {
	fake := "eyJhello_world_abc.xyz_abc_defgh.qwe_rty_uiop"
	if got := findByType(ScanBody(fake, "https://h/x.js"), "JWT-shaped Token"); len(got) != 0 {
		t.Errorf("dotted non-JWT string was kept as a JWT: %+v", got)
	}
	// Header {"alg":"HS256"}, payload {"sub":"user12345"}, a dummy signature.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzNDUifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
	if got := findByType(ScanBody(`t="`+jwt+`"`, "https://h/x.js"), "JWT-shaped Token"); len(got) != 1 {
		t.Errorf("well-formed JWT not kept: %d matches", len(got))
	}
}

// TestURLPasswordRejectsPlaceholderWords checks that a connection string whose
// password is a placeholder word is ignored, while a generated password is kept.
func TestURLPasswordRejectsPlaceholderWords(t *testing.T) {
	if got := ScanBody(`dsn = "postgres://app:password@db.corp.test/app"`, "https://h/x.js"); len(got) != 0 {
		t.Errorf("placeholder password was kept: %+v", got)
	}
	live := `dsn = "postgres://app:` + fakeToken(alnum, 14, 3) + `@db.corp.test/app"`
	if got := findByType(ScanBody(live, "https://h/x.js"), "Database Connection String"); len(got) != 1 {
		t.Errorf("generated database password not kept: %d matches", len(got))
	}
}

// TestPrivateKeyNeedsBodyAndEndMarker checks that a bare BEGIN line, the form
// documentation shows, is not reported, while a full block is.
func TestPrivateKeyNeedsBodyAndEndMarker(t *testing.T) {
	if got := ScanBody("-----BEGIN RSA PRIVATE KEY-----", "https://h/doc.html"); len(got) != 0 {
		t.Errorf("bare BEGIN line was reported as a key: %+v", got)
	}
	block := "-----BEGIN RSA PRIVATE KEY-----\n" + fakeToken(alnum, 64, 5) + "\n-----END RSA PRIVATE KEY-----"
	if got := findByType(ScanBody(block, "https://h/key.pem"), "Private Key Block"); len(got) != 1 {
		t.Errorf("complete private key block not reported: %d matches", len(got))
	}
}

// TestKeywordAnchoredPatternsRejectWords checks that a keyword-anchored
// pattern (Azure here) ignores a quoted English identifier and keeps a
// quoted value with digits.
func TestKeywordAnchoredPatternsRejectWords(t *testing.T) {
	word := `azure": "AzureActiveDirectoryAuthenticationSchemeHandler"`
	if got := findByType(ScanBody(word, "https://h/x.js"), "Azure Client Secret"); len(got) != 0 {
		t.Errorf("identifier-like value was kept: %+v", got)
	}
	real := `azure": "` + fakeToken(alnum, 30, 9) + `"`
	if got := findByType(ScanBody(real, "https://h/x.js"), "Azure Client Secret"); len(got) != 1 {
		t.Errorf("generated Azure value not kept: %d matches", len(got))
	}
}

// TestOpenAIDoesNotClaimAnthropicKeys checks that an sk-ant- key is reported
// only as an Anthropic key, and that a project-scoped OpenAI key is reported
// as OpenAI.
func TestOpenAIDoesNotClaimAnthropicKeys(t *testing.T) {
	anthropic := "sk-ant-" + fakeToken(alnum, 95, 21)
	matches := ScanBody(`k="`+anthropic+`"`, "https://h/x.js")
	if got := findByType(matches, "OpenAI API Key"); len(got) != 0 {
		t.Errorf("Anthropic key was also reported as OpenAI: %+v", got)
	}
	if got := findByType(matches, "Anthropic API Key"); len(got) != 1 {
		t.Errorf("Anthropic key not reported: %d matches", len(got))
	}
	openai := "sk-proj-" + fakeToken(alnum, 60, 22)
	if got := findByType(ScanBody(`k="`+openai+`"`, "https://h/x.js"), "OpenAI API Key"); len(got) != 1 {
		t.Errorf("project-scoped OpenAI key not reported: %d matches", len(got))
	}
}

// TestTwilioAccountSIDIsInformational checks that the Account SID, which
// identifies an account but cannot authenticate, is classed as public.
func TestTwilioAccountSIDIsInformational(t *testing.T) {
	sid := "AC" + fakeToken(hexLo, 32, 4)
	got := findByType(ScanBody(`sid="`+sid+`"`, "https://h/x.js"), "Twilio Account SID")
	if len(got) != 1 || got[0].Level != "public-key" {
		t.Errorf("Twilio Account SID = %+v, want one public-key match", got)
	}
}

// TestNewProviderFormats checks the provider patterns added in this change.
// Each synthetic value has the documented prefix and length, so a positive
// match proves the shape. Patterns marked public are checked for their level.
func TestNewProviderFormats(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		public bool
	}{
		{"DigitalOcean Token", "dop_v1_" + fakeToken(hexLo, 64, 31), false},
		{"Linear API Key", "lin_api_" + fakeToken(alnum, 40, 32), false},
		{"Groq API Key", "gsk_" + fakeToken(alnum, 52, 33), false},
		{"Hugging Face Token", "hf_" + fakeToken(alnum, 34, 34), false},
		{"Notion Integration Token", "secret_" + fakeToken(alnum, 43, 35), false},
		{"Figma Personal Access Token", "figd_" + fakeToken(alnum, 40, 36), false},
		{"Supabase Personal Access Token", "sbp_" + fakeToken(hexLo, 40, 37), false},
		{"Doppler Token", "dp.pt." + fakeToken(alnum, 40, 38), false},
		{"HashiCorp Vault Service Token", "hvs." + fakeToken(alnum, 30, 39), false},
		{"Docker Hub Personal Access Token", "dckr_pat_" + fakeToken(alnum, 27, 40), false},
		{"RubyGems API Key", "rubygems_" + fakeToken(hexLo, 48, 41), false},
		{"Pulumi Access Token", "pul-" + fakeToken(hexLo, 40, 42), false},
		{"Razorpay Live Key", "rzp_live_" + fakeToken(alnum, 14, 43), false},
		{"Stripe Webhook Signing Secret", "whsec_" + fakeToken(alnum, 40, 44), false},
		{"Google OAuth Client Secret", "GOCSPX-" + fakeToken(alnum, 28, 45), false},
		{"Grafana Cloud API Key", "glc_" + fakeToken(alnum, 40, 46), false},
		{"Brevo API Key", "xkeysib-" + fakeToken(hexLo, 64, 47) + "-" + fakeToken(alnum, 16, 48), false},
		{"Mapbox Secret Token", "sk.eyJ" + fakeToken(alnum, 30, 49) + "." + fakeToken(alnum, 20, 50), false},
		{"Mapbox Public Token", "pk.eyJ" + fakeToken(alnum, 30, 51) + "." + fakeToken(alnum, 20, 52), true},
		{"Sentry DSN", "https://" + fakeToken(hexLo, 32, 53) + "@o123456.ingest.sentry.io/4505", true},
		{"Google OAuth Client ID", "734291865520-" + fakeToken("abcdefghijklmnopqrstuvwxyz0123456789", 32, 54) + ".apps.googleusercontent.com", true},
	}
	for _, c := range cases {
		matches := findByType(ScanBody(`x = "`+c.value+`";`, "https://h/x.js"), c.name)
		if len(matches) != 1 {
			t.Errorf("%s: got %d matches for %q, want 1", c.name, len(matches), c.value)
			continue
		}
		wantLevel := "secret"
		if c.public {
			wantLevel = "public-key"
		}
		if matches[0].Level != wantLevel {
			t.Errorf("%s: level = %q, want %q", c.name, matches[0].Level, wantLevel)
		}
	}
}

// TestValidateHelpers checks the validator helpers directly on the boundary
// cases the patterns rely on.
func TestValidateHelpers(t *testing.T) {
	if hasLetterAndDigit("undefinedundefined") {
		t.Error("letters-only value passed hasLetterAndDigit")
	}
	if !hasLetterAndDigit("abc123") {
		t.Error("letters-and-digits value failed hasLetterAndDigit")
	}
	if hasDigitOrMixedCase("undefinedundefined") {
		t.Error("lowercase word passed hasDigitOrMixedCase")
	}
	if !hasDigitOrMixedCase("UndefinedUndefined") {
		t.Error("mixed-case value failed hasDigitOrMixedCase")
	}
	if !notPrefix("sk-ant-")("sk-proj-abc") || notPrefix("sk-ant-")("sk-ant-abc") {
		t.Error("notPrefix did not reject the excluded prefix only")
	}
	if validURLPassword("https://user:password@host.test") {
		t.Error("placeholder password passed validURLPassword")
	}
	if !validURLPassword("https://user:Xq7rT2mLp9Wz@host.test") {
		t.Error("generated password failed validURLPassword")
	}
}
