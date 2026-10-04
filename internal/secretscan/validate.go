package secretscan

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode"
)

// Pattern validators run after a regex has matched and before a value is
// kept. Each one rejects a shape that the regex alone cannot exclude, such as
// a plain English word that happens to fit a keyword-anchored pattern, a JWT
// whose header is not JSON, or a URL whose password is a placeholder word.

// hasLetterAndDigit reports whether s contains at least one letter and at
// least one digit. Generated tokens almost always contain both, while English
// words, identifiers, and CSS class names usually contain only letters.
func hasLetterAndDigit(s string) bool {
	var letter, digit bool
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsLetter(r):
			letter = true
		}
		if letter && digit {
			return true
		}
	}
	return false
}

// hasDigitOrMixedCase reports whether s has a digit or both an upper- and a
// lower-case letter. An all-lowercase word such as "undefinedundefined" has
// neither, so it is rejected, while most random tokens pass.
func hasDigitOrMixedCase(s string) bool {
	var upper, lower bool
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			return true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		}
	}
	return upper && lower
}

// entropyAtLeast returns a validator that requires Shannon entropy of at
// least min bits per character. Random tokens sit well above 3 bits; repeated
// or wordy values sit well below it.
func entropyAtLeast(min float64) func(string) bool {
	return func(s string) bool {
		return shannonEntropy(s) >= min
	}
}

// allOf combines validators; a value passes only when every one passes.
func allOf(validators ...func(string) bool) func(string) bool {
	return func(s string) bool {
		for _, v := range validators {
			if !v(s) {
				return false
			}
		}
		return true
	}
}

// notPrefix returns a validator rejecting values that start with prefix. It
// separates patterns whose character class overlaps another provider's
// format, such as the OpenAI "sk-" pattern matching Anthropic's "sk-ant-".
func notPrefix(prefix string) func(string) bool {
	return func(s string) bool {
		return !strings.HasPrefix(s, prefix)
	}
}

// validJWTHeader requires the first dot-separated segment of a JWT-shaped
// value to base64url-decode to a JSON object with an "alg" member. That is the
// one field every real JWT header carries, so a random dotted token fails.
func validJWTHeader(s string) bool {
	seg := s
	if i := strings.IndexByte(s, '.'); i >= 0 {
		seg = s[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return false
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw, &header); err != nil {
		return false
	}
	_, ok := header["alg"]
	return ok
}

// placeholderPasswords are credential words that appear in documentation and
// tutorials far more often than in live URLs.
var placeholderPasswords = []string{
	"password", "passwd", "pass", "pwd", "secret", "changeme", "example",
	"username", "user", "yourpassword", "your-password", "your_password",
	"xxx", "***", "...",
}

// validURLPassword checks the password inside a scheme://user:pass@host match.
// It rejects a missing password, a template reference, and the placeholder
// words above, so "https://user:password@localhost" is not reported.
func validURLPassword(s string) bool {
	scheme := strings.Index(s, "://")
	if scheme < 0 {
		return false
	}
	rest := s[scheme+3:]
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return false
	}
	userinfo := rest[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 {
		return false
	}
	password := userinfo[colon+1:]
	if len(password) < 3 || strings.HasPrefix(password, "$") || strings.HasPrefix(password, "{") {
		return false
	}
	lower := strings.ToLower(password)
	for _, p := range placeholderPasswords {
		if lower == p {
			return false
		}
	}
	return true
}
