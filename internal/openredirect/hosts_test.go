package openredirect

import (
	"net/url"
	"testing"
)

// TestInetAtonForms checks the inet_aton spellings Oralyzer's payload list
// relies on: decimal, hex, octal, and shortened forms of one IPv4 address.
func TestInetAtonForms(t *testing.T) {
	cases := map[string]string{
		"2130706433":         "127.0.0.1",
		"0x7f000001":         "127.0.0.1",
		"0177.0.0.1":         "127.0.0.1",
		"127.1":              "127.0.0.1",
		"0x7f.1":             "127.0.0.1",
		"0xd83ad6ce":         "216.58.214.206",
		"0330.072.0326.0316": "216.58.214.206",
	}
	for in, want := range cases {
		got := inetAton(in)
		if got == nil || got.String() != want {
			t.Errorf("inetAton(%q) = %v, want %s", in, got, want)
		}
	}
	// Values that are not an inet_aton spelling must not be read as addresses:
	// out-of-range parts, too many parts, and ordinary domain names.
	for _, in := range []string{"256.0.0.1", "1.2.3.4.5", "example.com", "0x", ""} {
		if got := inetAton(in); got != nil {
			t.Errorf("inetAton(%q) = %v, want nil", in, got)
		}
	}
}

// TestCanonicalHost checks that the spellings a browser resolves to one host
// reduce to one canonical string.
func TestCanonicalHost(t *testing.T) {
	cases := map[string]string{
		"127。0。0。1":        "127.0.0.1", // ideographic full stops
		"127．0．0．1":        "127.0.0.1", // fullwidth full stops
		"::ffff:127.0.0.1": "127.0.0.1", // IPv4-mapped IPv6
		"EXAMPLE.com":      "example.com",
		"evil。example":     "evil.example",
	}
	for in, want := range cases {
		if got := canonicalHost(in); got != want {
			t.Errorf("canonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSameCallbackHost checks the callback match a redirect has to pass. Any
// spelling of the callback's host and default port should match, and a
// different host or port should not.
func TestSameCallbackHost(t *testing.T) {
	cases := []struct {
		name, location, callback string
		want                     bool
	}{
		{"decimal IP with port", "https://2130706433:8443/x", "127.0.0.1:8443", true},
		{"hex IP with port", "https://0x7f000001:8443/x", "127.0.0.1:8443", true},
		{"ideographic dot in domain", "https://webhook。site/x", "webhook.site", true},
		{"explicit default port", "https://example.com:443/x", "example.com", true},
		{"missing port vs callback port", "https://127.0.0.1/x", "127.0.0.1:8443", false},
		{"different host", "https://127.0.0.2:8443/x", "127.0.0.1:8443", false},
		{"different port", "https://127.0.0.1:9000/x", "127.0.0.1:8443", false},
	}
	for _, c := range cases {
		loc, err := url.Parse(c.location)
		if err != nil {
			t.Fatalf("%s: url.Parse(%q): %v", c.name, c.location, err)
		}
		if got := sameCallbackHost(loc, c.callback); got != c.want {
			t.Errorf("%s: sameCallbackHost(%q, %q) = %v, want %v", c.name, c.location, c.callback, got, c.want)
		}
	}
}

// TestIPLiteralFormsResolveToCallback checks that every spelling this module
// sends points back at the callback's own IPv4 address. Each form has to
// round-trip through the callback match, or the module could never confirm.
func TestIPLiteralFormsResolveToCallback(t *testing.T) {
	const cb = "127.0.0.1:8443"
	forms := ipLiteralForms(cb)
	if len(forms) != 5 {
		t.Fatalf("ipLiteralForms(%q) returned %d forms, want 5", cb, len(forms))
	}
	for _, f := range forms {
		loc, err := url.Parse("https://" + f.host + "/collab/t/x/")
		if err != nil {
			t.Errorf("%s form %q: url.Parse: %v", f.kind, f.host, err)
			continue
		}
		if !sameCallbackHost(loc, cb) {
			t.Errorf("%s form %q does not resolve to %s", f.kind, f.host, cb)
		}
	}
}

// TestIPLiteralFormsSkipDomains checks that a domain callback produces no IP
// forms, since there is no address to spell out.
func TestIPLiteralFormsSkipDomains(t *testing.T) {
	if got := ipLiteralForms("aperture.example:8443"); got != nil {
		t.Errorf("ipLiteralForms(domain) = %v, want nil", got)
	}
}

// TestFullwidthHost checks that only the host of a poison address is rewritten.
// The path, which carries the identifier, must stay byte-for-byte.
func TestFullwidthHost(t *testing.T) {
	got := fullwidthHost("evil.example:8443/collab/t.k/or-x.1")
	want := "evil。example:8443/collab/t.k/or-x.1"
	if got != want {
		t.Errorf("fullwidthHost = %q, want %q", got, want)
	}
	if got := fullwidthHost("evil.example"); got != "evil。example" {
		t.Errorf("fullwidthHost(no path) = %q", got)
	}
}
