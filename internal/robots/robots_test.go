package robots

import (
	"net/url"
	"testing"
)

// TestParseAppliesWildcardAndAperture checks which groups count: the wildcard
// group and the Aperture group, but not a group addressed to some other bot.
func TestParseAppliesWildcardAndAperture(t *testing.T) {
	body := `
User-agent: Googlebot
Disallow: /google-only/

User-agent: *
Disallow: /private/   # internal tools
Disallow: /tmp

User-agent: Aperture
Disallow: /aperture-only/
`
	p := Parse(body)
	cases := map[string]bool{
		"https://h/private/x":          false,
		"https://h/tmp":                false,
		"https://h/aperture-only/page": false,
		"https://h/google-only/":       true,
		"https://h/public":             true,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := p.Allowed(u); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", raw, got, want)
		}
	}
}

// TestNilPolicyAllowsEverything checks that a missing robots.txt (a nil policy)
// never blocks a crawl.
func TestNilPolicyAllowsEverything(t *testing.T) {
	var p *Policy
	u, _ := url.Parse("https://h/anything")
	if !p.Allowed(u) {
		t.Error("nil policy blocked a URL")
	}
}
