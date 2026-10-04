package breach

import (
	"context"
	"net/url"
	"testing"
)

// TestLookupRequiresAPIKey checks the lookup refuses to call out without a key,
// so a missing setting fails with a clear message rather than an unauthorized request.
func TestLookupRequiresAPIKey(t *testing.T) {
	if _, err := Lookup(context.Background(), "a@example.com", ""); err == nil {
		t.Fatal("expected an error when no API key is configured")
	}
}

// TestCollectEmailsKeepsRealAddressesAndDropsAssetNames checks the crawl only
// records plausible addresses, and that a static-asset name like logo@2x.png
// (which the regex can match) is discarded instead of being reported as an email.
func TestCollectEmailsKeepsRealAddressesAndDropsAssetNames(t *testing.T) {
	into := map[string]map[string]bool{}
	collectEmails("Contact Admin@Acme-Corp.io or logo@2x.png today", "https://x.test/", into)

	if _, ok := into["admin@acme-corp.io"]; !ok {
		t.Fatalf("real address missing (lower-cased): %v", into)
	}
	for e := range into {
		if e == "logo@2x.png" {
			t.Fatal("an asset filename was reported as an email address")
		}
	}
	if !into["admin@acme-corp.io"]["https://x.test/"] {
		t.Fatal("address not attributed to the page it was found on")
	}
}

// TestCrawlSameOrigin checks the crawler follows links only to the seed's own
// host, so a crawl can't wander off to third-party sites.
func TestCrawlSameOrigin(t *testing.T) {
	base, _ := url.Parse("https://app.example.com/")
	same, _ := url.Parse("https://APP.example.com/login")
	other, _ := url.Parse("https://evil.example.net/")
	if !crawlSameOrigin(base, same) {
		t.Error("same host (different case) should be followed")
	}
	if crawlSameOrigin(base, other) {
		t.Error("a different host must not be followed")
	}
}
