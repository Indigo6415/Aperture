package breach

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestValidateEmailRejectsNonAddresses checks that a value that cannot be an
// address is refused before any request is sent, and a plain address passes.
func TestValidateEmailRejectsNonAddresses(t *testing.T) {
	for _, bad := range []string{"", "no-at-sign", "@nodomainlocal", "user@", "user@nodot", "us er@x.io"} {
		if err := validateEmail(bad); err == nil {
			t.Errorf("validateEmail(%q) = nil, want error", bad)
		}
	}
	if err := validateEmail("dev@acme.io"); err != nil {
		t.Errorf("validateEmail(valid) = %v, want nil", err)
	}
}

// TestLookupRejectsMalformedEmailBeforeRequest checks that a malformed address
// fails fast with a clear error rather than costing a rate-limited API call.
func TestLookupRejectsMalformedEmailBeforeRequest(t *testing.T) {
	if _, err := Lookup(context.Background(), "not-an-email", "key"); err == nil {
		t.Fatal("expected an error for a malformed address")
	}
}

// TestHIBPClientVerifiesTLS checks that the HIBP client uses the default
// transport, which verifies certificates. It must not use the netgov transport,
// which skips verification for lab targets, because the request carries the
// account's API key.
func TestHIBPClientVerifiesTLS(t *testing.T) {
	if hibpClient.Transport != nil {
		t.Fatal("HIBP client has a custom transport; it must keep default TLS verification")
	}
	if hibpClient.Timeout <= 0 {
		t.Fatal("HIBP client has no timeout")
	}
}

// TestNormalizeEmailDropsNonAddresses checks the filters that keep version
// strings, asset names, data files, and placeholder domains out of the results.
func TestNormalizeEmailDropsNonAddresses(t *testing.T) {
	for _, bad := range []string{
		"pkg@1.2.3",          // version string: numeric TLD
		"icon@2.0",           // image density suffix
		"user@example.com",   // reserved documentation domain
		"user@example.org",   // reserved documentation domain
		"you@yourdomain.com", // template placeholder
		"config@data.json",   // data file
		"logo@2x.png",        // image asset
		"module@page.html",   // markup file
	} {
		if got := normalizeEmail(bad); got != "" {
			t.Errorf("normalizeEmail(%q) = %q, want dropped", bad, got)
		}
	}
	if got := normalizeEmail("Dev@Acme.IO"); got != "dev@acme.io" {
		t.Errorf("normalizeEmail(real) = %q, want dev@acme.io", got)
	}
}

// TestCrawlFetchHonorsHostHeader checks that a Host override in the saved
// headers reaches the server, which a plain Header.Set would silently drop.
func TestCrawlFetchHonorsHostHeader(t *testing.T) {
	var seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := crawlFetch(context.Background(), crawlClient(), srv.URL+"/", map[string]string{"Host": "app.internal.test"}); err != nil {
		t.Fatalf("crawlFetch: %v", err)
	}
	if seenHost != "app.internal.test" {
		t.Errorf("server saw Host %q, want the override", seenHost)
	}
}
