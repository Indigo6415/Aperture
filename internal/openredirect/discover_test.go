package openredirect

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// cdxCollinfo is a collinfo.json listing with one collection, whose CDX index
// is the URL the fake fetcher then serves rows for.
const cdxCollinfo = `[{"cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-34-index"}]`

// stubCommonCrawl swaps commonCrawlFetch for a function of the requested URL
// and restores the real one when the test ends.
func stubCommonCrawl(t *testing.T, fn func(rawURL string) (string, error)) {
	t.Helper()
	orig := commonCrawlFetch
	commonCrawlFetch = func(_ context.Context, rawURL string) (string, error) { return fn(rawURL) }
	t.Cleanup(func() { commonCrawlFetch = orig })
}

// TestFetchCommonCrawlURLsParsesJSONL checks the two-step lookup: the newest
// collection's CDX index is found, then queried, and each JSON line's URL is
// returned in order.
func TestFetchCommonCrawlURLsParsesJSONL(t *testing.T) {
	var queried []string
	stubCommonCrawl(t, func(rawURL string) (string, error) {
		queried = append(queried, rawURL)
		if strings.Contains(rawURL, "collinfo.json") {
			return cdxCollinfo, nil
		}
		return `{"url": "https://example.com/login?next=/account", "status": "200"}
{"url": "https://example.com/page", "status": "200"}
`, nil
	})

	got := fetchCommonCrawlURLs(context.Background(), "example.com")
	want := []string{"https://example.com/login?next=/account", "https://example.com/page"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("fetchCommonCrawlURLs = %v, want %v", got, want)
	}
	if len(queried) != 2 {
		t.Errorf("made %d requests, want 2 (collection list, then index)", len(queried))
	}
	// The domain query must be scoped to the host's own path space and carry
	// no operator credentials, which the fetcher never receives.
	idx := queried[len(queried)-1]
	if !strings.Contains(idx, "url=example.com/*") {
		t.Errorf("index query %q is not scoped to example.com/*", idx)
	}
}

// TestFetchCommonCrawlURLsFailuresReturnNil checks that every failure mode
// (fetch error, empty or malformed collection list, failed index query) yields
// no URLs, so discovery adds nothing rather than aborting the scan.
func TestFetchCommonCrawlURLsFailuresReturnNil(t *testing.T) {
	cases := map[string]func(rawURL string) (string, error){
		"collection fetch error": func(string) (string, error) { return "", errors.New("boom") },
		"empty collection list":  func(string) (string, error) { return "[]", nil },
		"collection not JSON":    func(string) (string, error) { return "<html>", nil },
		"index query error": func(rawURL string) (string, error) {
			if strings.Contains(rawURL, "collinfo.json") {
				return cdxCollinfo, nil
			}
			return "", errors.New("boom")
		},
	}
	for name, fn := range cases {
		stubCommonCrawl(t, fn)
		if got := fetchCommonCrawlURLs(context.Background(), "example.com"); got != nil {
			t.Errorf("%s: fetchCommonCrawlURLs = %v, want nil", name, got)
		}
	}
}

// TestFetchCommonCrawlURLsTruncates checks that no more than
// commonCrawlMaxRows rows are read, even when the index returns more.
func TestFetchCommonCrawlURLsTruncates(t *testing.T) {
	var b strings.Builder
	for i := 0; i < commonCrawlMaxRows+5; i++ {
		fmt.Fprintf(&b, `{"url": "https://example.com/%d", "status": "200"}`+"\n", i)
	}
	stubCommonCrawl(t, func(rawURL string) (string, error) {
		if strings.Contains(rawURL, "collinfo.json") {
			return cdxCollinfo, nil
		}
		return b.String(), nil
	})
	if got := fetchCommonCrawlURLs(context.Background(), "example.com"); len(got) != commonCrawlMaxRows {
		t.Errorf("got %d URLs, want %d", len(got), commonCrawlMaxRows)
	}
}

// TestFetchCommonCrawlURLsSkipsMalformedRows checks that a bad row costs only
// itself: rows that are not JSON or carry no URL are skipped, and the rest are
// kept.
func TestFetchCommonCrawlURLsSkipsMalformedRows(t *testing.T) {
	stubCommonCrawl(t, func(rawURL string) (string, error) {
		if strings.Contains(rawURL, "collinfo.json") {
			return cdxCollinfo, nil
		}
		return "not json\n{\"status\": \"200\"}\n{\"url\": \"https://example.com/\", \"status\": \"200\"}\n", nil
	})
	got := fetchCommonCrawlURLs(context.Background(), "example.com")
	if fmt.Sprint(got) != "[https://example.com/]" {
		t.Errorf("fetchCommonCrawlURLs = %v, want only the valid row", got)
	}
}

// TestDiscoverEndpointsFiltersAndDedups checks the full discovery filter: only
// URLs that take a destination parameter, under the same host, are kept, one
// per path, and the operator's own path is skipped.
func TestDiscoverEndpointsFiltersAndDedups(t *testing.T) {
	rows := []string{
		"https://example.com/login?next=/account",       // kept
		"https://example.com/login?next=/other",         // same path, dropped
		"https://example.com/page",                      // no redirect param, dropped
		"https://other.example/login?next=/account",     // other host, dropped
		"https://example.com/out?url=https://evil.test", // kept
		"https://example.com/search?q=next-day",         // not a param match
		"https://example.com/go?continue=/home",         // kept
		"https://example.com/account?next=/x",           // the operator's own path, dropped
	}
	stubCommonCrawl(t, func(rawURL string) (string, error) {
		if strings.Contains(rawURL, "collinfo.json") {
			return cdxCollinfo, nil
		}
		var b strings.Builder
		for _, r := range rows {
			fmt.Fprintf(&b, `{"url": %q, "status": "200"}`+"\n", r)
		}
		return b.String(), nil
	})

	target, _ := url.Parse("https://example.com/account?next=/home")
	got := discoverEndpoints(context.Background(), target)
	want := []string{
		"https://example.com/login?next=/account",
		"https://example.com/out?url=https://evil.test",
		"https://example.com/go?continue=/home",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("discoverEndpoints = %v, want %v", got, want)
	}
}

// TestDiscoverEndpointsCapped checks that a host with many redirect-shaped
// paths yields at most maxDiscoveredEndpoints endpoints.
func TestDiscoverEndpointsCapped(t *testing.T) {
	stubCommonCrawl(t, func(rawURL string) (string, error) {
		if strings.Contains(rawURL, "collinfo.json") {
			return cdxCollinfo, nil
		}
		var b strings.Builder
		for i := 0; i < 20; i++ {
			fmt.Fprintf(&b, `{"url": "https://example.com/r%d?next=/x", "status": "200"}`+"\n", i)
		}
		return b.String(), nil
	})
	target, _ := url.Parse("https://example.com/")
	if got := discoverEndpoints(context.Background(), target); len(got) != maxDiscoveredEndpoints {
		t.Errorf("got %d endpoints, want %d", len(got), maxDiscoveredEndpoints)
	}
}

// TestRedirectDorksMatch checks the dork list on its own: the destination
// parameter names Oralyzer looks for match, and an unrelated query does not.
func TestRedirectDorksMatch(t *testing.T) {
	for _, u := range []string{
		"https://example.com/a?next=/x",
		"https://example.com/a?redirect_uri=https://x",
		"https://example.com/redirect/https://x",
		"https://example.com/a?NEXTURL=/x",
	} {
		if !redirectDorks.MatchString(u) {
			t.Errorf("redirectDorks should match %q", u)
		}
	}
	if redirectDorks.MatchString("https://example.com/a?page=2") {
		t.Error("redirectDorks should not match an unrelated query")
	}
}
