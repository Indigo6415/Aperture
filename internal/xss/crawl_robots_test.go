package xss

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestCrawlHonorsRobotsTxt checks that link discovery skips a disallowed
// directory while still following ordinary links on the same page.
func TestCrawlHonorsRobotsTxt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /private/\n")
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><a href="/public">a</a><a href="/private/secret">b</a></html>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html>page</html>")
		}
	}))
	defer srv.Close()

	seed, _ := url.Parse(srv.URL + "/")
	res, err := crawl(context.Background(), srv.Client(), seed, Request{URL: srv.URL + "/", RecursionDepth: 1, MaxPages: 10})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	var sawPublic, sawPrivate bool
	for _, p := range res.PagesScanned {
		sawPublic = sawPublic || strings.HasSuffix(p, "/public")
		sawPrivate = sawPrivate || strings.Contains(p, "/private/")
	}
	if !sawPublic {
		t.Errorf("ordinary link was not followed; scanned %v", res.PagesScanned)
	}
	if sawPrivate {
		t.Errorf("disallowed path was crawled: %v", res.PagesScanned)
	}
}
