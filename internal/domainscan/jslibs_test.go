package domainscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// scriptAt builds a scriptFile for a URL and body, for the in-process checks.
func scriptAt(url, body string) scriptFile {
	return scriptFile{URL: url, Body: []byte(body)}
}

// TestJSLibraryBannerDetection checks that a banner version below an advisory's
// fix is reported with its CVEs, and that a fixed version is not.
func TestJSLibraryBannerDetection(t *testing.T) {
	old := libraryFindings(scriptAt("https://h/js/app.js", "/*! jQuery v1.12.4 | (c) OpenJS */\nvar a=1;"))
	if len(old) != 1 {
		t.Fatalf("jQuery 1.12.4 findings = %d, want 1", len(old))
	}
	if !strings.Contains(old[0].Detail, "CVE-2020-11022") || old[0].Severity != "medium" {
		t.Errorf("jQuery 1.12.4 finding = %+v, want CVE-2020-11022 at medium", old[0])
	}
	if old[0].Evidence != "jQuery@1.12.4" {
		t.Errorf("evidence = %q, want jQuery@1.12.4", old[0].Evidence)
	}

	if got := libraryFindings(scriptAt("https://h/js/app.js", "/*! jQuery v3.6.0 | (c) OpenJS */")); len(got) != 0 {
		t.Errorf("jQuery 3.6.0 (fixed) reported: %+v", got)
	}
}

// TestJSLibraryFilenameFallback checks that a minified build with no banner is
// versioned from its file name, and that a version found in neither is not reported.
func TestJSLibraryFilenameFallback(t *testing.T) {
	got := libraryFindings(scriptAt("https://h/static/jquery-1.8.3.min.js", "!function(){}();"))
	if len(got) != 1 {
		t.Fatalf("jquery-1.8.3.min.js findings = %d, want 1", len(got))
	}
	// 1.8.3 is below both the 1.9.0 and 3.5.0 fixes, so both CVEs are listed in one finding.
	if !strings.Contains(got[0].Detail, "CVE-2012-6708") || !strings.Contains(got[0].Detail, "CVE-2020-11023") {
		t.Errorf("detail = %q, want both jQuery advisories", got[0].Detail)
	}
	if got := libraryFindings(scriptAt("https://h/static/jquery.min.js", "!function(){}();")); len(got) != 0 {
		t.Errorf("unversioned jquery file reported: %+v", got)
	}
}

// TestJSLibraryBranchLimitedAdvisory checks that a Bootstrap advisory applies
// only to its own major branch: 3.3.7 and 4.2.0 are affected, 4.3.1 and 5.0.0 are not.
func TestJSLibraryBranchLimitedAdvisory(t *testing.T) {
	cases := map[string]bool{
		"/*! Bootstrap v3.3.7 */": true,
		"/*! Bootstrap v4.2.0 */": true,
		"/*! Bootstrap v4.3.1 */": false,
		"/*! Bootstrap v5.0.0 */": false,
	}
	for banner, want := range cases {
		got := len(libraryFindings(scriptAt("https://h/b.js", banner))) > 0
		if got != want {
			t.Errorf("%q: flagged = %v, want %v", banner, got, want)
		}
	}
}

// TestJSLibraryLodashNeedsItsOwnMarker checks that Lodash's VERSION assignment
// is trusted only in a file that names lodash, so an unrelated VERSION constant
// is not read as a Lodash version.
func TestJSLibraryLodashNeedsItsOwnMarker(t *testing.T) {
	lodash := scriptAt("https://h/js/lodash.min.js", `/** lodash build */ var VERSION = '4.17.20';`)
	if got := libraryFindings(lodash); len(got) != 1 || !strings.Contains(got[0].Detail, "CVE-2021-23337") {
		t.Errorf("lodash 4.17.20 = %+v, want one CVE-2021-23337 finding", got)
	}

	unrelated := scriptAt("https://h/js/app.js", `var VERSION = '1.0.0';`)
	if got := libraryFindings(unrelated); len(got) != 0 {
		t.Errorf("unrelated VERSION constant reported as lodash: %+v", got)
	}

	fixed := scriptAt("https://h/js/lodash.min.js", `/** lodash build */ var VERSION = '4.17.21';`)
	if got := libraryFindings(fixed); len(got) != 0 {
		t.Errorf("lodash 4.17.21 (fixed) reported: %+v", got)
	}
}

// TestJSLibraryBannerWindow checks that a version string buried past the banner
// window, deep in a large bundle, is not taken as the library version.
func TestJSLibraryBannerWindow(t *testing.T) {
	body := strings.Repeat("x", jsBannerWindow+100) + "jQuery v1.8.0"
	if got := libraryFindings(scriptAt("https://h/bundle.js", body)); len(got) != 0 {
		t.Errorf("version past the banner window was used: %+v", got)
	}
}

// TestJSLibraryMomentAndUnrelatedCode checks a Moment.js banner, and that
// ordinary code naming a library without a version is not reported.
func TestJSLibraryMomentAndUnrelatedCode(t *testing.T) {
	// One finding per library version, carrying both advisories it falls under.
	moment := libraryFindings(scriptAt("https://h/m.js", "//! moment.js\n//! version : 2.29.1\n"))
	if len(moment) != 1 || !strings.Contains(moment[0].Detail, "CVE-2022-31129") || !strings.Contains(moment[0].Detail, "CVE-2022-24785") {
		t.Errorf("moment 2.29.1 = %+v, want one finding listing both advisories", moment)
	}
	if got := libraryFindings(scriptAt("https://h/app.js", "// uses jQuery and Bootstrap components\nfunction f(){}")); len(got) != 0 {
		t.Errorf("unversioned library mention reported: %+v", got)
	}
}

// TestScratchNameIsUnique checks that scripts sharing a base name (or differing
// only by case) get distinct scratch files, so none overwrites another. The old
// naming could write two scripts to one file.
func TestScratchNameIsUnique(t *testing.T) {
	used := map[string]bool{}
	got := []string{
		scratchName(used, "https://a.test/x/app.js"),
		scratchName(used, "https://b.test/y/app.js"),
		scratchName(used, "https://c.test/z/APP.js"),
		scratchName(used, "https://d.test/bundle"),
		scratchName(used, "https://e.test/bundle"),
	}
	want := []string{"app.js", "app-1.js", "APP-2.js", "bundle.js", "bundle-1.js"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("name %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSharedCrawlRunsOnce checks that two modules in one scan share a single
// crawl of the site, rather than each walking it again.
func TestSharedCrawlRunsOnce(t *testing.T) {
	var homeHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			homeHits.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/js/jquery-1.12.4.min.js"></script></html>`)
		case "/js/jquery-1.12.4.min.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, "/*! jQuery v1.12.4 */ var x=1;")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx := withCrawlMemo(context.Background())
	target := ResolveTarget(srv.URL)
	opts := Options{}

	findings, err := runJSLibrariesModule(ctx, target, opts)
	if err != nil {
		t.Fatalf("runJSLibrariesModule: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("library module findings = %d, want 1", len(findings))
	}
	// A second consumer in the same scan reuses the memo instead of crawling again.
	_ = sharedCrawl(ctx, target, opts)
	if n := homeHits.Load(); n != 1 {
		t.Errorf("homepage fetched %d times in one scan, want 1", n)
	}
}

// TestSharedCrawlWithoutMemoCrawlsEachCall checks that a module invoked outside
// a scan (no memo in the context) still works, crawling for each call.
func TestSharedCrawlWithoutMemoCrawlsEachCall(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>plain</html>")
	}))
	defer srv.Close()

	target := ResolveTarget(srv.URL)
	sharedCrawl(context.Background(), target, Options{})
	sharedCrawl(context.Background(), target, Options{})
	if n := hits.Load(); n != 2 {
		t.Errorf("homepage fetched %d times without a memo, want 2", n)
	}
}

// TestJSLibrariesModuleIsRegistered checks the library module appears in the
// registry alongside retire, so a scan runs it.
func TestJSLibrariesModuleIsRegistered(t *testing.T) {
	found := false
	for _, m := range Modules() {
		if m.ID == "js_libraries" {
			found = true
		}
	}
	if !found {
		t.Error("js_libraries module is not registered")
	}
}
