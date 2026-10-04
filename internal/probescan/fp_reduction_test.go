package probescan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// labelsContaining returns the findings whose label contains sub.
func labelsContaining(findings []Finding, sub string) []Finding {
	var out []Finding
	for _, f := range findings {
		if strings.Contains(f.Label, sub) {
			out = append(out, f)
		}
	}
	return out
}

// httpResultFor builds the response shape the validators read from a body and
// content type, without a server round trip.
func httpResultFor(status int, contentType, body string) *httpResult {
	h := http.Header{}
	h.Set("Content-Type", contentType)
	return &httpResult{StatusCode: status, Header: h, Body: []byte(body), Text: body}
}

// TestAdminPanelsIgnoreCatchAllStatuses checks that a host answering every path
// with the same 200 shell or the same 403 block page reports no admin panel,
// since the old module judged each response on its own.
func TestAdminPanelsIgnoreCatchAllStatuses(t *testing.T) {
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><body>Request blocked by the edge firewall.</body></html>")
	}))
	defer forbidden.Close()
	if got := runModule(t, forbidden.URL, "admin_panels"); len(got) != 0 {
		t.Errorf("403 catch-all reported %d admin panels, want 0: %+v", len(got), got)
	}

	shell := fixtureServer(t, nil)
	if got := runModule(t, shell.URL, "admin_panels"); len(got) != 0 {
		t.Errorf("200 catch-all reported %d admin panels, want 0: %+v", len(got), got)
	}
}

// TestAdminPanelConfidenceFollowsEvidence checks that a product signature or a
// password field confirms a panel as likely, and that a bare 200 with neither is
// only a heuristic lead.
func TestAdminPanelConfidenceFollowsEvidence(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/manager/html": {"text/html", "<html><title>Tomcat Web Application Manager</title></html>"},
		"/admin/login":  {"text/html", `<html><form><input type="password" name="pw"></form></html>`},
		"/admin":        {"text/html", "<html><h1>Admin dashboard panel</h1></html>"},
	})
	findings := runModule(t, srv.URL, "admin_panels")

	if got := labelsContaining(findings, "Tomcat manager panel accessible"); len(got) != 1 || got[0].Confidence != ConfidenceLikely {
		t.Errorf("Tomcat signature finding = %+v, want one likely finding", got)
	}
	if got := labelsContaining(findings, "Generic admin login accessible"); len(got) != 1 || got[0].Confidence != ConfidenceLikely {
		t.Errorf("password-field finding = %+v, want one likely finding", got)
	}
	if got := labelsContaining(findings, "Generic admin panel returned 200 at"); len(got) != 1 || got[0].Confidence != ConfidenceHeuristic {
		t.Errorf("bare-200 finding = %+v, want one heuristic finding", got)
	}
}

// TestWordPressAuthorEnumerationFollowsRedirect checks the author check on a
// WordPress site that redirects /?author=1 to /author/<slug>/. The old check
// never followed the redirect, so it could not see the slug and never fired.
func TestWordPressAuthorEnumerationFollowsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && r.URL.RawQuery == "":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><link href="/wp-content/themes/x/style.css"></html>`)
		case r.URL.Path == "/" && r.URL.RawQuery == "author=1":
			http.Redirect(w, r, "/author/admin/", http.StatusMovedPermanently)
		case r.URL.Path == "/author/admin/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><h1>Author archive for the admin account</h1></html>")
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><h1>Nothing lives at this address</h1></html>")
		}
	}))
	defer srv.Close()

	findings := labelsContaining(runModule(t, srv.URL, "wordpress"), "WordPress author enumeration")
	if len(findings) != 1 {
		t.Fatalf("author enumeration findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Detail, "admin") {
		t.Errorf("detail does not name the author slug: %q", findings[0].Detail)
	}
}

// TestWordPressRESTUsersNeedsSlugs checks that the REST user list is judged by
// its JSON shape: an array of objects carrying a slug.
func TestWordPressRESTUsersNeedsSlugs(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/":                    {"text/html", `<html><link href="/wp-content/x.css"></html>`},
		"/wp-json/wp/v2/users": {"application/json", `[{"id":1,"name":"Ada","slug":"ada"}]`},
	})
	if got := labelsContaining(runModule(t, srv.URL, "wordpress"), "REST API user enumeration"); len(got) == 0 {
		t.Error("REST user list with slugs was not reported")
	}

	noSlug := fixtureServer(t, map[string][2]string{
		"/":                    {"text/html", `<html><link href="/wp-content/x.css"></html>`},
		"/wp-json/wp/v2/users": {"application/json", `[{"id":1,"name":"Ada"}]`},
	})
	if got := labelsContaining(runModule(t, noSlug.URL, "wordpress"), "REST API user enumeration"); len(got) != 0 {
		t.Errorf("user list without slugs reported: %+v", got)
	}
}

// TestCVSEntriesNeedsRecordFormat checks that /CVS/Entries is matched by its
// record shape, not by any text containing a slash.
func TestCVSEntriesNeedsRecordFormat(t *testing.T) {
	prose := fixtureServer(t, map[string][2]string{
		"/CVS/Entries": {"text/plain", "notes about the project/for later/today"},
	})
	if got := labelsContaining(runModule(t, prose.URL, "version_control"), "CVS entries file"); len(got) != 0 {
		t.Errorf("prose with slashes reported as CVS/Entries: %+v", got)
	}

	real := fixtureServer(t, map[string][2]string{
		"/CVS/Entries": {"text/plain", "/README/1.1/Mon Jan  1 00:00:00 2024//\nD/src////\n"},
	})
	if got := labelsContaining(runModule(t, real.URL, "version_control"), "CVS entries file"); len(got) != 1 {
		t.Errorf("real CVS/Entries not reported: %+v", got)
	}
}

// TestAPIRootRejectsHTMLWithBraces checks that a plain HTML page containing
// braces (inline script) is not an API root, while a JSON body is.
func TestAPIRootRejectsHTMLWithBraces(t *testing.T) {
	html := fixtureServer(t, map[string][2]string{
		"/api/v1/users": {"text/html", `<html><script>var cfg={debug:true};</script><p>Users page</p></html>`},
	})
	if got := labelsContaining(runModule(t, html.URL, "api_endpoints"), "User list endpoint"); len(got) != 0 {
		t.Errorf("HTML page with braces reported as an API endpoint: %+v", got)
	}

	json := fixtureServer(t, map[string][2]string{
		"/api/v1/users": {"application/json", `{"users":[]}`},
	})
	if got := labelsContaining(runModule(t, json.URL, "api_endpoints"), "User list endpoint"); len(got) != 1 {
		t.Errorf("JSON user list not reported: %+v", got)
	}
}

// TestGraphQLNeedsJSONEnvelope checks that a GraphQL endpoint is confirmed by
// a JSON data or errors member, not by the word "data" appearing in a page.
func TestGraphQLNeedsJSONEnvelope(t *testing.T) {
	page := fixtureServer(t, map[string][2]string{
		"/graphql": {"text/html", "<html><p>Your metadata and data policy</p></html>"},
	})
	if got := labelsContaining(runModule(t, page.URL, "api_endpoints"), "GraphQL endpoint"); len(got) != 0 {
		t.Errorf("HTML page mentioning data reported as GraphQL: %+v", got)
	}

	gql := fixtureServer(t, map[string][2]string{
		"/graphql": {"application/json", `{"errors":[{"message":"Must provide query string."}]}`},
	})
	if got := labelsContaining(runModule(t, gql.URL, "api_endpoints"), "GraphQL endpoint"); len(got) != 1 {
		t.Errorf("GraphQL error envelope not reported: %+v", got)
	}
}

// TestHealthAndRobotsRequireTheirFormat checks the health and robots validators
// on prose and on the real format.
func TestHealthAndRobotsRequireTheirFormat(t *testing.T) {
	if validHealthBody(httpResultFor(200, "text/html", "<html>Status: ok, book your visit</html>")) {
		t.Error("HTML page mentioning ok was accepted as a health check")
	}
	if !validHealthBody(httpResultFor(200, "application/json", `{"status":"UP"}`)) {
		t.Error("JSON status object was not accepted as a health check")
	}
	if !validHealthBody(httpResultFor(200, "text/plain", "OK\n")) {
		t.Error("bare OK body was not accepted as a health check")
	}

	if validRegexp(robotsDirective)(httpResultFor(200, "text/plain", "This page is allowed to be read by anyone.")) {
		t.Error("prose containing 'allowed' was accepted as robots.txt")
	}
	if !validRegexp(robotsDirective)(httpResultFor(200, "text/plain", "User-agent: *\nDisallow: /private\n")) {
		t.Error("real robots.txt was not accepted")
	}
}

// TestWPConfigSourceOnly checks that a WordPress config is reported only when
// the raw PHP source leaks, and that an HTML page mentioning DB_PASSWORD is not.
func TestWPConfigSourceOnly(t *testing.T) {
	src := fixtureServer(t, map[string][2]string{
		"/wp-config.php.bak": {"text/plain", "<?php\ndefine('DB_PASSWORD', 'x');\n"},
	})
	if got := labelsContaining(runModule(t, src.URL, "sensitive_files"), "WordPress config backup"); len(got) != 1 {
		t.Errorf("leaked wp-config source not reported: %+v", got)
	}

	page := fixtureServer(t, map[string][2]string{
		"/wp-config.php.bak": {"text/html", "<html>docs: set DB_PASSWORD in your config</html>"},
	})
	if got := labelsContaining(runModule(t, page.URL, "sensitive_files"), "WordPress config backup"); len(got) != 0 {
		t.Errorf("HTML page mentioning DB_PASSWORD reported as config backup: %+v", got)
	}
}

// TestDSStoreIsReportedByOneModule checks that .DS_Store is reported by the
// sensitive-files module and not again by dev artifacts.
func TestDSStoreIsReportedByOneModule(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/.DS_Store": {"application/octet-stream", "\x00\x00\x00\x01Bud1" + strings.Repeat("\x00", 64)},
	})
	if got := labelsContaining(runModule(t, srv.URL, "sensitive_files"), "macOS DS_Store file"); len(got) != 1 {
		t.Errorf("sensitive_files did not report .DS_Store: %+v", got)
	}
	if got := labelsContaining(runModule(t, srv.URL, "dev_artifacts"), "DS_Store"); len(got) != 0 {
		t.Errorf("dev_artifacts reported .DS_Store a second time: %+v", got)
	}
}

// TestVimSwapFileIsDetected checks the Vim swap magic that a swap copy of
// source code begins with.
func TestVimSwapFileIsDetected(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/index.php.swp": {"application/octet-stream", "b0VIM 8.0\x00\x00" + strings.Repeat("x", 40)},
	})
	if got := labelsContaining(runModule(t, srv.URL, "dev_artifacts"), "Vim swap file"); len(got) != 1 {
		t.Errorf("Vim swap file not reported: %+v", got)
	}
}

// TestDjangoSettingsRequireSettingsShape checks that a settings module is
// reported when it defines SECRET_KEY with INSTALLED_APPS or DATABASES, and
// that an unrelated Python file at the same kind of path is not.
func TestDjangoSettingsRequireSettingsShape(t *testing.T) {
	srv := fixtureServer(t, map[string][2]string{
		"/settings.py":       {"text/plain", "SECRET_KEY = 'abc'\nINSTALLED_APPS = []\n"},
		"/local_settings.py": {"text/plain", "print('hello')\n"},
	})
	findings := runModule(t, srv.URL, "sensitive_files")
	if got := labelsContaining(findings, "Django settings module"); len(got) != 1 {
		t.Errorf("Django settings not reported: %+v", got)
	}
	if got := labelsContaining(findings, "Django local settings"); len(got) != 0 {
		t.Errorf("unrelated Python file reported as settings: %+v", got)
	}
}

// TestTraversalIgnoresLocalhostEcho checks that a response containing the
// word localhost does not count as hosts-file traversal. The old indicator was
// that bare word, which ordinary pages echo.
func TestTraversalIgnoresLocalhostEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "127.0.0.1 localhost\nlinks to localhost:8080 for dev\n")
	}))
	defer srv.Close()

	client := newProbeClient(16, nil)
	target := paramTarget{url: srv.URL + "/item?id=1", params: url.Values{"id": {"1"}}}
	if got := checkPathTraversal(context.Background(), client, target); len(got) != 0 {
		t.Errorf("page echoing localhost reported as traversal: %+v", got)
	}
}

// TestSSTIRequiresTheUniqueProduct checks that a template result is reported
// only when the unusual product appears, and that the old 15129 value, which
// ordinary pages can contain, no longer triggers it.
func TestSSTIRequiresTheUniqueProduct(t *testing.T) {
	evaluates := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "{{1337*7331}}" {
			fmt.Fprint(w, "result: 9801547")
			return
		}
		fmt.Fprint(w, "result: plain")
	}))
	defer evaluates.Close()

	client := newProbeClient(16, nil)
	target := paramTarget{url: evaluates.URL + "/render?id=1", params: url.Values{"id": {"1"}}}
	if got := checkSSTI(context.Background(), client, target); len(got) == 0 {
		t.Error("evaluated template result was not reported")
	}

	static := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "order total 15129 units")
	}))
	defer static.Close()
	target.url = static.URL + "/render?id=1"
	if got := checkSSTI(context.Background(), client, target); len(got) != 0 {
		t.Errorf("unrelated 15129 on a page reported as SSTI: %+v", got)
	}
}

// TestWeakRSABits checks the key-size helper on a 1024-bit and a 2048-bit RSA
// certificate: only the short key is weak.
func TestWeakRSABits(t *testing.T) {
	for _, tc := range []struct {
		bits int
		weak bool
	}{{1024, true}, {2048, false}} {
		key, err := rsa.GenerateKey(rand.Reader, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "fixture"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		bits, weak := weakRSABits(cert)
		if weak != tc.weak {
			t.Errorf("%d-bit key: weak = %v, want %v", tc.bits, weak, tc.weak)
		}
		if weak && bits != tc.bits {
			t.Errorf("%d-bit key reported as %d bits", tc.bits, bits)
		}
	}
}

// TestCatchAllHomepageFallback checks the soft-404 fallback: when the random
// path profile is unstable, a 200 identical to the homepage is treated as the
// catch-all, and a stable profile is never overridden by the homepage.
func TestCatchAllHomepageFallback(t *testing.T) {
	const home = `<html><title>Acme</title><body>Welcome to the Acme portal and its shared front end</body></html>`
	homeObs := fingerprint.Observe(200, "text/html", []byte(home))

	unstable := newProbeClient(4, nil)
	unstable.profile = fingerprint.NewProfile(nil)
	unstable.home = &homeObs
	if !unstable.isCatchAll(httpResultFor(200, "text/html", home)) {
		t.Error("homepage-identical 200 not treated as catch-all on an unstable host")
	}
	robots := httpResultFor(200, "text/plain", "User-agent: *\nDisallow: /private\n")
	if unstable.isCatchAll(robots) {
		t.Error("robots.txt treated as catch-all because the homepage exists")
	}

	stableSamples := []fingerprint.Observation{
		fingerprint.Observe(404, "text/html", []byte("not found page one")),
		fingerprint.Observe(404, "text/html", []byte("not found page one")),
	}
	stable := newProbeClient(4, nil)
	stable.profile = fingerprint.NewProfile(stableSamples)
	stable.home = &homeObs
	if stable.isCatchAll(httpResultFor(200, "text/html", home)) {
		t.Error("homepage fallback overrode a stable profile")
	}
}

// TestPrimeCatchAllRecordsHomepage checks that priming a client on a site that
// serves a 200 homepage records that homepage as the fallback baseline.
func TestPrimeCatchAllRecordsHomepage(t *testing.T) {
	srv := fixtureServer(t, nil)
	client := newProbeClient(4, nil)
	primeCatchAll(context.Background(), client, &Target{URL: srv.URL, Hostname: "fixture"}, nil)
	if client.home == nil {
		t.Fatal("homepage baseline not recorded for a 200 homepage")
	}
}
