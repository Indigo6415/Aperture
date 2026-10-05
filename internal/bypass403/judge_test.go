package bypass403

import (
	"context"

	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// TestMain points the Wayback Machine check at an offline stub for the whole
// package, so no test depends on archive.org being reachable (or on what it
// happens to hold for a httptest URL).
func TestMain(m *testing.M) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"archived_snapshots":{}}`)
	}))
	waybackEndpoint = stub.URL
	code := m.Run()
	stub.Close()
	os.Exit(code)
}

// acmeHome is the protected site's own front page in these fixtures.
const acmeHome = `<!doctype html><html><head><title>Acme Store</title></head><body>
<p>Welcome to the Acme store. Browse our catalogue of widgets, gadgets and accessories today.</p></body></html>`

// softNotFound is what a catch-all host serves for every path it doesn't know
// about: a 200 "not found" page rather than a real 404.
const softNotFound = `<!doctype html><html><head><title>Page not found</title></head><body>
<h1>Not Found</h1><p>The page you requested could not be found on this server. Check the address and try again.</p></body></html>`

// adminConsole is the protected content a successful bypass exposes.
const adminConsole = `<!doctype html><html><head><title>Admin console</title></head><body>
<p>Users: alice, bob, carol. Delete account. Rotate API keys. Manage billing settings.</p></body></html>`

// denialPage is a block page with no denial phrase at all, so only the
// same-page comparison can recognize it as a denial.
const denialPage = `<!doctype html><html><head><title>Restricted</title></head><body>
<h1>Access Restricted</h1><p>This resource is protected. Please contact the site owner for access to this area of the site.</p></body></html>`

// findAttempt returns the attempt with the given ID, failing the test if the
// run did not produce it.
func findAttempt(t *testing.T, res *Result, id string) Attempt {
	t.Helper()
	for _, a := range res.Attempts {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no attempt %q in result", id)
	return Attempt{}
}

// TestSoftNotFoundCatchAllIsNotABypass is the soft-404 false positive: the
// host answers 200 "not found" for every path except the denied one, so every
// attempt gets a 200 that differs from the 403. Only the catch-all profile can
// tell those apart from the resource, since the homepage is a different page.
func TestSoftNotFoundCatchAllIsNotABypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RequestURI()), "admin") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden")
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, acmeHome)
			return
		}
		fmt.Fprint(w, softNotFound)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL+"/admin", Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Baseline.Blocked {
		t.Fatal("baseline 403 was not treated as blocked")
	}
	if res.BypassCount != 0 {
		t.Errorf("BypassCount = %d, want 0: soft-404 pages were counted as bypasses", res.BypassCount)
	}
	if a := findAttempt(t, res, "path-encode-first-char"); a.Bypassed || !strings.Contains(a.Note, "catch-all") {
		t.Errorf("path-encode-first-char = {bypassed:%v note:%q}, want not bypassed and noted as catch-all", a.Bypassed, a.Note)
	}
}

// TestSignInRedirectIsBlockedAndNeverABypass covers the redirect case: the
// protected path 302s to a login page, which has no denial text for the body
// check to find. The baseline has to count as blocked (it is an access
// control), and no redirect may count as a bypass.
func TestSignInRedirectIsBlockedAndNeverABypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RequestURI()), "admin") {
			w.Header().Set("Location", "/login?next=/admin")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, acmeHome)
			return
		}
		fmt.Fprint(w, softNotFound)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL+"/admin", Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Baseline.Blocked || res.Baseline.Reason != "redirects to a sign-in page" {
		t.Fatalf("baseline = {blocked:%v reason:%q}, want blocked by a sign-in redirect", res.Baseline.Blocked, res.Baseline.Reason)
	}
	if res.BypassCount != 0 {
		t.Errorf("BypassCount = %d, want 0: a sign-in redirect was counted as a bypass", res.BypassCount)
	}
	if a := findAttempt(t, res, "path-trailing-slash-toggle"); !strings.Contains(a.Note, "sign-in") {
		t.Errorf("expected the sign-in redirect to be noted, got %q", a.Note)
	}
}

// TestSameDenialPageUnderOtherStatusIsNotABypass is a regression test for the
// status-only comparison: a WAF that serves the identical denial page with a
// 200 instead of a 403 changed the status but not the denial, and used to
// count as a bypass.
func TestSameDenialPageUnderOtherStatusIsNotABypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RequestURI()), "admin") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, denialPage)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, acmeHome)
			return
		}
		fmt.Fprint(w, denialPage)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL+"/admin", Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Baseline.Blocked {
		t.Fatal("baseline 403 was not treated as blocked")
	}
	if res.BypassCount != 0 {
		t.Errorf("BypassCount = %d, want 0: the same denial page under 200 was counted as a bypass", res.BypassCount)
	}
	if a := findAttempt(t, res, "path-encode-first-char"); !strings.Contains(a.Note, "same block page") {
		t.Errorf("expected the denial page to be recognized as the same block page, got note %q", a.Note)
	}
}

// TestIPSpoofHeaderBypassIsCounted is the positive case: only X-Forwarded-For
// set to 127.0.0.1 opens the protected path, so exactly that technique must be
// counted, with the protected content echoed back.
func TestIPSpoofHeaderBypassIsCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
				fmt.Fprint(w, adminConsole)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden")
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, acmeHome)
			return
		}
		fmt.Fprint(w, softNotFound)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL+"/admin", Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	xff := findAttempt(t, res, "header-ip-x-forwarded-for")
	if !xff.Bypassed {
		t.Fatalf("header-ip-x-forwarded-for not bypassed: status=%d note=%q", xff.StatusCode, xff.Note)
	}
	if !strings.Contains(xff.BodySnippet, "admin console") {
		t.Errorf("BodySnippet = %q, want it to show the admin console", xff.BodySnippet)
	}
	// The hop-by-hop variant sends the same X-Forwarded-For value (plus a
	// Connection listing it), so this origin opens for it too. Exactly those
	// two may count; no other header does.
	if res.BypassCount != 2 {
		t.Errorf("BypassCount = %d, want exactly 2 (X-Forwarded-For plain and hop-by-hop, which carry the same value)", res.BypassCount)
	}
	if a := findAttempt(t, res, "header-hop-by-hop-x-forwarded-for"); !a.Bypassed {
		t.Error("header-hop-by-hop-x-forwarded-for not bypassed, but the origin reads the same X-Forwarded-For value")
	}
	if a := findAttempt(t, res, "header-ip-x-real-ip"); a.Bypassed {
		t.Error("header-ip-x-real-ip was counted, but the server only trusts X-Forwarded-For")
	}
}

// TestRewriteHeaderAgainstRootIsCounted checks the corrected X-Original-URL
// form: the request goes to the site root with the real path in the header,
// which is how a front-end that rewrites on that header is actually reached.
// The same-path variant must stay a non-bypass for this server.
func TestRewriteHeaderAgainstRootIsCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Header.Get("X-Original-URL") == "/admin" {
			fmt.Fprint(w, adminConsole)
			return
		}
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden")
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, acmeHome)
			return
		}
		fmt.Fprint(w, softNotFound)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL+"/admin", Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if a := findAttempt(t, res, "header-x-original-url"); !a.Bypassed {
		t.Errorf("header-x-original-url (root-targeted) not bypassed: status=%d note=%q", a.StatusCode, a.Note)
	}
	if a := findAttempt(t, res, "header-x-original-url-same-path"); a.Bypassed {
		t.Error("header-x-original-url-same-path was counted, but this server ignores the header on /admin")
	}
}

// TestDoubleSlashAttemptsSendOriginFormTarget checks the request-line fix: an
// opaque target beginning with "//" used to be rendered as an absolute URL
// (GET http://host//...). The server must receive the literal path instead.
func TestDoubleSlashAttemptsSendOriginFormTarget(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.RequestURI)
		mu.Unlock()
		if strings.Contains(strings.ToLower(r.URL.RequestURI()), "admin") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden")
			return
		}
		fmt.Fprint(w, acmeHome)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL+"/admin", Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if a := findAttempt(t, res, "path-double-slash-wrap"); a.Target != "//admin//" {
		t.Fatalf("path-double-slash-wrap target = %q, want //admin//", a.Target)
	}

	mu.Lock()
	defer mu.Unlock()
	gotLiteral := false
	for _, ruri := range seen {
		if strings.HasPrefix(ruri, "http://") || strings.HasPrefix(ruri, "https://") {
			t.Errorf("request sent in absolute form: %q", ruri)
		}
		if ruri == "//admin//" {
			gotLiteral = true
		}
	}
	if !gotLiteral {
		t.Errorf("server never received the literal request-target //admin//; saw %v", seen)
	}
}

// TestAttemptsAreWellFormed checks that every technique has a unique ID (the
// UI and Result key on it) and a request-target that can be sent at all.
func TestAttemptsAreWellFormed(t *testing.T) {
	for _, base := range []string{"/admin", "/api/v2/admin/", "/"} {
		specs := buildAttempts(base, "x=1", "https", "https://host.test/")
		if len(specs) < 60 {
			t.Errorf("%s: only %d attempts built, expected the full battery", base, len(specs))
		}
		ids := map[string]bool{}
		for _, s := range specs {
			if ids[s.id] {
				t.Errorf("%s: duplicate attempt ID %q", base, s.id)
			}
			ids[s.id] = true
			if !strings.HasPrefix(s.target, "/") {
				t.Errorf("%s: attempt %q has target %q, which is not a valid request-target", base, s.id, s.target)
			}
		}
	}
}

// TestWaybackCountsOnlyHTTP200Snapshots checks the archive gate: a snapshot
// taken as a 200 is a bypass candidate, while one taken as a 403 or missing
// entirely is not.
func TestWaybackCountsOnlyHTTP200Snapshots(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		bypassed bool
		wantNil  bool
	}{
		{"200 snapshot counts", `{"archived_snapshots":{"closest":{"available":true,"url":"https://web.archive.org/x","timestamp":"20240101000000","status":"200"}}}`, true, false},
		{"403 snapshot does not", `{"archived_snapshots":{"closest":{"available":true,"url":"https://web.archive.org/x","timestamp":"20240101000000","status":"403"}}}`, false, false},
		{"no snapshot does not", `{"archived_snapshots":{}}`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			old := waybackEndpoint
			waybackEndpoint = srv.URL
			defer func() { waybackEndpoint = old }()

			got := checkWaybackMachine(context.Background(), "https://target.test/admin")
			if got == nil {
				t.Fatal("checkWaybackMachine returned nil for a reachable endpoint")
			}
			if got.Bypassed != tc.bypassed {
				t.Errorf("Bypassed = %v, want %v (description: %q)", got.Bypassed, tc.bypassed, got.Description)
			}
		})
	}
}

// TestIsSignInRedirect checks which redirects count as sign-in pages: only a
// 3xx whose Location names an authentication page.
func TestIsSignInRedirect(t *testing.T) {
	cases := []struct {
		status   int
		location string
		want     bool
	}{
		{302, "/login?next=/admin", true},
		{301, "https://sso.example.com/auth/start", true},
		{302, "/home", false},
		{200, "/login", false},
		{302, "", false},
	}
	for _, tc := range cases {
		if got := isSignInRedirect(tc.status, tc.location); got != tc.want {
			t.Errorf("isSignInRedirect(%d, %q) = %v, want %v", tc.status, tc.location, got, tc.want)
		}
	}
}

// TestJudgeAttemptRules exercises the verdict rules one response at a time,
// so each rule's positive and negative case is pinned down without a server.
func TestJudgeAttemptRules(t *testing.T) {
	denied := fingerprint.Observe(http.StatusForbidden, "", []byte(denialPage))
	baseline := Baseline{StatusCode: http.StatusForbidden, ContentLength: len(denialPage), body: denied}
	mk := func(status int, body, location string) *httpResult {
		return &httpResult{StatusCode: status, ContentLength: len(body), BodyLower: strings.ToLower(body), Location: location}
	}
	cases := []struct {
		name string
		res  *httpResult
		want bool
	}{
		{"2xx with the admin page is a bypass", mk(200, adminConsole, ""), true},
		{"404 is not", mk(404, softNotFound, ""), false},
		{"500 is not", mk(500, adminConsole, ""), false},
		{"redirect to a path is not", mk(301, "", "/admin/"), false},
		{"redirect to login is not", mk(302, "", "/login"), false},
		{"2xx with the denial page under another status is not", mk(200, denialPage, ""), false},
		{"2xx that still reads as denied is not", mk(200, "<p>Access denied</p>", ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := judgeAttempt(tc.res, baseline, nil)
			if got != tc.want {
				t.Errorf("judgeAttempt = %v, want %v", got, tc.want)
			}
		})
	}
	// Same body and length as the baseline, status changed to 200, must not
	// be a bypass even with no profile or homepage to compare against.
	same := mk(200, denialPage, "")
	if got, _ := judgeAttempt(same, baseline, nil); got {
		t.Error("identical body under 200 was counted as a bypass")
	}
}
