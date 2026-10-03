package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// spaShell is the kind of document a single-page app serves for every route.
const spaShell = `<!doctype html><html><head><title>Acme Portal</title></head>
<body><div id="root"></div><script src="/app.js"></script>
<p>Welcome to the Acme portal. Sign in to continue to your dashboard and reports.</p></body></html>`

// TestSimhashToleratesDynamicTokens checks that a page differing only in a
// few dynamic tokens stays close, while a genuinely different page is far.
func TestSimhashToleratesDynamicTokens(t *testing.T) {
	base := "Welcome to the Acme portal. Sign in to continue to your dashboard and reports. " +
		"Your session expires after a period of inactivity for security reasons and " +
		"the support team reviews access logs every single day of the week."
	withToken := base + " request id 8f3a2c91 generated 2026-10-03T12:00:01Z"
	different := "Quarterly invoice summary for the finance department. Totals, tax lines, " +
		"currency conversion notes and a payment schedule for vendors in region four."

	a, b, c := Simhash(base), Simhash(withToken), Simhash(different)
	if d := Distance(a, b); d > maxSimhashDistance {
		t.Errorf("near-identical pages distance = %d, want <= %d", d, maxSimhashDistance)
	}
	if d := Distance(a, c); d <= maxSimhashDistance {
		t.Errorf("different pages distance = %d, want > %d", d, maxSimhashDistance)
	}
}

// TestSimhashIgnoresMarkup checks that identical visible text wrapped in
// different markup and scripts hashes the same, so templating noise does not
// create false differences.
func TestSimhashIgnoresMarkup(t *testing.T) {
	plain := "hello world from the status page for the service today"
	wrapped := `<div class="x"><script>var a = 1;</script><span>` + plain + `</span></div>`
	if Simhash(plain) != Simhash(wrapped) {
		t.Errorf("markup changed the simhash; plain=%x wrapped=%x", Simhash(plain), Simhash(wrapped))
	}
}

// TestProfileMatchesCatchAll checks the central claim: on a host that serves
// the same shell for every path, the profile recognizes that shell and does
// not recognize a real page that differs from it.
func TestProfileMatchesCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real content lives only at /real; everything else is the shell.
		if r.URL.Path == "/real" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "DB_PASSWORD=hunter2\nDB_HOST=10.0.0.5\nAPP_KEY=abc123\n")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, spaShell)
	}))
	defer srv.Close()

	profile, err := BuildProfile(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatalf("BuildProfile: %v", err)
	}
	if !profile.Stable {
		t.Fatal("profile of a consistent catch-all should be stable")
	}

	shellObs, err := fetchObservation(context.Background(), srv.Client(), srv.URL+"/some/route", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Matches(shellObs) {
		t.Error("catch-all shell was not recognized as catch-all")
	}

	realObs, err := fetchObservation(context.Background(), srv.Client(), srv.URL+"/real", nil)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Matches(realObs) {
		t.Error("real secrets file was hidden as if it were the catch-all page")
	}
}

// TestProfileUnstableHostIsNeverFiltered checks that when random paths get
// inconsistent answers, the profile refuses to filter anything, so real
// content cannot be hidden by accident.
func TestProfileUnstableHostIsNeverFiltered(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every answer is a different size, so no two probes agree.
		fmt.Fprint(w, strings.Repeat("x", int(n.Add(1))*500))
	}))
	defer srv.Close()

	profile, err := BuildProfile(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatalf("BuildProfile: %v", err)
	}
	if profile.Stable {
		t.Fatal("inconsistent host should not be marked stable")
	}
	if profile.Matches(Observation{Status: 200, Length: 500}) {
		t.Error("unstable profile must never match")
	}
	if profile.MatchesSize(200, 500) {
		t.Error("unstable profile must never match by size either")
	}
}

// TestNilProfileNeverMatches checks the nil-safe behavior scanners rely on
// when the profile could not be built.
func TestNilProfileNeverMatches(t *testing.T) {
	var p *Profile
	if p.Matches(Observation{Status: 200}) || p.MatchesSize(200, 10) {
		t.Error("nil profile matched something")
	}
}
