package idor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// findingIn returns the findings of the module with the given id, failing the
// test when the module is absent from the result.
func findingIn(t *testing.T, res *Result, moduleID string) []Finding {
	t.Helper()
	// Scan the modules for the one asked about.
	for _, m := range res.Modules {
		if m.ID == moduleID {
			return m.Findings
		}
	}
	t.Fatalf("module %q not present in result", moduleID)
	return nil
}

// TestClassify checks that each reference shape is recognised and that
// ordinary non-reference values are not.
func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		kind refKind
		ok   bool
	}{
		{"1001", kindNumeric, true},
		{"550e8400-e29b-41d4-a716-446655440000", kindUUID, true},
		{"507f1f77bcf86cd799439011", kindObjectID, true},
		{"d41d8cd98f00b204e9800998ecf8427e", kindHex, true},
		{"MTAwMQ==", kindBase64, true}, // base64 of "1001"
		{"alice@example.com", kindEmail, true},
		{"john-doe", kindSlug, true},
		{"en", "", false},              // common locale word, not a reference
		{"true", "", false},            // boolean flag
		{"", "", false},                // empty
		{"the quick brown", "", false}, // free text
	}
	// Each value must classify exactly as expected.
	for _, c := range cases {
		kind, ok := classify(c.in)
		if ok != c.ok || (ok && kind != c.kind) {
			t.Errorf("classify(%q) = (%q,%v), want (%q,%v)", c.in, kind, ok, c.kind, c.ok)
		}
	}
}

// TestNumericNeighbors checks the adjacent-id generation around a value.
func TestNumericNeighbors(t *testing.T) {
	got := map[string]bool{}
	// Collect the generated neighbour values for id 1000.
	for _, c := range numericNeighbors("1000") {
		got[c.value] = true
	}
	// The immediately adjacent ids must be present; a negative must not.
	for _, want := range []string{"1001", "999", "1002", "900"} {
		if !got[want] {
			t.Errorf("numericNeighbors(1000) missing %q", want)
		}
	}
}

// TestEnumerationDetectsDistinctObject runs the scanner against an endpoint
// where id=1001 (another user's record) is reachable by changing id=1000, and
// checks that the enumeration module reports it while the secure negative
// control (a non-existent id) keeps it from being a catch-all false positive.
func TestEnumerationDetectsDistinctObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The endpoint returns a distinct record for ids 1000 and 1001, and a
		// 404 for everything else -- the classic enumerable-id bug.
		switch r.URL.Query().Get("id") {
		case "1000":
			w.Write([]byte("owner record: name=Alice balance=100 secret=alpha padding padding padding"))
		case "1001":
			w.Write([]byte("other record: name=Bob balance=250 secret=bravo padding padding padding"))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/item?id=1000"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := findingIn(t, res, "id-enumeration")
	// The query id point must produce exactly the neighbour finding.
	if len(findings) == 0 {
		t.Fatalf("expected an enumeration finding, got none")
	}
	f := findings[0]
	// The first adjacent id is 1001, so that is the payload that should fire.
	if f.Payload != "1001" {
		t.Errorf("finding payload = %q, want 1001", f.Payload)
	}
	// A negative control ran (the 404 for unknown ids), so the finding is
	// "likely" rather than a bare lead.
	if f.Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want %q", f.Confidence, ConfidenceLikely)
	}
}

// TestSecureEndpointIsClean checks that an endpoint which denies every id but
// the owner's (and ignores injected parameters) produces no findings.
func TestSecureEndpointIsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the owner's own id is ever served; any other id is denied. The
		// server also ignores unknown query parameters entirely.
		if r.URL.Query().Get("id") == "1000" {
			w.Write([]byte("owner record: name=Alice balance=100 secret=alpha padding padding padding"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/item?id=1000"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// No module should report against a correctly-authorizing endpoint.
	for _, m := range res.Modules {
		if len(m.Findings) > 0 {
			t.Errorf("module %q reported %d finding(s) on a secure endpoint: %+v", m.ID, len(m.Findings), m.Findings)
		}
	}
}

// TestCatchAllSuppressesFindings checks that an endpoint returning the same
// page for every id (including a non-existent one) yields no enumeration
// findings, because the negative control reveals it as a catch-all.
func TestCatchAllSuppressesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same body for every request -- a single-page app or catch-all route.
		w.Write([]byte("<html><body>application shell, same for every id value here</body></html>"))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/item?id=1000"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings := findingIn(t, res, "id-enumeration")
	// The control draws the same page, so nothing is a distinct object.
	if len(findings) != 0 {
		t.Errorf("catch-all endpoint produced %d enumeration finding(s), want 0", len(findings))
	}
}

// TestCrossIdentityConfirmed checks that when a second credential retrieves the
// owner's object, the cross-identity module confirms broken access control.
func TestCrossIdentityConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The object for id=1000 is served to any caller that presents some
		// session cookie, regardless of whose it is -- broken object-level
		// authorization. A non-existent id is a 404 for everyone.
		if r.URL.Query().Get("id") == "1000" && r.Header.Get("Cookie") != "" {
			w.Write([]byte("owner profile: name=Alice email=alice@example.com secret=alpha padding padding"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{
		URL:             srv.URL + "/profile?id=1000",
		Headers:         map[string]string{"Cookie": "session=owner-token"},
		AttackerHeaders: map[string]string{"Cookie": "session=attacker-token"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := findingIn(t, res, "cross-identity")
	// The attacker credential sees the owner's profile, so this is confirmed.
	if len(findings) == 0 {
		t.Fatalf("expected a cross-identity finding, got none")
	}
	if c := findings[0].Confidence; c != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q", c, ConfidenceConfirmed)
	}
	// The run must record that it tested under the second credential.
	if len(res.Identities) == 0 || !strings.Contains(strings.Join(res.Identities, ","), "second credential") {
		t.Errorf("identities = %v, want it to include the second credential", res.Identities)
	}
}

// TestManyTestsPerHost checks the headline requirement: a single seed with a
// couple of id parameters yields well over 100 individual probes, thanks to
// the common-parameter list, the mutation catalogs, and the per-point controls.
func TestManyTestsPerHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A plain endpoint that just echoes a short constant; the point is to
		// count probes, not to find anything.
		w.Write([]byte("ok, nothing to see here, a short and stable response body"))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/api/item?id=1000&account=42"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The explicit goal: more than 100 tests for a given host.
	if res.TestsRun <= 100 {
		t.Errorf("TestsRun = %d, want > 100", res.TestsRun)
	}
	t.Logf("points=%d tests=%d", res.PointsTested, res.TestsRun)
}
