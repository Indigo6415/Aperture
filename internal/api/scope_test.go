package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/store"
)

// newScopeTestServer builds a Server on a fresh temp database, for handlers
// that only need the store.
func newScopeTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewServer(st, engine.New(), nil, t.TempDir())
}

// TestCaseScopeRoutesRoundTrip checks PUT then GET on /api/cases/{id}/scope,
// and that an invalid pattern is rejected before anything is saved.
func TestCaseScopeRoutesRoundTrip(t *testing.T) {
	s := newScopeTestServer(t)
	if err := s.store.CreateCase("case-s", "scoped", ""); err != nil {
		t.Fatal(err)
	}

	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/cases/case-s/scope", strings.NewReader(body))
		req.SetPathValue("id", "case-s")
		s.handleSetCaseScope(rec, req)
		return rec
	}

	if rec := put(`{"patterns":["example.com","*.lab.test"]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT valid scope = %d: %s", rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cases/case-s/scope", nil)
	req.SetPathValue("id", "case-s")
	s.handleGetCaseScope(rec, req)
	var got caseScopeBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Patterns, []string{"example.com", "*.lab.test"}) {
		t.Fatalf("GET patterns = %v", got.Patterns)
	}

	if rec := put(`{"patterns":["bad host!"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid pattern = %d, want 400", rec.Code)
	}
	// The failed PUT must not have replaced the valid rules.
	if saved, _ := s.store.GetCaseScope("case-s"); len(saved) != 2 {
		t.Fatalf("invalid PUT changed saved scope to %v", saved)
	}
}

// TestCaseScopeRoutesUnknownCase expects 404 for a scope read or write against
// a case that doesn't exist.
func TestCaseScopeRoutesUnknownCase(t *testing.T) {
	s := newScopeTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/cases/nope/scope", strings.NewReader(`{"patterns":[]}`))
	req.SetPathValue("id", "nope")
	s.handleSetCaseScope(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT unknown case = %d, want 404", rec.Code)
	}
}

// TestScanRefusesOutOfScopeTarget checks the start-time gate: a scan whose
// target sits outside the case's scope is refused with 400 before a scan is
// registered, and an in-scope target is accepted.
func TestScanRefusesOutOfScopeTarget(t *testing.T) {
	s := newScopeTestServer(t)
	if err := s.store.SetCaseScope("case-x", []string{"example.com"}); err != nil {
		t.Fatal(err)
	}

	start := func(target string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"url": target, "caseId": "case-x"})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/xss/scan", bytes.NewReader(body))
		s.handleXSSScan(rec, req)
		return rec
	}

	if rec := start("https://elsewhere.test/page"); rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-scope scan = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := start("https://app.example.com/page"); rec.Code != http.StatusAccepted {
		t.Fatalf("in-scope scan = %d, want 202: %s", rec.Code, rec.Body.String())
	}
}

// TestRefuseCrossOriginWrites checks that state-changing requests from another
// site are refused, while reads, same-origin writes, and origin-less (CLI)
// writes still pass.
func TestRefuseCrossOriginWrites(t *testing.T) {
	reached := 0
	h := refuseCrossOriginWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name, method, origin string
		wantCode             int
	}{
		{"cross-site POST refused", http.MethodPost, "https://evil.example", http.StatusForbidden},
		{"cross-site DELETE refused", http.MethodDelete, "https://evil.example", http.StatusForbidden},
		{"cross-site GET allowed (reads are not state changes)", http.MethodGet, "https://evil.example", http.StatusOK},
		{"same-origin POST allowed", http.MethodPost, "http://aperture.test", http.StatusOK},
		{"origin-less POST (CLI) allowed", http.MethodPost, "", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "http://aperture.test/api/x", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}

// TestTargetHost covers how a target string is reduced to the host the scope
// check sees: URLs, bare hosts, ports, IPv6, and inputs that aren't hosts.
func TestTargetHost(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com/login": "app.example.com",
		"http://10.0.0.5:8080/x":        "10.0.0.5:8080",
		"example.com":                   "example.com",
		"example.com:443":               "example.com:443",
		"http://[::1]:9000/":            "[::1]:9000",
		"user@example.com":              "",
		"not a host":                    "",
		"":                              "",
	}
	for in, want := range cases {
		if got := targetHost(in); got != want {
			t.Errorf("targetHost(%q) = %q, want %q", in, got, want)
		}
	}
}
