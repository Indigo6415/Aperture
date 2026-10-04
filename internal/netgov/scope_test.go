package netgov

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestScopeAllows covers each pattern form and the host shapes a request can
// present (ports, IPv6 brackets, trailing dots, mixed case).
func TestScopeAllows(t *testing.T) {
	s, err := NewScope([]string{"example.com", "*.lab.test", "10.0.0.5", "192.168.1.0/24", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"EXAMPLE.com:8443", true},
		{"example.com.", true},
		{"api.example.com", true},
		{"deep.api.example.com:80", true},
		{"notexample.com", false},
		{"example.com.evil.net", false},
		{"lab.test", false},
		{"a.lab.test", true},
		{"10.0.0.5:8080", true},
		{"10.0.0.6", false},
		{"192.168.1.200", true},
		{"192.168.2.1", false},
		{"[::1]:8080", true},
		{"[::2]:8080", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := s.Allows(tc.host); got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestNilScopeAllowsEverything pins the unrestricted default: no rules means no
// restriction, and an empty pattern list must not produce a rejecting scope.
func TestNilScopeAllowsEverything(t *testing.T) {
	s, err := NewScope(nil)
	if err != nil || s != nil {
		t.Fatalf("NewScope(nil) = %v, %v; want nil, nil", s, err)
	}
	if !s.Allows("anything.example") {
		t.Fatal("nil scope must allow every host")
	}
	blank, err := NewScope([]string{"  ", ""})
	if err != nil || blank != nil {
		t.Fatalf("blank-only patterns = %v, %v; want nil, nil", blank, err)
	}
}

// TestNewScopeRejectsBadPatterns checks that malformed rules fail loudly
// instead of silently allowing or denying more than the operator meant.
func TestNewScopeRejectsBadPatterns(t *testing.T) {
	for _, p := range []string{"exa mple.com", "bad_name.com", "*.", "10.0.0.0/33", "-x.com", "singlelabel"} {
		if _, err := NewScope([]string{p}); err == nil {
			t.Errorf("NewScope(%q) accepted a bad pattern", p)
		}
	}
}

// TestRoundTripRefusesOutOfScopeHost checks the enforcement point end to end:
// an out-of-scope request returns ErrOutOfScope and never reaches the server.
func TestRoundTripRefusesOutOfScopeHost(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer srv.Close()

	// Scope names a different host, so the test server's 127.0.0.1 is outside it.
	scope, err := NewScope([]string{"only.example"})
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(0, false)
	ctx := WithPolicy(context.Background(), Policy{Scope: scope})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)

	_, err = client.Do(req)
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
	if hits != 0 {
		t.Fatalf("server received %d requests; an out-of-scope host must receive none", hits)
	}
}
