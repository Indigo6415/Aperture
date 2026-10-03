package apienum

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newGatewayErrorServer stands in for a reverse proxy whose upstream is down:
// every path answers 502 Bad Gateway. Nothing here exists as an API route, so
// neither the brute force nor method characterization should report one.
func newGatewayErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestBruteforceIgnoresGatewayErrors checks that a path answering 502 is not
// kept as a discovered route, the same way a 404 is not kept.
func TestBruteforceIgnoresGatewayErrors(t *testing.T) {
	srv := newGatewayErrorServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := newClient(0, newLimiter(0), nil)
	target := ResolveTarget(srv.URL)
	found := bruteforcePaths(ctx, client, target, []string{""}, nil, nil)

	if len(found) != 0 {
		t.Fatalf("expected no routes from a server answering only 502, got %d (first: %+v)", len(found), found[0])
	}
}

// TestCharacterizeIgnoresGatewayErrors checks that a 502 on every method probe
// marks no method as allowed, so the route doesn't claim write support or
// confirmation it never earned.
func TestCharacterizeIgnoresGatewayErrors(t *testing.T) {
	srv := newGatewayErrorServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := newClient(0, newLimiter(0), nil)
	target := ResolveTarget(srv.URL)
	route := Route{Path: "/api/items", Source: "js", Methods: []MethodProbe{{Method: "GET"}}}
	got := characterizeRoute(ctx, client, target, route)

	if got.Confirmed {
		t.Error("expected a route that only ever answered 502 to stay unconfirmed")
	}
	if len(got.Methods) == 0 {
		t.Fatal("expected method probes to be recorded")
	}
	for _, m := range got.Methods {
		if m.Allowed {
			t.Errorf("expected %s to not be marked allowed on a 502, got %+v", m.Method, m)
		}
	}
}
