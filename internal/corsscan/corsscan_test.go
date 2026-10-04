package corsscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunFlagsOriginReflectionWithCredentials serves an endpoint that echoes any
// Origin back with credentials allowed, the classic exploitable CORS setup, and
// expects at least one finding.
func TestRunFlagsOriginReflectionWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/api/me"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	total := 0
	for _, m := range res.Modules {
		total += len(m.Findings)
	}
	if total == 0 {
		t.Fatal("origin reflection with credentials produced no findings")
	}
}

// TestRunQuietOnStaticEndpoint checks an endpoint with no CORS headers at all
// produces no findings, so the scanner doesn't cry wolf on ordinary responses.
func TestRunQuietOnStaticEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("static"))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Request{URL: srv.URL + "/static"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, m := range res.Modules {
		if len(m.Findings) != 0 {
			t.Fatalf("module %s reported %d findings on an endpoint with no CORS headers", m.ID, len(m.Findings))
		}
	}
}
