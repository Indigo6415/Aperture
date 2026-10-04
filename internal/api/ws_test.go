package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCheckWSOrigin pins which Origin headers may open a WebSocket: same-host,
// loopback (for the Vite dev proxy), or absent (non-browser clients). Anything
// else from another site must be refused.
func TestCheckWSOrigin(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"no origin (non-browser client)", "127.0.0.1:8337", "", true},
		{"same host", "127.0.0.1:8337", "http://127.0.0.1:8337", true},
		{"vite dev server on localhost", "127.0.0.1:8080", "http://localhost:5173", true},
		{"loopback ip any port", "127.0.0.1:8337", "http://127.0.0.1:5173", true},
		{"ipv6 loopback", "127.0.0.1:8337", "http://[::1]:5173", true},
		{"foreign site", "127.0.0.1:8337", "https://evil.example", false},
		{"foreign site with matching port", "127.0.0.1:8337", "https://evil.example:8337", false},
		{"unparseable origin", "127.0.0.1:8337", "://%%", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/ws/jobs/x", nil)
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := checkWSOrigin(r); got != tc.want {
				t.Fatalf("checkWSOrigin(origin=%q, host=%q) = %v, want %v", tc.origin, tc.host, got, tc.want)
			}
		})
	}
}

// TestLimitBodyCapsReads checks that a body larger than maxRequestBody fails to
// read, and one under the cap reads in full.
func TestLimitBodyCapsReads(t *testing.T) {
	var readErr error
	var got int
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		got = len(b)
		readErr = err
	}))

	small := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader("hello"))
	h.ServeHTTP(httptest.NewRecorder(), small)
	if readErr != nil || got != 5 {
		t.Fatalf("small body: read %d bytes, err=%v; want 5, nil", got, readErr)
	}

	big := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(strings.Repeat("a", maxRequestBody+1)))
	h.ServeHTTP(httptest.NewRecorder(), big)
	if readErr == nil {
		t.Fatalf("oversized body: read %d bytes with no error; want a MaxBytesReader error", got)
	}
}
