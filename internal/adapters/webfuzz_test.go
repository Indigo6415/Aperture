package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Indigo6415/Aperture/internal/model"
)

// writeWordlist writes one word per line to a temp file and returns its path.
func writeWordlist(t *testing.T, words ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte(strings.Join(words, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runWebFuzz runs the adapter with cfg and returns every emitted finding.
func runWebFuzz(t *testing.T, cfg WebFuzzConfig) []model.Finding {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var out []model.Finding
	emit := func(f model.Finding) {
		mu.Lock()
		defer mu.Unlock()
		out = append(out, f)
	}
	if err := (&WebFuzzAdapter{}).Run(context.Background(), raw, RunMeta{RunID: "t", NodeID: "n"}, emit, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out
}

// TestWebFuzzHostHeaderReachesServer checks header-based vhost fuzzing: the
// FUZZ word must arrive as the request's Host. Before the fix it was set with
// req.Header.Set, which Go silently ignores for Host.
func TestWebFuzzHostHeaderReachesServer(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Host] = true
		mu.Unlock()
		fmt.Fprint(w, "vhost")
	}))
	defer srv.Close()

	runWebFuzz(t, WebFuzzConfig{
		URL:      srv.URL + "/",
		Wordlist: writeWordlist(t, "alpha", "beta"),
		Headers:  map[string]string{"Host": "FUZZ.example.test"},
		Threads:  2,
	})
	for _, want := range []string{"alpha.example.test", "beta.example.test"} {
		if !seen[want] {
			t.Errorf("server never saw Host %q; saw %v", want, seen)
		}
	}
}

// TestWebFuzzFiltersCatchAllWithAutoCalibrate checks the central claim for the
// native fuzzer: when every unknown path returns the same shell, only the real
// path is reported, not one finding per wordlist entry.
func TestWebFuzzFiltersCatchAllWithAutoCalibrate(t *testing.T) {
	shell := `<!doctype html><html><head><title>Portal</title></head><body>
<p>Welcome to the portal. Sign in to see your dashboard and account settings today.</p></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, "<html><title>Admin console</title><p>Restricted operator controls and user management tools.</p></html>")
			return
		}
		fmt.Fprint(w, shell)
	}))
	defer srv.Close()

	findings := runWebFuzz(t, WebFuzzConfig{
		URL:           srv.URL + "/FUZZ",
		Wordlist:      writeWordlist(t, "admin", "nope1", "nope2", "nope3"),
		AutoCalibrate: true,
		Threads:       4,
	})
	var urls []string
	for _, f := range findings {
		urls = append(urls, f.URL)
	}
	if len(findings) != 1 || !strings.HasSuffix(findings[0].URL, "/admin") {
		t.Errorf("findings = %v, want exactly the /admin hit", urls)
	}
}

// TestIsDirectoryHit checks the recursion rule: directories are walked, plain
// files are not.
func TestIsDirectoryHit(t *testing.T) {
	cases := []struct {
		name string
		res  webfuzzResult
		url  string
		want bool
	}{
		{"redirect to slash form", webfuzzResult{statusCode: 301, redirectLoc: "/admin/"}, "http://h/admin", true},
		{"redirect to a file", webfuzzResult{statusCode: 302, redirectLoc: "/login"}, "http://h/login", false},
		{"forbidden path", webfuzzResult{statusCode: 403}, "http://h/private", true},
		{"extensionless 200", webfuzzResult{statusCode: 200}, "http://h/api", true},
		{"robots.txt is a file", webfuzzResult{statusCode: 200}, "http://h/robots.txt", false},
		{"slash-terminated 200", webfuzzResult{statusCode: 200}, "http://h/docs/", true},
		{"not found", webfuzzResult{statusCode: 404}, "http://h/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDirectoryHit(tc.res, tc.url); got != tc.want {
				t.Errorf("isDirectoryHit = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCatchAllBase checks where the probe prefix comes from for each URL shape.
func TestCatchAllBase(t *testing.T) {
	cases := map[string]string{
		"http://h/FUZZ":        "http://h/",
		"http://h/api/FUZZ.do": "http://h/api/",
		"http://h/static/":     "http://h/static/",
	}
	for in, want := range cases {
		if got := catchAllBase(in); got != want {
			t.Errorf("catchAllBase(%q) = %q, want %q", in, got, want)
		}
	}
}
