package bypass403

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCatchAllHomepageIsNotABypass checks the false-positive case: a host that
// denies /admin but answers every other path with its homepage. The changed
// status makes each attempt look different from the 403, yet none opened
// anything, so none may count as a bypass.
func TestCatchAllHomepageIsNotABypass(t *testing.T) {
	const home = `<!doctype html><html><head><title>Acme Store</title></head><body>
<p>Welcome to the Acme store. Browse our catalogue of widgets, gadgets and accessories today.</p></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RequestURI()), "admin") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden")
			return
		}
		fmt.Fprint(w, home)
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
		t.Errorf("BypassCount = %d, want 0: homepage responses were counted as bypasses", res.BypassCount)
	}
	noted := 0
	for _, a := range res.Attempts {
		if a.Note != "" {
			noted++
		}
	}
	if noted == 0 {
		t.Error("no attempt was annotated as returning the homepage")
	}
}
