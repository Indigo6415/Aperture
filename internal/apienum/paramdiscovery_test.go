package apienum

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDiscoversUndocumentedParams: /api/report changes its answer for two
// undocumented switches. One switches the output format (a different body),
// the other reflects its value into the body. Both must be found, and the
// reflected one must say so.
func TestDiscoversUndocumentedParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Has("callback"):
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, "%s({\"rows\":[1,2,3]});", q.Get("callback"))
		case q.Has("format"):
			w.Header().Set("Content-Type", "text/csv")
			fmt.Fprint(w, strings.Repeat("id,name,value\n1,alpha,100\n", 30))
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"rows":[1,2,3]}`)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	found := newClient(0, newLimiter(0), nil).discoverQueryParams(ctx, ResolveTarget(srv.URL), "/api/report", nil)

	byName := map[string]Param{}
	for _, p := range found {
		byName[p.Name] = p
	}
	format, ok := byName["format"]
	if !ok || !format.Flagged || format.Location != LocationQuery {
		t.Errorf("format param = %+v, want a flagged query param", format)
	}
	callback, ok := byName["callback"]
	if !ok {
		t.Fatalf("callback param not found; got %+v", found)
	}
	if !strings.Contains(callback.Reason, "reflected") {
		t.Errorf("callback reason = %q, want it to say the value is reflected", callback.Reason)
	}
}

// TestParamSweepIgnoresUnstableRoutes: a route whose answer changes on every
// request has no stable baseline, so no difference can be attributed to a
// parameter. The sweep must report nothing.
func TestParamSweepIgnoresUnstableRoutes(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Each answer is about twice the size of the last, far outside the length tolerance.
		fmt.Fprint(w, strings.Repeat("x", 100<<n.Add(1)))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if found := newClient(0, newLimiter(0), nil).discoverQueryParams(ctx, ResolveTarget(srv.URL), "/api/unstable", nil); len(found) != 0 {
		t.Errorf("unstable route produced %d params: %+v", len(found), found)
	}
}

// TestParamSweepFindsNothingOnPlainRoute: a route that ignores its query string
// has no parameters to report.
func TestParamSweepFindsNothingOnPlainRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","version":"1.2.3"}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if found := newClient(0, newLimiter(0), nil).discoverQueryParams(ctx, ResolveTarget(srv.URL), "/api/plain", nil); len(found) != 0 {
		t.Errorf("plain route produced params: %+v", found)
	}
}

// TestParamSweepSkipsDocumentedParams: a parameter the spec already documents
// is not a discovery, so it must not come back as one.
func TestParamSweepSkipsDocumentedParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("format") {
			fmt.Fprint(w, strings.Repeat("a,b,c\n", 40))
			return
		}
		fmt.Fprint(w, `{"rows":[1]}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	known := []Param{{Name: "format", Location: LocationQuery}}
	for _, p := range newClient(0, newLimiter(0), nil).discoverQueryParams(ctx, ResolveTarget(srv.URL), "/api/report", known) {
		if p.Name == "format" {
			t.Error("a documented parameter was reported as a discovery")
		}
	}
}

// TestParamBudgetIsSpentPerRun: the sweep is budgeted per run, so once the
// budget is gone no further route may take it.
func TestParamBudgetIsSpentPerRun(t *testing.T) {
	c := newClient(0, newLimiter(0), nil)
	c.paramBudget.Store(2)
	if !c.takeParamBudget() || !c.takeParamBudget() {
		t.Fatal("budget of 2 did not grant two routes")
	}
	if c.takeParamBudget() {
		t.Error("third route was granted a sweep from a budget of 2")
	}
}
