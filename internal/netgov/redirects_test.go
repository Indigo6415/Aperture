package netgov

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRedirectHopRecordsItsSource checks that the 200 reached through a 302
// records the 302's ref as its FromRef, so the inspector can show which hop led
// to it.
func TestRedirectHopRecordsItsSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var got []Exchange
	ctx := WithRecorder(context.Background(), RecorderFunc(func(e Exchange) { got = append(got, e) }))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := NewClient(0, true).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	var hop, landed *Exchange
	for i := range got {
		switch {
		case got[i].Status == http.StatusFound:
			hop = &got[i]
		case got[i].Status == http.StatusOK:
			landed = &got[i]
		}
	}
	if hop == nil || landed == nil {
		t.Fatalf("want a 302 and a 200 recorded, got %d exchanges: %+v", len(got), got)
	}
	if hop.Ref == "" || landed.Ref == "" {
		t.Fatalf("exchanges must carry refs: hop=%q landed=%q", hop.Ref, landed.Ref)
	}
	if landed.FromRef != hop.Ref {
		t.Errorf("landed.FromRef = %q, want the 302's ref %q", landed.FromRef, hop.Ref)
	}
	if hop.FromRef != "" {
		t.Errorf("the first request was not a redirect, but FromRef = %q", hop.FromRef)
	}
}

// TestUnfollowedRedirectIsNotLinked checks that a client which does not follow
// redirects leaves the 3xx as the final response and links nothing.
func TestUnfollowedRedirectIsNotLinked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	var got []Exchange
	ctx := WithRecorder(context.Background(), RecorderFunc(func(e Exchange) { got = append(got, e) }))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/x", nil)
	resp, err := NewClient(0, false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 returned as-is", resp.StatusCode)
	}
	for _, e := range got {
		if e.FromRef != "" {
			t.Errorf("no hop should be linked, got FromRef %q", e.FromRef)
		}
	}
}
