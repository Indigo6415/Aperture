package ssrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestDiscoverParamsFindsFormAction is a regression check for the exact
// scenario reported: a GET form whose action points at a different path
// than the page it's on must be tested against that action, not folded only
// into the page's own query string.
func TestDiscoverParamsFindsFormAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body>
				<form method="GET" action="/fetch">
					<input type="text" name="url" placeholder="http://example.com" value="http://example.com">
					<button type="submit">Fetch</button>
				</form>
			</body></html>`))
		case "/fetch":
			w.Write([]byte("fetched: " + r.URL.Query().Get("url")))
		}
	}))
	defer srv.Close()

	seed, err := parseTarget(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	client := newClient()
	_, forms := discoverParams(t.Context(), client, seed, 0, 0, nil)

	if len(forms) != 1 {
		t.Fatalf("expected 1 form target, got %d: %+v", len(forms), forms)
	}
	ft := forms[0]
	if ft.method != http.MethodGet {
		t.Errorf("method = %q, want GET", ft.method)
	}
	if got := ft.url.Path; got != "/fetch" {
		t.Errorf("url.Path = %q, want /fetch", got)
	}
	if len(ft.params) != 1 || ft.params[0] != "url" {
		t.Errorf("params = %v, want [url]", ft.params)
	}
}

// TestRunAutoDiscoverHitsFormAction confirms Run itself (not just
// discoverParams in isolation) actually sends requests to the form's action
// endpoint when AutoDiscover is on -- i.e. scanning "/" for SSRF must
// produce traffic against "/fetch", matching how a real browser submitting
// that form would behave.
func TestRunAutoDiscoverHitsFormAction(t *testing.T) {
	var mu sync.Mutex
	var fetchHits int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<form method="GET" action="/fetch"><input name="url" value="http://example.com"></form>`))
		case "/fetch":
			mu.Lock()
			fetchHits++
			mu.Unlock()
			w.Write([]byte("fetched: " + r.URL.Query().Get("url")))
		}
	}))
	defer srv.Close()

	_, err := Run(context.Background(), Request{URL: srv.URL + "/", AutoDiscover: true}, OOBConfig{})
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if fetchHits == 0 {
		t.Fatal("expected Run to send at least one request to the discovered form's /fetch action, got none")
	}
}
