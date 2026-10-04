package paramminer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// newTestServer returns a handler-backed server and the URL to mine it at.
func newTestServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *url.URL) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/endpoint")
	if err != nil {
		t.Fatal(err)
	}
	return srv, u
}

// mine runs Mine against u with a short-timeout client.
func mine(t *testing.T, u *url.URL, method string, names []string) Result {
	t.Helper()
	res, err := Mine(context.Background(), Options{
		URL:    u,
		Method: method,
		Client: &http.Client{Timeout: 5 * time.Second},
		Names:  names,
	})
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	return res
}

// TestMineFindsHiddenParamsGET checks that a parameter which changes the
// response, and one which is only reflected, are both found, and that a
// parameter the handler ignores is not.
func TestMineFindsHiddenParamsGET(t *testing.T) {
	_, u := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// A switch: its presence changes the status.
		if q.Get("debug") != "" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		// A reflected value: the canary comes back in the body.
		if v := q.Get("echo"); v != "" {
			w.Write([]byte("<p>" + v + "</p>"))
			return
		}
		w.Write([]byte("<h1>static page</h1>"))
	})

	res := mine(t, u, http.MethodGet, []string{"debug", "echo", "ignored1", "ignored2"})
	sort.Strings(res.Names)
	if want := []string{"debug", "echo"}; !reflect.DeepEqual(res.Names, want) {
		t.Fatalf("Names = %v, want %v", res.Names, want)
	}
	if want := []string{"echo"}; !reflect.DeepEqual(res.Reflected, want) {
		t.Fatalf("Reflected = %v, want %v", res.Reflected, want)
	}
}

// TestMineFindsHiddenParamsPOST checks the same discovery through a form body.
func TestMineFindsHiddenParamsPOST(t *testing.T) {
	_, u := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Write([]byte("get"))
			return
		}
		if r.PostFormValue("callback") != "" {
			w.Write([]byte("callback handled"))
			return
		}
		w.Write([]byte("nothing here"))
	})

	res := mine(t, u, http.MethodPost, []string{"callback", "unused"})
	if want := []string{"callback"}; !reflect.DeepEqual(res.Names, want) {
		t.Fatalf("Names = %v, want %v", res.Names, want)
	}
}

// TestMineSkipsUnstableEndpoint checks that an endpoint answering differently
// on every request yields nothing, since a later difference would be noise.
func TestMineSkipsUnstableEndpoint(t *testing.T) {
	n := 0
	_, u := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Write([]byte(strings.Repeat("x", n*500)))
	})
	res := mine(t, u, http.MethodGet, []string{"debug", "echo"})
	if len(res.Names) != 0 {
		t.Fatalf("Names = %v, want none for an unstable endpoint", res.Names)
	}
	if res.Requests != 2 {
		t.Fatalf("Requests = %d, want just the two baseline probes", res.Requests)
	}
}

// TestMineKnownNamesNotProbed checks that names the caller already has are
// excluded from the candidates, so they cost no probe.
func TestMineKnownNamesNotProbed(t *testing.T) {
	_, u := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("static"))
	})
	u.RawQuery = "url=http://example.com"
	res, err := Mine(context.Background(), Options{
		URL:    u,
		Client: &http.Client{Timeout: 5 * time.Second},
		Known:  []string{"debug"},
		Names:  []string{"url", "debug"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two baseline probes and nothing else: both candidates are already known.
	if res.Requests != 2 {
		t.Fatalf("Requests = %d, want 2 (both candidates are known)", res.Requests)
	}
}

// TestMineNilClientIsNoop checks that a run without a client returns an empty
// result rather than panicking.
func TestMineNilClientIsNoop(t *testing.T) {
	res, err := Mine(context.Background(), Options{URL: &url.URL{Scheme: "http", Host: "example.invalid"}})
	if err != nil || len(res.Names) != 0 || res.Requests != 0 {
		t.Fatalf("got %+v, %v; want an empty result", res, err)
	}
}
