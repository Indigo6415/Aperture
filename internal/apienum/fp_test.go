package apienum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// softPage is the 200 "not found" page a catch-all host serves for every path
// it doesn't have -- the soft-404 shape that used to turn every guess into a hit.
const softPage = `<!doctype html><html><head><title>Page not found</title></head><body>
<h1>Not Found</h1><p>The page you requested could not be found on this server. Check the address and try again.</p></body></html>`

// newSoftServer answers exactly the paths in real (with the given JSON body) and
// every other path with the soft-404 page.
func newSoftServer(t *testing.T, real map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := real[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, softPage)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestBruteforceDropsSoftNotFound: a host that answers 200 "not found" for
// everything has exactly one real path. Only that path may survive the brute
// force; the rest of the wordlist is the soft-404 answer and must be dropped.
func TestBruteforceDropsSoftNotFound(t *testing.T) {
	srv := newSoftServer(t, map[string]string{"/items": `[{"id":1,"name":"widget"},{"id":2,"name":"gadget"}]`})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := newClient(0, newLimiter(0), nil)
	found := bruteforcePaths(ctx, client, ResolveTarget(srv.URL), []string{""}, nil, nil)

	if len(found) != 1 || found[0].Path != "/items" {
		paths := make([]string, 0, len(found))
		for _, r := range found {
			paths = append(paths, r.Path)
		}
		t.Fatalf("kept %d paths %v, want only /items", len(found), paths)
	}
}

// TestSoftNotFoundRouteIsUnconfirmed: a JS-mined route answering the soft-404
// page must stay in the uncertain bucket, and a route with its own JSON answer
// must be confirmed.
func TestSoftNotFoundRouteIsUnconfirmed(t *testing.T) {
	srv := newSoftServer(t, map[string]string{"/api/things": `{"things":[1,2,3]}`})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := newClient(0, newLimiter(0), nil)
	target := ResolveTarget(srv.URL)

	soft := characterizeRoute(ctx, client, target, Route{Path: "/api/ghost", Source: "js", Methods: []MethodProbe{{Method: "GET"}}})
	if soft.Confirmed {
		t.Error("a route answering the soft-404 page was confirmed")
	}
	real := characterizeRoute(ctx, client, target, Route{Path: "/api/things", Source: "js", Methods: []MethodProbe{{Method: "GET"}}})
	if !real.Confirmed {
		t.Error("a route with its own JSON answer was not confirmed")
	}
}

// TestLoginRedirectIsNotPublic: a route that 302s to a sign-in page is behind
// a login. The verdict must say so, and the redirect must not be followed to
// the login page's own 200.
func TestLoginRedirectIsNotPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/secret" {
			w.Header().Set("Location", "/login?next=/api/secret")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>please sign in</html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got := characterizeRoute(ctx, newClient(0, newLimiter(0), nil), ResolveTarget(srv.URL), Route{Path: "/api/secret", Source: "js", Methods: []MethodProbe{{Method: "GET"}}})

	if got.Auth.Verdict != "login-redirect" || !got.Auth.RequiresAuth {
		t.Errorf("auth = %+v, want login-redirect requiring auth", got.Auth)
	}
	if got.Auth.UnauthenticatedStatus != http.StatusFound {
		t.Errorf("unauthenticated status = %d, want 302 (the redirect must not be followed)", got.Auth.UnauthenticatedStatus)
	}
}

// TestSiteWideGateIsNotARouteControl: when every path, nonexistent or not, gets
// the same 401 with a challenge, the gate belongs to the host. The route must
// not claim RequiresAuth of its own, and the challenge is still surfaced.
func TestSiteWideGateIsNotARouteControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="staging"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got := characterizeRoute(ctx, newClient(0, newLimiter(0), nil), ResolveTarget(srv.URL), Route{Path: "/api/things", Source: "js", Methods: []MethodProbe{{Method: "GET"}}})

	if got.Auth.Verdict != "site-wide-gate" {
		t.Errorf("verdict = %q, want site-wide-gate", got.Auth.Verdict)
	}
	if got.Auth.RequiresAuth {
		t.Error("a host-wide gate was reported as the route's own auth requirement")
	}
	if !strings.Contains(got.Auth.Challenge, "staging") {
		t.Errorf("challenge = %q, want the WWW-Authenticate value", got.Auth.Challenge)
	}
}

// TestRouteSpecificAuthIsReported is the positive counterpart: a 401 that only
// one route returns is that route's own requirement.
func TestRouteSpecificAuthIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/private" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/open" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := newClient(0, newLimiter(0), nil)
	target := ResolveTarget(srv.URL)

	private := characterizeRoute(ctx, client, target, Route{Path: "/api/private", Source: "js", Methods: []MethodProbe{{Method: "GET"}}})
	if private.Auth.Verdict != "requires-auth" || !private.Auth.RequiresAuth {
		t.Errorf("private auth = %+v, want requires-auth", private.Auth)
	}
	open := characterizeRoute(ctx, client, target, Route{Path: "/api/open", Source: "js", Methods: []MethodProbe{{Method: "GET"}}})
	if open.Auth.Verdict != "public" || open.Auth.RequiresAuth || !open.Confirmed {
		t.Errorf("open = {auth:%+v confirmed:%v}, want public and confirmed", open.Auth, open.Confirmed)
	}
}

// TestGraphQLDiscoveryNeedsAGraphQLAnswer covers the discovery false positive:
// a generic JSON API and an HTML shell must not be reported as GraphQL, while a
// real endpoint on a non-first path is found.
func TestGraphQLDiscoveryNeedsAGraphQLAnswer(t *testing.T) {
	cases := []struct {
		name      string
		handler   http.HandlerFunc
		wantFound bool
	}{
		{"generic JSON errors", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"errors":["bad input"]}`)
		}, false},
		{"HTML shell containing the word data", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script>var data = {"data": 1};</script></html>`)
		}, false},
		{"GraphQL on a versioned path", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/graphql" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			var body struct {
				Query string `json:"query"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.Contains(body.Query, "__schema") {
				fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query","fields":[]},"mutationType":null,"types":[]}}}`)
				return
			}
			fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			summary, _ := discoverGraphQL(ctx, newClient(0, newLimiter(0), nil), ResolveTarget(srv.URL))
			if summary.Found != tc.wantFound {
				t.Errorf("Found = %v, want %v (%+v)", summary.Found, tc.wantFound, summary)
			}
		})
	}
}

// TestRequestsSentIsRealTraffic: the reported request count must match the
// traffic the target actually received, not a count of method probes. The
// netgov transport may add its own canary probes, so the reported number may
// be lower than what the server saw, but never higher, and never zero.
func TestRequestsSentIsRealTraffic(t *testing.T) {
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		if r.URL.Path == "/api/things" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"things":[1]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := RunScan(ctx, srv.URL, Options{CrawlDepth: 1, MaxPages: 1})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	seen := served.Load()
	if res.Stats.RequestsSent <= 0 || int64(res.Stats.RequestsSent) > seen {
		t.Errorf("RequestsSent = %d, server saw %d", res.Stats.RequestsSent, seen)
	}
}
