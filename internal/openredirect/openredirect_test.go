package openredirect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// hitSeq gives every recorded test hit a unique ID. WaitForCallbacks
// deduplicates by ID, and the real listener always assigns one, so a blank ID
// here would collapse every hit into a single one.
var hitSeq atomic.Int64

// newCallbackServer stands up a stand-in for Aperture's own /collab/{token}
// listener: it records every hit against the token under the identifier
// segment that follows it, exactly as handlers_collaborator.go does. It
// serves TLS, because the https:// payloads only confirm against a listener
// that speaks TLS -- the same constraint a victim's browser would face.
func newCallbackServer(t *testing.T, reg *collaborator.Registry) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path is /collab/<token>/<identifier>/...; anything shorter is
		// not something the scanner would ever send.
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "collab" {
			reg.Record(parts[1], collaborator.Interaction{
				ID:         fmt.Sprintf("hit-%d", hitSeq.Add(1)),
				Protocol:   "http",
				Timestamp:  time.Now(),
				RemoteAddr: "127.0.0.1",
				Identifier: parts[2],
			})
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTargetServer emulates the vulnerable shapes under test, one per route:
//   - /host: builds its redirect from the Host header (the bfgs.nl case)
//   - /fwd: builds its redirect from X-Forwarded-Host
//   - /ref: redirects back to the Referer
//   - /login?next=: a naive filter that rejects "http(s)://" and "//" but
//     trusts everything else -- the shape browser normalization bypasses
//   - /hop?next= and /landing?to=: a two-step chain that only reaches the
//     destination if the scanner follows the intermediate redirect
//   - /go/... and /redirect/...: destination taken from the path
//   - /clean: no redirects at all
func newTargetServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.URL.Path == "/host":
			// Trusts the Host header outright.
			w.Header().Set("Location", "https://"+r.Host+"/")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/fwd":
			if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
				w.Header().Set("Location", "https://"+xfh+"/home")
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/ref":
			if ref := r.Referer(); ref != "" {
				w.Header().Set("Location", ref)
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/login":
			next := q.Get("next")
			// The naive filter: absolute and protocol-relative values are
			// rejected, anything else is trusted as a relative destination.
			if next == "" || strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") || strings.HasPrefix(next, "//") {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/hop":
			w.Header().Set("Location", "/landing?to="+url.QueryEscape(q.Get("next")))
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/landing":
			w.Header().Set("Location", q.Get("to"))
			w.WriteHeader(http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/go/") || strings.HasPrefix(r.URL.Path, "/redirect/"):
			// The destination is everything after the route segment,
			// raw, so "https://" and "//" survive intact.
			rest := r.URL.Path[strings.Index(strings.TrimPrefix(r.URL.Path, "/"), "/")+2:]
			w.Header().Set("Location", rest)
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// hostOf returns host[:port] for a test server, the form CallbackBase uses.
func hostOf(srv *httptest.Server) string {
	return strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
}

// runAgainst runs the scanner against target with a fresh callback token and
// returns the result, so each test gets its own attribution namespace.
func runAgainst(t *testing.T, target string, cbSrv *httptest.Server, reg *collaborator.Registry, follow bool) *Result {
	t.Helper()
	token := reg.NewToken()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := Run(ctx, Request{
		URL:             target,
		CallbackBase:    hostOf(cbSrv) + "/collab/" + token,
		CallbackPoll:    CallbackPollConfig{Registry: reg, Token: token, Provider: "aperture"},
		FollowRedirects: follow,
	})
	if err != nil {
		t.Fatalf("Run(%s): %v", target, err)
	}
	return res
}

// findingsIn returns the findings a named module reported, or fails the test
// if the module isn't in the result at all.
func findingsIn(t *testing.T, res *Result, moduleID string) []Finding {
	t.Helper()
	for _, m := range res.Modules {
		if m.ID == moduleID {
			return m.Findings
		}
	}
	t.Fatalf("module %q missing from result", moduleID)
	return nil
}

// totalFindings counts findings across every module.
func totalFindings(res *Result) int {
	n := 0
	for _, m := range res.Modules {
		n += len(m.Findings)
	}
	return n
}

// TestHostHeaderRedirectConfirmed covers the bfgs.nl shape: a server that
// builds its redirect from the Host header. Only the callback host is ever
// injected, so this only passes if confirmation requests the callback under
// the probe's own path.
func TestHostHeaderRedirectConfirmed(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/host", cb, reg, true)
	got := findingsIn(t, res, "host-header")
	if len(got) != 1 {
		t.Fatalf("host-header findings = %d, want 1 (%+v)", len(got), got)
	}
	if !strings.Contains(got[0].Label, "Host header") {
		t.Errorf("label %q does not name the Host header", got[0].Label)
	}
	if got[0].Request == nil || got[0].Request.Headers["Host"] == "" {
		t.Errorf("captured request should record the injected Host header, got %+v", got[0].Request)
	}
}

// TestForwardedHostRedirectConfirmed checks that a forwarded-host header is
// attributed to exactly the header the app trusted, not to its siblings.
func TestForwardedHostRedirectConfirmed(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/fwd", cb, reg, true)
	got := findingsIn(t, res, "forwarded-host")
	if len(got) != 1 {
		t.Fatalf("forwarded-host findings = %d, want 1 (%+v)", len(got), got)
	}
	if !strings.Contains(got[0].Label, "X-Forwarded-Host") {
		t.Errorf("label %q should name X-Forwarded-Host only", got[0].Label)
	}
}

// TestRefererRedirectConfirmed checks the Referer-bounce shape.
func TestRefererRedirectConfirmed(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/ref", cb, reg, true)
	if got := findingsIn(t, res, "referer"); len(got) != 1 {
		t.Fatalf("referer findings = %d, want 1", len(got))
	}
}

// TestBrowserNormalizationBypassesFilter checks that the naive filter on
// /login rejects absolute and protocol-relative values (no finding) while
// browser-normalized shapes (backslash, tab, missing slashes) get through.
func TestBrowserNormalizationBypassesFilter(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/login?next=/dashboard", cb, reg, true)

	if got := findingsIn(t, res, "absolute-url"); len(got) != 0 {
		t.Errorf("absolute-url should be filtered by /login, got %d finding(s)", len(got))
	}
	if got := findingsIn(t, res, "protocol-relative"); len(got) != 0 {
		t.Errorf("protocol-relative should be filtered by /login, got %d finding(s)", len(got))
	}
	if got := findingsIn(t, res, "backslash-trick"); len(got) != 1 {
		t.Errorf("backslash-trick should bypass /login, got %d finding(s)", len(got))
	}
	if got := findingsIn(t, res, "whitespace-control"); len(got) != 1 {
		t.Errorf("whitespace-control should bypass /login, got %d finding(s)", len(got))
	}
}

// TestFollowRedirectsControlsChainConfirmation checks the multi-hop
// behavior: /hop only reaches the callback through /landing, so the chain is
// only confirmed when following redirects is on, and that's the default.
func TestFollowRedirectsControlsChainConfirmation(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	on := runAgainst(t, target.URL+"/hop?next=/home", cb, reg, true)
	if got := findingsIn(t, on, "absolute-url"); len(got) != 1 {
		t.Errorf("with follow on, /hop chain should confirm absolute-url, got %d finding(s)", len(got))
	}
	if !on.FollowRedirects {
		t.Errorf("result should report FollowRedirects=true")
	}

	off := runAgainst(t, target.URL+"/hop?next=/home", cb, reg, false)
	if got := findingsIn(t, off, "absolute-url"); len(got) != 0 {
		t.Errorf("with follow off, /hop chain should not confirm, got %d finding(s)", len(got))
	}
	if off.FollowRedirects {
		t.Errorf("result should report FollowRedirects=false")
	}
}

// TestPathSegmentRedirectConfirmed checks destinations taken from the path
// rather than a query parameter.
func TestPathSegmentRedirectConfirmed(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/clean", cb, reg, true)
	if got := findingsIn(t, res, "path-absolute"); len(got) == 0 {
		t.Errorf("path-absolute should confirm against /go/ or /redirect/ routes, got none")
	}
	if got := findingsIn(t, res, "path-protocol-relative"); len(got) == 0 {
		t.Errorf("path-protocol-relative should confirm against /go/ or /redirect/ routes, got none")
	}
}

// TestCleanEndpointHasNoFindings guards against false positives: an endpoint
// that never redirects anywhere must produce no findings at all.
func TestCleanEndpointHasNoFindings(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	// A separate server with no redirect routes at all: the path-segment
	// probes fire at the origin, so reusing the redirecting target would
	// make this test flag its own /go/ route.
	clean := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(clean.Close)

	res := runAgainst(t, clean.URL+"/", cb, reg, true)
	if n := totalFindings(res); n != 0 {
		t.Errorf("clean endpoint produced %d finding(s), want 0", n)
	}
	if res.ProbesSent == 0 {
		t.Errorf("ProbesSent should count the probes fired, got 0")
	}
}

// TestOperatorHostHeaderIsHonored checks the Go Host-header fix: a Host header
// the operator supplies must reach the server, not be silently dropped.
func TestOperatorHostHeaderIsHonored(t *testing.T) {
	target := newTargetServer(t)
	res, err := send(context.Background(), nil, target.URL+"/host", map[string]string{"Host": "operator.test"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Location != "https://operator.test/" {
		t.Errorf("Location = %q, want %q (operator Host header was dropped)", res.Location, "https://operator.test/")
	}
	if res.Request.Headers["Host"] != "operator.test" {
		t.Errorf("captured request Host = %q, want operator.test", res.Request.Headers["Host"])
	}
}

// TestBrowserResolve checks the normalization that stands in for a browser's
// URL parser: each shape should resolve to the host a victim would reach.
func TestBrowserResolve(t *testing.T) {
	base, _ := url.Parse("https://target.example/login")
	cases := []struct {
		raw, wantHost string
	}{
		{"https://evil.example/x", "evil.example"},
		{"//evil.example/x", "evil.example"},
		{"/\\evil.example/x", "evil.example"},
		{"\\\\evil.example/x", "evil.example"},
		{"////evil.example/x", "evil.example"},
		{"/\t/evil.example/x", "evil.example"},
		{" //evil.example/x", "evil.example"},
		{"https:evil.example/x", "evil.example"},
		{"https:/\\evil.example/x", "evil.example"},
		{"https://target.example@evil.example/x", "evil.example"},
		{"/dashboard", "target.example"},
	}
	for _, c := range cases {
		got, err := browserResolve(base, c.raw)
		if err != nil {
			t.Errorf("browserResolve(%q): %v", c.raw, err)
			continue
		}
		if got.Host != c.wantHost {
			t.Errorf("browserResolve(%q).Host = %q, want %q", c.raw, got.Host, c.wantHost)
		}
	}
}

// TestIdentifiersAreUnique checks that parameters differing only in case, or
// otherwise sanitizing to the same readable form, still get distinct
// identifiers -- otherwise one hit would be credited to two probes.
func TestIdentifiersAreUnique(t *testing.T) {
	a := openRedirectIdentifierFor("absolute-url", "URL", "n1")
	b := openRedirectIdentifierFor("absolute-url", "url", "n1")
	c := openRedirectIdentifierFor("absolute-url", "u-r-l", "n1")
	if a == b || a == c || b == c {
		t.Errorf("identifiers collided: %q %q %q", a, b, c)
	}
	// The same probe in a later run must not reuse an earlier run's identifier,
	// or a shared callback token would credit old hits to the new run.
	if openRedirectIdentifierFor("absolute-url", "URL", "n1") == openRedirectIdentifierFor("absolute-url", "URL", "n2") {
		t.Errorf("identifier should differ across runs")
	}
}

// TestMergeHeadersProbeWins checks that a probe's own header replaces an
// operator header of the same name regardless of case, so an operator Host
// can't ride along beside the injected one.
func TestMergeHeadersProbeWins(t *testing.T) {
	merged := mergeHeaders(
		map[string]string{"host": "operator.test", "Cookie": "s=1"},
		map[string]string{"Host": "callback.test"},
	)
	if merged["Host"] != "callback.test" {
		t.Errorf("Host = %q, want callback.test", merged["Host"])
	}
	if _, ok := merged["host"]; ok {
		t.Errorf("operator's lowercase host should have been replaced")
	}
	if merged["Cookie"] != "s=1" {
		t.Errorf("unrelated operator headers should be kept")
	}
}

// TestSharedTokenDoesNotLeakEarlierHits covers a shared callback token used
// across two scans: the first scan's confirmed hit stays on the listener, and
// the second scan, against an endpoint that never redirects, must not inherit
// it. Identifiers carry a per-run nonce so that holds.
func TestSharedTokenDoesNotLeakEarlierHits(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)
	clean := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(clean.Close)

	token := reg.NewToken()
	scan := func(target string) *Result {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		res, err := Run(ctx, Request{
			URL:             target,
			CallbackBase:    hostOf(cb) + "/collab/" + token,
			CallbackPoll:    CallbackPollConfig{Registry: reg, Token: token, Provider: "aperture"},
			FollowRedirects: true,
		})
		if err != nil {
			t.Fatalf("Run(%s): %v", target, err)
		}
		return res
	}

	if got := findingsIn(t, scan(target.URL+"/ref"), "referer"); len(got) != 1 {
		t.Fatalf("first scan referer findings = %d, want 1", len(got))
	}
	if n := totalFindings(scan(clean.URL + "/")); n != 0 {
		t.Errorf("second scan inherited %d finding(s) from the first scan's hit, want 0", n)
	}
}
