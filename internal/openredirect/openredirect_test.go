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
//   - /fwd: builds its redirect from X-Forwarded-Host, keeping the whole value
//   - /fwdstrip: builds its redirect from X-Forwarded-Host's host alone, dropping
//     any path the proxy-supplied value carried
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
		case r.URL.Path == "/fwdstrip":
			if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
				// Keeps only the part before the first "/", as an app that
				// parses the header as a bare host would.
				host, _, _ := strings.Cut(xfh, "/")
				w.Header().Set("Location", "https://"+host+"/home")
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

// TestForwardedHostRedirectKeepsIdentifierPath covers an app that echoes the
// whole X-Forwarded-Host value into its redirect. The redirect itself carries
// the probe's identifier, so the confirming hop is the redirect the target
// sent, not a URL the scanner built.
func TestForwardedHostRedirectKeepsIdentifierPath(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/fwd", cb, reg, true)
	got := findingsIn(t, res, "forwarded-host")
	if len(got) != 1 {
		t.Fatalf("forwarded-host findings = %d, want 1", len(got))
	}
	f := got[0]
	if strings.Contains(f.Detail, "rebuilt") || strings.Contains(f.Detail, "did not keep") {
		t.Errorf("detail should not say the scanner rebuilt the callback: %q", f.Detail)
	}
	// The redirect kept the identifier, so the target's own URL is the proof.
	if f.Confidence != ConfidenceConfirmed {
		t.Errorf("confidence = %q, want %q when the redirect kept the identifier", f.Confidence, ConfidenceConfirmed)
	}
	// /fwd redirects to the sent value plus "/home", so the confirming hop must
	// be exactly that redirect target.
	want := "https://" + f.Request.Headers["X-Forwarded-Host"] + "/home"
	if got := callbackHop(t, f); got != want {
		t.Errorf("callback hop = %q, want the redirect's own target %q", got, want)
	}
}

// TestForwardedHostRedirectRebuildsDroppedPath covers an app that keeps only the
// host of X-Forwarded-Host. The redirect loses the identifier, so the scanner
// requests the callback under it itself, and the finding says so.
func TestForwardedHostRedirectRebuildsDroppedPath(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/fwdstrip", cb, reg, true)
	got := findingsIn(t, res, "forwarded-host")
	if len(got) != 1 {
		t.Fatalf("forwarded-host findings = %d, want 1 (%+v)", len(got), got)
	}
	f := got[0]
	if !strings.Contains(f.Detail, "did not keep this probe's identifier path") {
		t.Errorf("detail %q should say the redirect dropped the identifier path", f.Detail)
	}
	// The scanner built the callback URL, so the hit does not prove the target
	// followed its own redirect to it.
	if f.Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want %q when the scanner rebuilt the callback", f.Confidence, ConfidenceLikely)
	}
	if !strings.Contains(f.Chain[len(f.Chain)-1].URL, "/collab/") {
		t.Errorf("final hop %q should be the rebuilt callback URL", f.Chain[len(f.Chain)-1].URL)
	}
}

// callbackHop returns the URL of the confirming hop in f's chain, failing the
// test if there isn't one.
func callbackHop(t *testing.T, f Finding) string {
	t.Helper()
	// The confirming hop is the last one marked "callback".
	for i := len(f.Chain) - 1; i >= 0; i-- {
		if f.Chain[i].Kind == "callback" {
			return f.Chain[i].URL
		}
	}
	t.Fatalf("chain has no callback hop: %+v", f.Chain)
	return ""
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

// TestFindingCarriesTimedChain checks that a confirmed finding records every
// request from the probe to the callback: the probe, each followed redirect,
// and the confirming callback request, in order, with status codes and
// timings. The /hop -> /landing route is a two-step chain, so the expected
// shape is probe (302) -> redirect (302) -> callback (200).
func TestFindingCarriesTimedChain(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/hop?next=/home", cb, reg, true)
	findings := findingsIn(t, res, "absolute-url")
	if len(findings) != 1 {
		t.Fatalf("want 1 absolute-url finding, got %d", len(findings))
	}
	chain := findings[0].Chain
	if len(chain) != 3 {
		t.Fatalf("want 3 hops (probe, redirect, callback), got %d: %+v", len(chain), chain)
	}

	wantKinds := []string{"probe", "redirect", "callback"}
	wantStatus := []int{http.StatusFound, http.StatusFound, http.StatusOK}
	for i, h := range chain {
		if h.Step != i+1 {
			t.Errorf("hop %d: Step = %d, want %d", i, h.Step, i+1)
		}
		if h.Kind != wantKinds[i] {
			t.Errorf("hop %d: Kind = %q, want %q", i, h.Kind, wantKinds[i])
		}
		if h.StatusCode != wantStatus[i] {
			t.Errorf("hop %d: StatusCode = %d, want %d", i, h.StatusCode, wantStatus[i])
		}
		if h.Method != http.MethodGet {
			t.Errorf("hop %d: Method = %q, want GET", i, h.Method)
		}
		if h.DurationMs < 0 {
			t.Errorf("hop %d: DurationMs = %v, want >= 0", i, h.DurationMs)
		}
		if i > 0 && h.OffsetMs < chain[i-1].OffsetMs {
			t.Errorf("hop %d: OffsetMs %v went backwards from %v", i, h.OffsetMs, chain[i-1].OffsetMs)
		}
	}
	if chain[0].OffsetMs != 0 {
		t.Errorf("probe hop OffsetMs = %v, want 0", chain[0].OffsetMs)
	}
	if chain[1].Location == "" {
		t.Errorf("redirect hop should record its Location")
	}
	if !strings.Contains(chain[2].URL, hostOf(cb)) {
		t.Errorf("callback hop URL %q should point at the callback host %s", chain[2].URL, hostOf(cb))
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
		{"///evil.example/x", "evil.example"},
		{"/\\/evil.example/x", "evil.example"},
		{"https:\\\\evil.example/x", "evil.example"},
		{"https:///evil.example/x", "evil.example"},
		{"https://evil.example/#target.example", "evil.example"},
		{"https://evil.example/target.example", "evil.example"},
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

// shrinkBaselineTuning makes the baseline's timeout and retry pause short for
// one test, and restores the production values when the test ends.
func shrinkBaselineTuning(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldTimeout, oldPause := baselineTimeout, baselineRetryPause
	baselineTimeout, baselineRetryPause = timeout, time.Millisecond
	t.Cleanup(func() { baselineTimeout, baselineRetryPause = oldTimeout, oldPause })
}

// TestTesterRequestCarriesCallbackURL checks that a hostOnly finding hands the
// Tester the callback URL under the probe's identifier, with the probe's full
// header set, and that the probe's own request is still on the chain.
func TestTesterRequestCarriesCallbackURL(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/fwd", cb, reg, true)
	got := findingsIn(t, res, "forwarded-host")
	if len(got) != 1 {
		t.Fatalf("forwarded-host findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Request == nil {
		t.Fatal("finding has no Request for Send to Tester")
	}
	if f.Request.Headers["X-Forwarded-Host"] == "" {
		t.Errorf("Tester headers %v should include X-Forwarded-Host", f.Request.Headers)
	}
	if f.Request.Headers["User-Agent"] == "" {
		t.Errorf("Tester headers %v should include the User-Agent the probe sent", f.Request.Headers)
	}

	// The URL handed to the Tester must be the callback hop that confirmed the
	// hit, not the target.
	var callbackURL string
	for _, h := range f.Chain {
		if h.Kind == "callback" {
			callbackURL = h.URL
		}
	}
	if callbackURL == "" {
		t.Fatalf("chain has no callback hop: %+v", f.Chain)
	}
	if f.Request.URL != callbackURL {
		t.Errorf("Tester URL = %q, want the callback hop URL %q", f.Request.URL, callbackURL)
	}
	if !strings.Contains(f.Request.URL, "/collab/") {
		t.Errorf("Tester URL %q should contain the callback path /collab/", f.Request.URL)
	}
}

// TestBaselineRetriesThenSucceeds stalls the first two baseline attempts past
// the per-attempt timeout and expects the third to succeed.
func TestBaselineRetriesThenSucceeds(t *testing.T) {
	shrinkBaselineTuning(t, 200*time.Millisecond)

	var baselineHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("aperture-openredirect-baseline") != "1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The first two baseline attempts hang until the client gives up.
		if baselineHits.Add(1) <= 2 {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		// Headers must be set before WriteHeader, or the Location is dropped.
		w.Header().Set("Location", "/home")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	stats := &runStats{}
	res, err := baselineRequest(context.Background(), srv.URL+"/?aperture-openredirect-baseline=1", nil, stats)
	if err != nil {
		t.Fatalf("baselineRequest: %v", err)
	}
	if baselineHits.Load() != 3 {
		t.Errorf("baseline attempts = %d, want 3", baselineHits.Load())
	}
	// The two stalled attempts are timeouts, the third succeeded.
	if stats.requests.Load() != 3 || stats.timedOut.Load() != 2 {
		t.Errorf("stats = %d requests, %d timed out; want 3 and 2", stats.requests.Load(), stats.timedOut.Load())
	}
	if res.StatusCode != http.StatusFound || res.Location != "/home" {
		t.Errorf("baseline = %d %q, want 302 /home", res.StatusCode, res.Location)
	}
}

// TestBaselineFailureDoesNotAbortRun makes every baseline attempt fail and
// expects the run to still finish, with the failure recorded on the baseline.
func TestBaselineFailureDoesNotAbortRun(t *testing.T) {
	shrinkBaselineTuning(t, 200*time.Millisecond)

	// Port 1 refuses connections, so every attempt fails straight away. With no
	// callback base the run returns right after the baseline, so no probes are
	// sent at the dead host.
	res, err := Run(context.Background(), Request{
		URL: "http://127.0.0.1:1/endpoint",
	})
	if err != nil {
		t.Fatalf("Run returned error, want it to continue: %v", err)
	}
	if res.Baseline.Error == "" {
		t.Error("Baseline.Error should explain the failed baseline")
	}
	if res.Baseline.StatusCode != 0 {
		t.Errorf("Baseline.StatusCode = %d, want 0 when the baseline failed", res.Baseline.StatusCode)
	}
	if len(res.Modules) == 0 {
		t.Error("run should still report its modules after a failed baseline")
	}
}

// TestNewVectorsBypassNaiveFilter checks the vectors added to the module list
// against the same naive /login filter. Backslash and scheme-backslash values
// start with neither "//" nor "https://", so the filter passes them and the
// browser-resolved host confirms them. Triple-slash values begin with "//", so
// that filter rejects them and they produce no finding.
func TestNewVectorsBypassNaiveFilter(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newTargetServer(t)

	res := runAgainst(t, target.URL+"/login?next=/dashboard", cb, reg, true)
	for _, id := range []string{"backslash-slash", "https-backslash"} {
		if got := findingsIn(t, res, id); len(got) != 1 {
			t.Errorf("%s should bypass /login, got %d finding(s)", id, len(got))
		}
	}
	for _, id := range []string{"triple-slash", "https-triple-slash", "allowlist-fragment"} {
		if got := findingsIn(t, res, id); len(got) != 0 {
			t.Errorf("%s should be rejected by /login's filter, got %d finding(s)", id, len(got))
		}
	}
}

// TestClientSideRedirectConfirmed checks the client-side branch in the case it
// should confirm. The page puts the echoed value into a window.location.href
// assignment, so the redirect literal names the callback host and the probe's
// identifier. The finding is "likely", because the scanner requested the
// callback itself rather than following a 3xx.
func TestClientSideRedirectConfirmed(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	page := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		fmt.Fprintf(w, `<html><body><script>window.location.href = "%s";</script></body></html>`, next)
	}))
	t.Cleanup(page.Close)

	res := runAgainst(t, page.URL+"/bounce?next=/dashboard", cb, reg, true)
	got := findingsIn(t, res, "absolute-url")
	if len(got) != 1 {
		t.Fatalf("absolute-url findings = %d, want 1 (%+v)", len(got), got)
	}
	if got[0].Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want %q for a client-side redirect", got[0].Confidence, ConfidenceLikely)
	}
	if !strings.Contains(got[0].Detail, "client-side redirect") {
		t.Errorf("detail %q should say the redirect was client-side", got[0].Detail)
	}
}

// TestClientSideLiteralMustNameProbe checks clientRedirectTo directly. A
// literal with the callback host but another identifier, or with the
// identifier but another host, is not a redirect to this probe's callback.
func TestClientSideLiteralMustNameProbe(t *testing.T) {
	const cb, id = "aperture.example:8443", "or-absolute-url-x-1-2"
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"meta refresh names both", `<meta http-equiv="refresh" content="0;url=https://` + cb + `/collab/t/` + id + `/">`, true},
		{"script literal names both", `<script>location.replace("https://` + cb + `/collab/t/` + id + `/")</script>`, true},
		{"script literal, other identifier", `<script>location.href="https://` + cb + `/collab/t/other/"</script>`, false},
		{"script literal, other host", `<script>location.href="https://elsewhere.example/` + id + `"</script>`, false},
		{"echo only, no redirect", `<input value="https://` + cb + `/collab/t/` + id + `/">`, false},
		{"unrelated assignment", `<script>window.location.href = "/home"; var x = "` + cb + id + `";</script>`, false},
		{"comparison, not assignment", `<script>if (location.href == "https://` + cb + `/` + id + `") {}</script>`, false},
	}
	for _, c := range cases {
		if got := clientRedirectTo(c.body, cb, id); got != c.want {
			t.Errorf("%s: clientRedirectTo = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestEchoedValueWithUnrelatedScriptNotReported guards against a false
// positive in the client-side branch. The page echoes the next parameter into
// an input, and separately has an ordinary script that sets location.href to
// its own path. The echo puts the callback host into the body, but nothing
// redirects to it, so no probe should be reported.
func TestEchoedValueWithUnrelatedScriptNotReported(t *testing.T) {
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	page := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		fmt.Fprintf(w, `<html><body><input name="q" value="%s"><script>window.location.href = "/home";</script></body></html>`, next)
	}))
	t.Cleanup(page.Close)

	res := runAgainst(t, page.URL+"/search?next=/dashboard", cb, reg, true)
	if n := totalFindings(res); n != 0 {
		t.Errorf("echoed value next to an unrelated redirect script produced %d finding(s), want 0", n)
	}
}
