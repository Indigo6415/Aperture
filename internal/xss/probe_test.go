package xss

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// probeTestServer is a page that echoes query parameter q through transform,
// wrapped in a div. It records every query value it was sent, so a test can
// count the probe and payload requests a scan made.
type probeTestServer struct {
	mu        sync.Mutex
	values    []string
	transform func(string) string
	status    int
}

// ServeHTTP reflects q (after the transform) and records the value.
func (s *probeTestServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("q")
	s.mu.Lock()
	s.values = append(s.values, v)
	s.mu.Unlock()
	if s.status != 0 {
		w.WriteHeader(s.status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	out := v
	if s.transform != nil {
		out = s.transform(v)
	}
	_, _ = w.Write([]byte("<html><body><div>" + out + "</div></body></html>"))
}

// seen returns a copy of every recorded value.
func (s *probeTestServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.values...)
}

// queryPoint is an injection point for query parameter q on srv.
func queryPoint(srv *httptest.Server) injectionPoint {
	return injectionPoint{
		Kind: kindQuery, PageURL: srv.URL, URL: srv.URL, Method: "GET", Param: "q",
		Defaults: url.Values{"q": {"seed"}},
	}
}

// TestProbeReadsSurvivingCharacters checks the first probe. With no filter every
// probe character comes back, and a filter that encodes angle brackets is seen
// as stripping them, while the quotes still survive.
func TestProbeReadsSurvivingCharacters(t *testing.T) {
	const canary = "apxss0123456789ab"
	ctx := context.Background()

	open := &probeTestServer{}
	srv := httptest.NewServer(open)
	defer srv.Close()
	p := probePoint(ctx, make(chan struct{}, 4), newClient(), queryPoint(srv), canary, nil)
	if !p.reflected {
		t.Fatal("unfiltered probe: expected a reflection")
	}
	for i := 0; i < len(probeSpecials); i++ {
		if !p.survives[probeSpecials[i]] {
			t.Errorf("unfiltered probe: %q did not survive", probeSpecials[i])
		}
	}

	encoded := &probeTestServer{transform: func(s string) string {
		return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(s)
	}}
	srv2 := httptest.NewServer(encoded)
	defer srv2.Close()
	p = probePoint(ctx, make(chan struct{}, 4), newClient(), queryPoint(srv2), canary, nil)
	if !p.reflected {
		t.Fatal("angle-encoded probe: expected a reflection")
	}
	if p.survives['<'] || p.survives['>'] {
		t.Error("angle-encoded probe: < and > should not survive")
	}
	if !p.survives['"'] {
		t.Error("angle-encoded probe: a double quote should still survive")
	}
}

// TestProbeFindsStrippedTokens checks the second probe: a filter that removes the
// word alert reports alert as stripped, and a payload using it is not viable.
func TestProbeFindsStrippedTokens(t *testing.T) {
	const canary = "apxss0123456789ab"
	srv := httptest.NewServer(&probeTestServer{transform: func(s string) string {
		return strings.ReplaceAll(s, "alert", "")
	}})
	defer srv.Close()
	p := probePoint(context.Background(), make(chan struct{}, 4), newClient(), queryPoint(srv), canary, nil)
	if !strings.Contains(strings.Join(p.stripped, " "), "alert") {
		t.Fatalf("stripped = %v, want alert listed", p.stripped)
	}
	if p.viable("alert(1)") {
		t.Error("a payload containing a stripped token should not be viable")
	}
	if !p.viable("prompt(1)") {
		t.Error("a payload without a stripped token should stay viable")
	}
}

// TestProbeMarksUnreflectedAndBlocked checks the two states that skip a point or
// keep every candidate: no reflection at all, and a WAF refusing the probe.
func TestProbeMarksUnreflectedAndBlocked(t *testing.T) {
	const canary = "apxss0123456789ab"
	ctx := context.Background()

	ignore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>nothing here</body></html>"))
	}))
	defer ignore.Close()
	if p := probePoint(ctx, make(chan struct{}, 4), newClient(), queryPoint(ignore), canary, nil); p.reflected || p.blocked {
		t.Errorf("unreflected point: reflected=%v blocked=%v, want both false", p.reflected, p.blocked)
	}

	waf := httptest.NewServer(&probeTestServer{status: http.StatusForbidden})
	defer waf.Close()
	p := probePoint(ctx, make(chan struct{}, 4), newClient(), queryPoint(waf), canary, nil)
	if !p.blocked {
		t.Fatal("a 403 probe should be marked blocked")
	}
	if !p.viable(`<script>alert(1)</script>`) {
		t.Error("a blocked probe says nothing, so every payload stays viable")
	}
}

// TestProbeMarkersFitTruncation checks the markers stay short. A reflection cut
// at 30 characters must still carry the whole probe, or the point would be missed.
func TestProbeMarkersFitTruncation(t *testing.T) {
	open, closer := probeMarkers("apxss0123456789ab")
	if total := len(open) + len(probeSpecials) + len(closer); total > 30 {
		t.Fatalf("probe is %d bytes, want at most 30 so truncate:30 keeps it", total)
	}
}

// TestProbeDecodedReflectionIsAReflection checks that a response which echoes the
// markers only after HTML references are decoded still counts as a reflection, but
// with no characters surviving as-is.
func TestProbeDecodedReflectionIsAReflection(t *testing.T) {
	const canary = "apxss0123456789ab"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every character is written as a hexadecimal numeric reference, as a
		// hex-encoding filter would write it.
		var b strings.Builder
		for _, c := range r.URL.Query().Get("q") {
			b.WriteString("&#x" + strconv.FormatInt(int64(c), 16) + ";")
		}
		_, _ = w.Write([]byte("<html><body>" + b.String() + "</body></html>"))
	}))
	defer srv.Close()
	p := probePoint(context.Background(), make(chan struct{}, 4), newClient(), queryPoint(srv), canary, nil)
	if !p.reflected {
		t.Fatal("hex-encoded echo: expected a reflection")
	}
	for i := 0; i < len(probeSpecials); i++ {
		if p.survives[probeSpecials[i]] {
			t.Errorf("hex-encoded echo: %q should not survive", probeSpecials[i])
		}
	}
}

// TestRunSkipsUnreflectedParameters checks that a parameter the page does not echo
// costs only its probe: once the probe reports nothing reflected, no payloads are
// sent for that parameter.
func TestRunSkipsUnreflectedParameters(t *testing.T) {
	var mu sync.Mutex
	var bValues []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a is echoed. b is read and ignored, so its probe finds nothing.
		if v := r.URL.Query().Get("b"); v != "" {
			mu.Lock()
			bValues = append(bValues, v)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><div>" + r.URL.Query().Get("a") + "</div></body></html>"))
	}))
	defer ts.Close()

	if _, err := Run(context.Background(), Request{URL: ts.URL + "/p?a=seed&b=seed", SkipBrowser: true}, OOBConfig{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	probes := 0
	for _, v := range bValues {
		if v != "seed" {
			probes++
		}
	}
	if probes != 1 {
		t.Errorf("parameter b was sent %d non-default values, want exactly the 1 probe", probes)
	}
}

// TestRunHonorsPayloadBudget checks that a point which never executes is tried
// with no more payloads than the budget allows, plus the two probes.
func TestRunHonorsPayloadBudget(t *testing.T) {
	const budget = 10
	srv := &probeTestServer{transform: func(s string) string {
		// Escape everything, so nothing can run, but keep the probe's characters visible as text.
		return html.EscapeString(s)
	}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	if _, err := Run(context.Background(), Request{URL: ts.URL + "/p?q=seed", Params: []string{"q"}, SkipBrowser: true, PayloadBudget: budget}, OOBConfig{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Only payloads count here. The seed page, the probes (both carry the pb
	// marker), and requests with no query at all (the crawler's robots.txt
	// fetch, say) are not candidate payloads.
	payloads := 0
	for _, v := range srv.seen() {
		if v == "" || v == "seed" || strings.HasPrefix(v, "pb") {
			continue
		}
		payloads++
	}
	if payloads > budget {
		t.Errorf("sent %d payloads, want at most the budget of %d", payloads, budget)
	}
	if payloads == 0 {
		t.Error("no payloads were sent")
	}
}

// TestRunStopsAtFirstExecutingPayload checks that a point which runs its first
// payload stops there, so the payload budget is not spent after a finding.
func TestRunStopsAtFirstExecutingPayload(t *testing.T) {
	srv := &probeTestServer{}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	res, err := Run(context.Background(), Request{URL: ts.URL + "/p?q=seed", Params: []string{"q"}, SkipBrowser: true}, OOBConfig{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !anyFinding(res) {
		t.Fatal("an unescaped reflection should be a finding")
	}
	payloads := 0
	for _, v := range srv.seen() {
		if v != "seed" && !strings.HasPrefix(v, "pb") && !strings.HasPrefix(v, "pe") {
			payloads++
		}
	}
	if payloads > 60 {
		t.Errorf("sent %d payloads before stopping; the first executing payload should end the point", payloads)
	}
}
