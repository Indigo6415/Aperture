package openredirect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
)

// blockedPrefix is the naive filter the parser-differential routes share: it
// rejects the spellings a filter author thinks of first (case-sensitive
// "http://" and "https://", and a leading "//"), and trusts everything else.
func blockedPrefix(v string) bool {
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "//")
}

// redirectTo sends a 302 to loc with loc as the Location header value.
func redirectTo(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

// newParserTarget emulates the apps the parser-differential and CRLF modules
// are aimed at, one route per shape:
//   - /parse: the naive filter above, redirecting whatever it lets through
//   - /double: the same filter, but decodes the value a second time before
//     using it (the double-decoding app the encoded payloads need)
//   - /strip: removes "https://" wherever it occurs, then redirects to what is left
//   - /blocklist: refuses only the dotted-quad callback literal
//   - /crlf: writes the decoded value raw into its response header block, so
//     a CR/LF in the value really does split the response
func newParserTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		switch r.URL.Path {
		case "/parse":
			if next == "" || blockedPrefix(next) {
				w.WriteHeader(http.StatusOK)
				return
			}
			redirectTo(w, next)
		case "/double":
			if next == "" || blockedPrefix(next) {
				w.WriteHeader(http.StatusOK)
				return
			}
			decoded, err := url.QueryUnescape(next)
			if err != nil || decoded == "" {
				w.WriteHeader(http.StatusOK)
				return
			}
			redirectTo(w, decoded)
		case "/strip":
			stripped := strings.ReplaceAll(next, "https://", "")
			if stripped == "" {
				w.WriteHeader(http.StatusOK)
				return
			}
			redirectTo(w, stripped)
		case "/blocklist":
			// Only the literal dotted-quad host is refused, so a spelling of the
			// same address that a string match misses gets through.
			if u, err := url.Parse(next); err == nil && u.Hostname() == "127.0.0.1" {
				w.WriteHeader(http.StatusOK)
				return
			}
			if next == "" {
				w.WriteHeader(http.StatusOK)
				return
			}
			redirectTo(w, next)
		case "/crlf":
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			// The value is echoed into a header the app writes, as an app does
			// with a destination it reflects. A CR/LF in it ends that header
			// line and starts a new one, which is what injection looks like on
			// the wire.
			fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nX-Echo: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", next)
			buf.Flush()
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestParserDifferentialsBypassNaiveFilter checks the shapes a naive
// "reject http:// and //" filter lets through. Each one must confirm, exactly
// once, against the one parameter the route reads. The shapes the filter does
// reject, or that only a second decode would resolve, must not confirm.
func TestParserDifferentialsBypassNaiveFilter(t *testing.T) {
	t.Parallel()
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newParserTarget(t)

	res := runAgainst(t, target.URL+"/parse?next=/dashboard", cb, reg, true)
	for _, id := range []string{"scheme-case", "scheme-tab", "backslash-alternating"} {
		if got := findingsIn(t, res, id); len(got) != 1 {
			t.Errorf("%s should bypass /parse, got %d finding(s)", id, len(got))
		}
	}
	for _, id := range []string{"absolute-url", "protocol-relative", "nested-scheme", "scheme-encoded"} {
		if got := findingsIn(t, res, id); len(got) != 0 {
			t.Errorf("%s should not confirm on /parse, got %d finding(s)", id, len(got))
		}
	}
}

// TestEncodedSchemeNeedsSecondDecode checks the encoded-scheme shape on the
// app that decodes twice. The first decode leaves "https%3A%2F%2F" for the
// filter, and the second makes it a live https URL that reaches the callback.
func TestEncodedSchemeNeedsSecondDecode(t *testing.T) {
	t.Parallel()
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newParserTarget(t)

	res := runAgainst(t, target.URL+"/double?next=/dashboard", cb, reg, true)
	if got := findingsIn(t, res, "scheme-encoded"); len(got) != 1 {
		t.Errorf("scheme-encoded should confirm on the double-decoding app, got %d finding(s)", len(got))
	}
}

// TestNestedSchemeSurvivesStripping checks the shape a filter that removes
// "https://" once can't handle: stripping leaves a live https URL in the value.
func TestNestedSchemeSurvivesStripping(t *testing.T) {
	t.Parallel()
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newParserTarget(t)

	res := runAgainst(t, target.URL+"/strip?next=/dashboard", cb, reg, true)
	if got := findingsIn(t, res, "nested-scheme"); len(got) != 1 {
		t.Errorf("nested-scheme should survive the stripping filter, got %d finding(s)", len(got))
	}
}

// TestBlocklistEvadedBySpellings checks a blocklist that refuses the dotted-quad
// callback literal. Every other spelling of that address (five IP-literal
// forms and the ideographic-dot host) must still reach the callback. The plain
// absolute URL must not, since it is the spelling the blocklist refuses.
func TestBlocklistEvadedBySpellings(t *testing.T) {
	t.Parallel()
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newParserTarget(t)

	res := runAgainst(t, target.URL+"/blocklist?next=/dashboard", cb, reg, true)
	if got := findingsIn(t, res, "absolute-url"); len(got) != 0 {
		t.Errorf("absolute-url should be blocked, got %d finding(s)", len(got))
	}
	if got := findingsIn(t, res, "ip-literal"); len(got) != 5 {
		t.Errorf("ip-literal should reach the callback in all 5 spellings, got %d finding(s)", len(got))
	}
	if got := findingsIn(t, res, "unicode-dot"); len(got) != 1 {
		t.Errorf("unicode-dot should reach the callback, got %d finding(s)", len(got))
	}
}

// TestCRLFInjectionDetected checks the CR/LF module against the raw-writing
// route. The shapes that inject on a single decode must be found, and the
// percent-encoded shapes, which need a second decode, must not be.
func TestCRLFInjectionDetected(t *testing.T) {
	t.Parallel()
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	target := newParserTarget(t)

	res := runAgainst(t, target.URL+"/crlf?next=/dashboard", cb, reg, true)
	got := findingsIn(t, res, "crlf-injection")
	count := func(prefix string) int {
		n := 0
		for _, f := range got {
			if strings.HasPrefix(f.Label, prefix+" injects") && strings.Contains(f.Label, `"next"`) {
				n++
			}
		}
		return n
	}
	if n := count("CRLF Set-Cookie"); n != 1 {
		t.Errorf("CRLF Set-Cookie findings = %d, want 1", n)
	}
	if n := count("CRLF Location"); n != 1 {
		t.Errorf("CRLF Location findings = %d, want 1", n)
	}
	if n := count("percent-encoded CRLF Set-Cookie"); n != 0 {
		t.Errorf("percent-encoded CRLF Set-Cookie findings = %d, want 0 on a single-decode app", n)
	}
	for _, f := range got {
		if f.Confidence != ConfidenceConfirmed {
			t.Errorf("CRLF finding %q confidence = %q, want confirmed", f.Label, f.Confidence)
		}
		if f.Callback {
			t.Errorf("CRLF finding %q should not claim a callback hit", f.Label)
		}
	}
}

// TestCRLFRunsWithoutCallback checks that the CR/LF module still runs with no
// callback listener, since it judges response headers directly, while the
// callback modules report the "not configured" notice and send nothing.
func TestCRLFRunsWithoutCallback(t *testing.T) {
	t.Parallel()
	target := newParserTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := Run(ctx, Request{URL: target.URL + "/crlf?next=/dashboard"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := findingsIn(t, res, "crlf-injection"); len(got) == 0 {
		t.Error("crlf-injection should find the injection with no callback configured")
	}
	abs := findingsIn(t, res, "absolute-url")
	if len(abs) != 1 || abs[0].Label != "Callback listener not configured" {
		t.Errorf("absolute-url without a callback = %+v, want the not-configured notice", abs)
	}
}

// TestClientSideRedirectNamesDOMSource checks that a client-side redirect's
// detail says which DOM property the page reads. The page reads location.search
// and then redirects to the echoed value, so the source is reported.
func TestClientSideRedirectNamesDOMSource(t *testing.T) {
	t.Parallel()
	reg := collaborator.NewRegistry()
	cb := newCallbackServer(t, reg)
	page := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		fmt.Fprintf(w, `<html><body><script>var q = location.search; window.location.href = "%s";</script></body></html>`, next)
	}))
	t.Cleanup(page.Close)

	res := runAgainst(t, page.URL+"/bounce?next=/dashboard", cb, reg, true)
	got := findingsIn(t, res, "absolute-url")
	if len(got) != 1 {
		t.Fatalf("absolute-url findings = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Detail, "reading location.search") {
		t.Errorf("detail %q should name the DOM source the page reads", got[0].Detail)
	}
}

// TestDOMSourcesIgnoreSinks checks the source list on its own. A property that
// is only assigned to (the redirect sink) is not a source, while one that is
// read, even in a comparison, is.
func TestDOMSourcesIgnoreSinks(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"assignment is a sink", `window.location.href = "/home";`, ""},
		{"read is a source", `var u = document.referrer;`, "document.referrer"},
		{"comparison is a read", `if (location.href == "/x") {}`, "location.href"},
		{"duplicates listed once", `a(location.search); b(location.search);`, "location.search"},
		{"read and sink together", `var s = location.hash; location.href = s;`, "location.hash"},
	}
	for _, c := range cases {
		got := strings.Join(domSourcesIn(c.body), ",")
		if got != c.want {
			t.Errorf("%s: domSourcesIn = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestMergeResultsFoldsEndpoints checks that merging a discovered endpoint's
// result into the operator's adds its findings to the matching module, sums
// the counts, and unions the parameter names.
func TestMergeResultsFoldsEndpoints(t *testing.T) {
	into := &Result{
		Modules:      []ModuleResult{{ID: "absolute-url", Findings: []Finding{{Label: "a"}}}},
		ParamsTested: []string{"next", "url"},
		ProbesSent:   10, Requests: 12, TimedOut: 1,
	}
	add := &Result{
		Modules:      []ModuleResult{{ID: "absolute-url", Findings: []Finding{{Label: "b"}}}},
		ParamsTested: []string{"url", "return"},
		ProbesSent:   5, Requests: 6, TimedOut: 2,
	}
	mergeResults(into, add)

	if n := len(into.Modules[0].Findings); n != 2 {
		t.Errorf("merged findings = %d, want 2", n)
	}
	if fmt.Sprint(into.ParamsTested) != "[next return url]" {
		t.Errorf("ParamsTested = %v, want [next return url]", into.ParamsTested)
	}
	if into.ProbesSent != 15 || into.Requests != 18 || into.TimedOut != 3 {
		t.Errorf("counts = probes %d requests %d timedOut %d, want 15 18 3", into.ProbesSent, into.Requests, into.TimedOut)
	}
}
