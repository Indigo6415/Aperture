package corsscan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// hostRewriter sends every request to srv while keeping the URL's own host
// name in the Host header, so a test can exercise hostnames with dots (for the
// regex-bypass and related-domain probes) without any real DNS.
type hostRewriter struct{ srv *httptest.Server }

// RoundTrip redirects the connection to the test server and leaves the
// request's Host intact, so the handler sees the hostname the test chose.
func (h hostRewriter) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = h.srv.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(clone)
}

// testRun runs the full scan against a handler served behind the test host
// name example.test, returning the per-module findings keyed by module ID.
func testRun(t *testing.T, handler http.HandlerFunc) map[string][]Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: hostRewriter{srv: srv}}
	res, err := runWithClient(context.Background(), Request{URL: "http://example.test/api/me"}, client)
	if err != nil {
		t.Fatalf("runWithClient: %v", err)
	}
	out := map[string][]Finding{}
	for _, m := range res.Modules {
		out[m.ID] = m.Findings
	}
	return out
}

// reflectOrigin returns a handler that echoes the Origin header back in
// Access-Control-Allow-Origin, with the supplied credentials header value (or
// no credentials header when acac is empty).
func reflectOrigin(acac string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			if acac != "" {
				w.Header().Set("Access-Control-Allow-Credentials", acac)
			}
		}
		io.WriteString(w, `{"ok":true}`)
	}
}

// TestRunFlagsOriginReflectionWithCredentials serves an endpoint that echoes any
// Origin back with credentials allowed, the classic exploitable CORS setup, and
// expects the critical credentialed finding.
func TestRunFlagsOriginReflectionWithCredentials(t *testing.T) {
	findings := testRun(t, reflectOrigin("true"))
	if len(findings["credentialed-reflection"]) != 1 {
		t.Fatalf("credentialed-reflection findings = %d, want 1", len(findings["credentialed-reflection"]))
	}
	if len(findings["reflected-origin"]) != 1 {
		t.Errorf("reflected-origin findings = %d, want 1", len(findings["reflected-origin"]))
	}
}

// TestRunQuietOnStaticEndpoint checks an endpoint with no CORS headers at all
// produces no findings, so the scanner doesn't cry wolf on ordinary responses.
func TestRunQuietOnStaticEndpoint(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "static")
	})
	for id, fs := range findings {
		if len(fs) != 0 {
			t.Fatalf("module %s reported %d findings on an endpoint with no CORS headers", id, len(fs))
		}
	}
}

// TestCredentialsFlagIsLiteralTrue checks that only the literal value "true"
// counts: browsers compare Access-Control-Allow-Credentials case-sensitively, so
// "TRUE" grants no credentialed read and must not be reported as critical.
func TestCredentialsFlagIsLiteralTrue(t *testing.T) {
	findings := testRun(t, reflectOrigin("TRUE"))
	if n := len(findings["credentialed-reflection"]); n != 0 {
		t.Errorf("credentialed-reflection reported %d finding(s) for ACAC: TRUE, want 0", n)
	}
	if n := len(findings["reflected-origin"]); n != 1 {
		t.Errorf("reflected-origin findings = %d, want 1", n)
	}
}

// TestCredentialsFlagMustReproduce checks that a credentials flag seen on only
// one response (a cached or one-off response) is not reported as critical: the
// flag must come back on a second identical request.
func TestCredentialsFlagMustReproduce(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			if first {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["credentialed-reflection"]); n != 0 {
		t.Errorf("credentialed-reflection reported a flag that did not reproduce: %d finding(s)", n)
	}
}

// TestNullOriginWithCredentialsIsFlagged checks that trusting the null origin
// is reported, and that the detail notes the credentials flag when present.
func TestNullOriginWithCredentialsIsFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		io.WriteString(w, "ok")
	})
	fs := findings["null-origin"]
	if len(fs) != 1 {
		t.Fatalf("null-origin findings = %d, want 1", len(fs))
	}
	if !strings.Contains(fs[0].Detail, "Access-Control-Allow-Credentials: true") {
		t.Errorf("null-origin detail does not mention the credentials flag: %q", fs[0].Detail)
	}
}

// TestRegexDotBypassIsFlagged checks an allowlist written as an unescaped regex
// (^https://example.test$, where "." matches any character) and the lookalike
// origin that slips through it.
func TestRegexDotBypassIsFlagged(t *testing.T) {
	allow := regexp.MustCompile(`^https?://example.test$`)
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && allow.MatchString(o) {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	var hit bool
	for _, f := range findings["related-domain-trust"] {
		if strings.Contains(f.Evidence, "exampleXtest") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("unescaped-dot regex bypass origin not reported: %+v", findings["related-domain-trust"])
	}
}

// TestEscapedAllowlistIsNotFlagged checks that the same allowlist with the dot
// escaped rejects the lookalike origin, so no related-domain finding appears.
func TestEscapedAllowlistIsNotFlagged(t *testing.T) {
	allow := regexp.MustCompile(`^https://example\.test$`)
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && allow.MatchString(o) {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["related-domain-trust"]); n != 0 {
		t.Errorf("escaped allowlist reported %d related-domain finding(s), want 0", n)
	}
}

// TestContainsCheckBypassIsFlagged checks an unanchored substring trust check:
// any origin that contains the hostname is accepted.
func TestContainsCheckBypassIsFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && strings.Contains(o, "example.test") {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if len(findings["related-domain-trust"]) == 0 {
		t.Error("substring-based origin check was not reported as a related-domain trust")
	}
}

// TestPreflightIgnoredWithoutOriginReflection checks that a preflight which
// lists DELETE and Authorization but never grants the attacker origin is not
// reported: a browser would block the request, so the permissive headers do not
// expose anything to a cross-origin page.
func TestPreflightIgnoredWithoutOriginReflection(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["preflight"]); n != 0 {
		t.Errorf("preflight reported %d finding(s) without the origin being allowed, want 0", n)
	}
}

// TestPreflightNeedsSuccessStatus checks that a preflight answered with an
// error status is not reported, since a browser would not proceed past it.
func TestPreflightNeedsSuccessStatus(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Methods", "DELETE")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["preflight"]); n != 0 {
		t.Errorf("preflight answered 404 was reported %d time(s), want 0", n)
	}
}

// TestPreflightPermissiveFindings checks the positive preflight case: origin
// reflected, DELETE allowed, and Authorization allowed all produce findings.
func TestPreflightPermissiveFindings(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["preflight"]); n != 3 {
		t.Errorf("preflight findings = %d, want 3 (origin, DELETE, Authorization)", n)
	}
}

// TestWildcardAllowHeadersDoNotCoverAuthorization checks that "*" in
// Access-Control-Allow-Headers is not treated as allowing Authorization: the
// Fetch spec excludes Authorization from the wildcard.
func TestWildcardAllowHeadersDoNotCoverAuthorization(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		io.WriteString(w, "ok")
	})
	for _, f := range findings["preflight"] {
		if strings.Contains(f.Label, "Authorization") {
			t.Errorf("wildcard Allow-Headers was reported as allowing Authorization: %q", f.Label)
		}
	}
}

// TestVaryOriginMissingIsReported checks the cache-poisoning check: a reflected
// origin without Vary: Origin can be cached and served to other users.
func TestVaryOriginMissingIsReported(t *testing.T) {
	findings := testRun(t, reflectOrigin(""))
	if n := len(findings["vary-origin"]); n != 1 {
		t.Errorf("vary-origin findings = %d, want 1", n)
	}

	withVary := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		w.Header().Set("Vary", "Accept-Encoding, Origin")
		io.WriteString(w, "ok")
	})
	if n := len(withVary["vary-origin"]); n != 0 {
		t.Errorf("vary-origin reported %d finding(s) with Vary: Origin present, want 0", n)
	}
}

// TestRelatedOriginProbesCoverBypassClasses checks the probe builder directly:
// every bypass class is generated for a dotted hostname, the dot probe replaces
// only the first dot, and no dot-based probe is generated for a hostname with
// no dots.
func TestRelatedOriginProbesCoverBypassClasses(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/x")
	got := map[string]string{}
	for _, p := range relatedOriginProbes(u) {
		got[p.id] = p.origin
	}
	for _, id := range []string{"prefix-concat", "suffix-append", "arbitrary-subdomain", "contains-substring", "regex-unescaped-dot"} {
		if got[id] == "" {
			t.Errorf("probe %q missing", id)
		}
	}
	if got["regex-unescaped-dot"] != "https://apiXexample.com" {
		t.Errorf("regex-unescaped-dot origin = %q, want https://apiXexample.com", got["regex-unescaped-dot"])
	}

	local, _ := url.Parse("http://localhost:8080/x")
	for _, p := range relatedOriginProbes(local) {
		if p.id == "regex-unescaped-dot" {
			t.Error("dot-regex probe generated for a hostname without dots")
		}
	}
}
