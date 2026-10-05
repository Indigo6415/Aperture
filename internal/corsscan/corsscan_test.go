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
	return testRunURL(t, "http://example.test/api/me", handler)
}

// testRunURL is testRun against an explicit target URL. The scheme matters for
// checks that only apply to HTTPS targets (the plain-HTTP origin probe).
func testRunURL(t *testing.T, target string, handler http.HandlerFunc) map[string][]Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: hostRewriter{srv: srv}}
	res, err := runWithClient(context.Background(), Request{URL: target}, client)
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

// TestParserUnderscoreIsFlagged serves an allowlist that matches the target
// hostname as a prefix, so an origin with "_" appended after it is echoed back.
// The parser-bypass module must flag that origin.
func TestParserUnderscoreIsFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); strings.HasPrefix(o, "http://example.test_.") {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["parser-bypass"]); n != 1 {
		t.Fatalf("parser-bypass findings = %d, want 1", n)
	}
	if got := findings["parser-bypass"][0].Exploitation; got == "" {
		t.Error("parser-bypass finding has no exploitation text")
	}
}

// TestParserBacktickIsFlagged serves a parser that percent-decodes the Origin
// before checking it and echoes the decoded backtick back. The module must flag
// the encoded probe, since that is the case where the decoded value is what the
// server reflects.
func TestParserBacktickIsFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); strings.Contains(o, "%60") {
			w.Header().Set("Access-Control-Allow-Origin", strings.ReplaceAll(o, "%60", "`"))
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["parser-bypass"]); n != 1 {
		t.Fatalf("parser-bypass findings = %d, want 1", n)
	}
}

// TestParserBypassQuietWhenEncodedValueEchoed checks that a server echoing the
// percent-encoded origin verbatim is not flagged: only the decoded backtick is
// the parser weakness.
func TestParserBypassQuietWhenEncodedValueEchoed(t *testing.T) {
	findings := testRun(t, reflectOrigin(""))
	for _, f := range findings["parser-bypass"] {
		if strings.Contains(f.Label, "backtick") {
			t.Errorf("backtick finding reported for a server that echoes the raw %%60 origin: %+v", f)
		}
	}
}

// TestWildcardOriginFlaggedWithoutCredentials serves Access-Control-Allow-Origin: *
// with no credentials header. The wildcard-origin module must report it, and
// the credentialed wildcard module must stay quiet, so the one header yields one
// finding.
func TestWildcardOriginFlaggedWithoutCredentials(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		io.WriteString(w, "ok")
	})
	if n := len(findings["wildcard-origin"]); n != 1 {
		t.Errorf("wildcard-origin findings = %d, want 1", n)
	}
	if n := len(findings["wildcard-credentials"]); n != 0 {
		t.Errorf("wildcard-credentials findings = %d, want 0 without ACAC", n)
	}
}

// TestThirdPartyOriginFlagged serves a fixed absolute origin of another host, the
// static-allowlist case. The third-party module must report it. Reflection must
// not be reported, since the server never echoes the attacker origin here.
func TestThirdPartyOriginFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://codepen.io")
		io.WriteString(w, "ok")
	})
	if n := len(findings["third-party-origin"]); n != 1 {
		t.Errorf("third-party-origin findings = %d, want 1", n)
	}
	if n := len(findings["reflected-origin"]); n != 0 {
		t.Errorf("reflected-origin findings = %d, want 0 for a fixed origin", n)
	}
}

// TestReflectionIsNotThirdParty checks that echoing the scanner's own attacker
// origin is not also reported as a third-party trust. That origin is a
// reflection, which reflected-origin covers.
func TestReflectionIsNotThirdParty(t *testing.T) {
	findings := testRun(t, reflectOrigin(""))
	if n := len(findings["third-party-origin"]); n != 0 {
		t.Errorf("third-party-origin findings = %d for pure reflection, want 0", n)
	}
}

// TestEveryFindingHasExploitation runs a server that trips many modules at once
// and checks each finding carries an exploitation write-up, either its own or
// its module's default.
func TestEveryFindingHasExploitation(t *testing.T) {
	findings := testRun(t, reflectOrigin("true"))
	total := 0
	for id, fs := range findings {
		for _, f := range fs {
			total++
			if f.Exploitation == "" {
				t.Errorf("module %s finding %q has no exploitation text", id, f.Label)
			}
		}
	}
	if total == 0 {
		t.Fatal("expected at least one finding to check exploitation text on")
	}
}

// relatedHits returns the related-domain and parser-bypass findings whose sent
// origin contains needle. Corsy's probes are identified by the origin they send,
// so this is how a test asserts that one specific probe fired.
func relatedHits(findings map[string][]Finding, needle string) int {
	n := 0
	for _, id := range []string{"related-domain-trust", "parser-bypass"} {
		for _, f := range findings[id] {
			if strings.Contains(f.Detail, needle) {
				n++
			}
		}
	}
	return n
}

// TestPreDomainProbeFlagged matches Corsy's pre-domain check: the server trusts
// any origin that ends with the real hostname, so "evil" + host is accepted.
func TestPreDomainProbeFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); strings.HasSuffix(o, "example.test") {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if relatedHits(findings, "http://evilexample.test") != 1 {
		t.Errorf("pre-domain probe not flagged: related=%+v", findings["related-domain-trust"])
	}
}

// TestPostDomainProbeFlagged matches Corsy's post-domain check: the server trusts
// any origin that starts with the real hostname, so host + ".attacker" is accepted.
func TestPostDomainProbeFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); strings.HasPrefix(o, "http://example.test") {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if relatedHits(findings, "http://example.test.aperture-cors-poison.invalid") != 1 {
		t.Errorf("post-domain probe not flagged: related=%+v", findings["related-domain-trust"])
	}
}

// TestArbitrarySubdomainProbeFlagged covers the wildcard-subdomain policy: the
// server trusts every subdomain of the target, which includes an unregistered one.
func TestArbitrarySubdomainProbeFlagged(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); strings.HasSuffix(o, ".example.test") {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if relatedHits(findings, "aperture-cors-poison-subdomain.example.test") != 1 {
		t.Errorf("arbitrary-subdomain probe not flagged: related=%+v", findings["related-domain-trust"])
	}
}

// TestExactAllowlistIsQuiet is the negative control for the related-domain
// probes: an exact-match allowlist of the one legitimate origin rejects every
// lookalike, so the scanner must report nothing from any origin module.
func TestExactAllowlistIsQuiet(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o == "http://example.test" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	for id, fs := range findings {
		if len(fs) != 0 {
			t.Errorf("module %s reported %d finding(s) for an exact allowlist, want 0", id, len(fs))
		}
	}
}

// TestHTTPAllowanceFlaggedOnHTTPSTarget matches Corsy's HTTP check: an HTTPS
// target that trusts its own plain-HTTP origin lets a network attacker read the
// authenticated responses through that origin.
func TestHTTPAllowanceFlaggedOnHTTPSTarget(t *testing.T) {
	findings := testRunURL(t, "https://example.test/api/me", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o == "http://example.test" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["insecure-protocol"]); n != 1 {
		t.Errorf("insecure-protocol findings = %d, want 1", n)
	}
}

// TestHTTPAllowanceSkippedOnHTTPTarget checks the same trusted http origin on an
// HTTP target: there is no downgrade to test, so the module must not run.
func TestHTTPAllowanceSkippedOnHTTPTarget(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o == "http://example.test" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		io.WriteString(w, "ok")
	})
	if n := len(findings["insecure-protocol"]); n != 0 {
		t.Errorf("insecure-protocol findings on an http target = %d, want 0", n)
	}
}

// TestNullOriginWithoutCredentialsIsNotFullyExploitable checks that a trusted
// null origin with no credentials flag is still reported, but its detail does
// not claim authenticated exploitation.
func TestNullOriginWithoutCredentialsIsNotFullyExploitable(t *testing.T) {
	findings := testRun(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		io.WriteString(w, "ok")
	})
	fs := findings["null-origin"]
	if len(fs) != 1 {
		t.Fatalf("null-origin findings = %d, want 1", len(fs))
	}
	if strings.Contains(fs[0].Detail, "fully exploitable") {
		t.Errorf("null-origin without credentials claims full exploitability: %q", fs[0].Detail)
	}
}

// TestUnreachableTargetReturnsError checks the baseline failure path: when the
// target cannot be reached, Run reports an error rather than an empty clean
// result that would look like a passing scan.
func TestUnreachableTargetReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	client := &http.Client{Transport: hostRewriter{srv: srv}}
	if _, err := runWithClient(context.Background(), Request{URL: "http://example.test/api/me"}, client); err == nil {
		t.Error("expected an error for an unreachable target, got nil")
	}
}

// TestInvalidURLRejected checks that a target without a scheme or host is
// rejected up front, before any request is sent.
func TestInvalidURLRejected(t *testing.T) {
	for _, bad := range []string{"", "example.test/api", "ftp://example.test/x", "https://"} {
		if _, err := Run(context.Background(), Request{URL: bad}); err == nil {
			t.Errorf("Run(%q) returned no error", bad)
		}
	}
}
