package bypass403

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testReferer is the same-origin Referer buildAttempts is given in these tests.
const testReferer = "https://host.test/"

// specByID returns the attempt spec with the given ID, failing the test if
// buildAttempts did not produce it.
func specByID(t *testing.T, specs []attemptSpec, id string) attemptSpec {
	t.Helper()
	for _, s := range specs {
		if s.id == id {
			return s
		}
	}
	t.Fatalf("no attempt spec %q", id)
	return attemptSpec{}
}

// hasTarget reports whether any path-category spec sends exactly target.
func hasTarget(specs []attemptSpec, target string) bool {
	for _, s := range specs {
		if s.category == categoryPath && s.target == target {
			return true
		}
	}
	return false
}

// TestCaseVariantsFlipEachLetterAndAlternate checks the case family on a
// plain word: one flip per letter, then the two alternating spellings, and
// nothing else. Every variant must still spell the same word.
func TestCaseVariantsFlipEachLetterAndAlternate(t *testing.T) {
	got := caseVariants("admin")
	want := []string{"Admin", "aDmin", "adMin", "admIn", "admiN", "AdMiN", "aDmIn"}
	if len(got) != len(want) {
		t.Fatalf("caseVariants(admin) = %q, want %d variants %q", got, len(want), want)
	}
	seen := map[string]bool{}
	for i, v := range got {
		if v != want[i] {
			t.Errorf("variant %d = %q, want %q", i, v, want[i])
		}
		if seen[v] {
			t.Errorf("duplicate variant %q", v)
		}
		seen[v] = true
		if strings.ToLower(v) != "admin" {
			t.Errorf("variant %q does not spell admin", v)
		}
	}
}

// TestCaseVariantsSkipNonLetters checks that digits and punctuation are
// never switched, and that a segment with no letters yields nothing at all.
func TestCaseVariantsSkipNonLetters(t *testing.T) {
	got := caseVariants("v1-2")
	if len(got) != 1 || got[0] != "V1-2" {
		t.Errorf("caseVariants(v1-2) = %q, want only [V1-2]", got)
	}
	if got := caseVariants("123"); len(got) != 0 {
		t.Errorf("caseVariants(123) = %q, want none", got)
	}
}

// TestCaseVariantsAreCapped checks that a long segment is bounded by
// maxCaseVariants rather than producing one request per letter.
func TestCaseVariantsAreCapped(t *testing.T) {
	long := strings.Repeat("abcdefgh", 6)
	if got := len(caseVariants(long)); got != maxCaseVariants {
		t.Errorf("len(caseVariants(long)) = %d, want the cap %d", got, maxCaseVariants)
	}
}

// TestDoublePercentEncodeAllEncodesTheEscapeItself checks that each byte is
// escaped twice: the "%" of its single escape is itself encoded to "%25".
func TestDoublePercentEncodeAllEncodesTheEscapeItself(t *testing.T) {
	if got, want := doublePercentEncodeAll("ad"), "%2561%2564"; got != want {
		t.Errorf("doublePercentEncodeAll(ad) = %q, want %q", got, want)
	}
}

// TestMutateHostKeepsThePort checks the Host spellings: the name changes,
// the :port survives, and an unknown kind leaves the host alone.
func TestMutateHostKeepsThePort(t *testing.T) {
	cases := []struct{ host, kind, want string }{
		{"example.com", "trailing-dot", "example.com."},
		{"example.com:8443", "trailing-dot", "example.com.:8443"},
		{"example.com", "uppercase", "EXAMPLE.COM"},
		{"example.com:443", "uppercase", "EXAMPLE.COM:443"},
		{"[::1]:8080", "uppercase", "[::1]:8080"},
		{"example.com", "unknown", "example.com"},
	}
	for _, c := range cases {
		if got := mutateHost(c.host, c.kind); got != c.want {
			t.Errorf("mutateHost(%q, %q) = %q, want %q", c.host, c.kind, got, c.want)
		}
	}
}

// TestMidPathAttemptsInsertBeforeFinalSegment checks that a mid-path
// insertion goes between the parent directory and the protected segment,
// leaving both intact.
func TestMidPathAttemptsInsertBeforeFinalSegment(t *testing.T) {
	specs := buildAttempts("/api/admin", "", "https", testReferer)
	for _, want := range []string{"/api/%2e%2e/admin", "/api/..;/admin", "/api/%2e/admin"} {
		if !hasTarget(specs, want) {
			t.Errorf("no path attempt sends %q", want)
		}
	}
	// At the root there is no parent directory, so the insertion lands
	// directly before the segment.
	if rootSpecs := buildAttempts("/admin", "", "https", testReferer); !hasTarget(rootSpecs, "/%2e%2e/admin") {
		t.Error("root-level mid-path insertion missing for /admin")
	}
}

// TestSeparatorAttemptsNeedAParentDirectory checks the overlong-separator
// family: it swaps the "/" before the final segment, so it only exists when
// there is a parent directory to swap it out of.
func TestSeparatorAttemptsNeedAParentDirectory(t *testing.T) {
	nested := buildAttempts("/api/admin", "", "https", testReferer)
	if !hasTarget(nested, "/api%c0%afadmin") {
		t.Error("overlong separator attempt missing for /api/admin")
	}
	root := buildAttempts("/admin", "", "https", testReferer)
	for _, s := range root {
		if strings.HasPrefix(s.id, "path-unicode-separator") {
			t.Errorf("root path produced separator attempt %q, which has no separator to replace", s.id)
		}
	}
}

// TestPathTargetsAreUniquePerRun checks the de-duplication: no two path
// attempts send the same request-target, so no request is repeated.
func TestPathTargetsAreUniquePerRun(t *testing.T) {
	// Check each base path's whole battery for repeated targets.
	for _, base := range []string{"/admin", "/api/v2/admin/", "/api/admin", "/"} {
		specs := buildAttempts(base, "x=1", "https", testReferer)
		seen := map[string]string{}
		// Compare every path attempt's target against those already seen.
		for _, s := range specs {
			if s.category != categoryPath {
				continue
			}
			if prev, dup := seen[s.target]; dup {
				t.Errorf("%s: target %q sent by both %q and %q", base, s.target, prev, s.id)
			}
			seen[s.target] = s.id
		}
	}
}

// TestMethodOverrideBodiesCarryTheirPayload checks that the body-based
// override attempts send the override in the body they declare, as a POST.
func TestMethodOverrideBodiesCarryTheirPayload(t *testing.T) {
	specs := buildAttempts("/admin", "", "https", testReferer)
	form := specByID(t, specs, "method-override-body-form")
	if form.method != "POST" || form.body != "_method=GET" {
		t.Errorf("form override = %s %q, want POST with body _method=GET", form.method, form.body)
	}
	js := specByID(t, specs, "method-override-body-json")
	if js.method != "POST" || js.body != `{"_method":"GET"}` {
		t.Errorf("json override = %s %q, want POST with a _method GET body", js.method, js.body)
	}
	query := specByID(t, specs, "method-override-query")
	if query.target != "/admin?_method=GET" {
		t.Errorf("query override target = %q, want /admin?_method=GET", query.target)
	}
}

// TestNoOpHostMutationsAreDropped checks that an IP-literal host, which upper-
// casing cannot change, gets no uppercase attempt, while the trailing-dot one stays.
func TestNoOpHostMutationsAreDropped(t *testing.T) {
	specs := buildAttempts("/admin", "", "https", testReferer)
	kept := withoutNoOpHostMutations(specs, "127.0.0.1:8080")
	for _, s := range kept {
		if s.id == "header-host-uppercase" {
			t.Error("uppercase Host attempt kept for an IP literal, where it is a no-op")
		}
	}
	found := false
	for _, s := range kept {
		if s.id == "header-host-trailing-dot" {
			found = true
		}
	}
	if !found {
		t.Error("trailing-dot Host attempt dropped, but it changes the host")
	}
}

// TestNomore403TechniquesAreJudgedAsBypasses runs each new technique family
// against a server that opens only for that one request shape. The named
// attempt must be counted as a bypass, which proves the spelling reaches the
// wire intact and that the judge accepts it.
func TestNomore403TechniquesAreJudgedAsBypasses(t *testing.T) {
	cases := []struct {
		name string
		// base is the protected path the run targets.
		base string
		// wantID is the attempt that must be counted as a bypass.
		wantID string
		// gate reports whether the server should open for this request.
		gate func(r *http.Request, body string) bool
	}{
		{
			name: "mid-path encoded dot-dot", base: "/api/admin", wantID: "path-mid-encoded-dotdot",
			gate: func(r *http.Request, _ string) bool { return r.RequestURI == "/api/%2e%2e/admin" },
		},
		{
			name: "end-path encoded line feed", base: "/admin", wantID: "path-suffix-encoded-lf",
			gate: func(r *http.Request, _ string) bool { return r.RequestURI == "/admin%0a" },
		},
		{
			name: "case flip of the first letter", base: "/admin", wantID: "path-case-variant-0",
			gate: func(r *http.Request, _ string) bool { return r.RequestURI == "/Admin" },
		},
		{
			name: "double percent-encoded segment", base: "/admin", wantID: "path-double-encode-all",
			gate: func(r *http.Request, _ string) bool { return r.RequestURI == "/%2561%2564%256D%2569%256E" },
		},
		{
			name: "overlong separator before the final segment", base: "/api/admin", wantID: "path-unicode-separator-overlong",
			gate: func(r *http.Request, _ string) bool { return r.RequestURI == "/api%c0%afadmin" },
		},
		{
			name: "hex loopback in X-Forwarded-For", base: "/admin", wantID: "header-ip-hex-x-forwarded-for",
			gate: func(r *http.Request, _ string) bool { return r.Header.Get("X-Forwarded-For") == "0x7f.0x0.0x0.0x1" },
		},
		{
			name: "IPv6 loopback in CF-Connecting-IP", base: "/admin", wantID: "header-ip-ipv6-cf-connecting-ip",
			gate: func(r *http.Request, _ string) bool { return r.Header.Get("CF-Connecting-IP") == "[::1]" },
		},
		{
			name: "hop-by-hop listing of X-Real-IP", base: "/admin", wantID: "header-hop-by-hop-x-real-ip",
			gate: func(r *http.Request, _ string) bool {
				return r.Header.Get("X-Real-IP") == "127.0.0.1" && strings.Contains(r.Header.Get("Connection"), "X-Real-IP")
			},
		},
		{
			name: "rewrite header X-Forwarded-Uri against the root", base: "/admin", wantID: "header-x-forwarded-uri",
			gate: func(r *http.Request, _ string) bool {
				return r.RequestURI == "/" && r.Header.Get("X-Forwarded-Uri") == "/admin"
			},
		},
		{
			name: "rewrite header X-Forwarded-URL against the root", base: "/admin", wantID: "header-x-forwarded-url",
			gate: func(r *http.Request, _ string) bool {
				return r.RequestURI == "/" && r.Header.Get("X-Forwarded-URL") == "/admin"
			},
		},
		{
			name: "Front-End-Https claims HTTPS", base: "/admin", wantID: "header-front-end-https",
			gate: func(r *http.Request, _ string) bool { return r.Header.Get("Front-End-Https") == "on" },
		},
		{
			name: "RFC 7239 Forwarded header", base: "/admin", wantID: "header-forwarded-rfc7239",
			gate: func(r *http.Request, _ string) bool {
				return strings.Contains(r.Header.Get("Forwarded"), "proto=https")
			},
		},
		{
			name: "X-Forwarded-Server set to localhost", base: "/admin", wantID: "header-x-forwarded-server-localhost",
			gate: func(r *http.Request, _ string) bool { return r.Header.Get("X-Forwarded-Server") == "localhost" },
		},
		{
			name: "POST with _method=GET in the query", base: "/admin", wantID: "method-override-query",
			gate: func(r *http.Request, _ string) bool {
				return r.Method == "POST" && r.URL.Path == "/admin" && r.URL.Query().Get("_method") == "GET"
			},
		},
		{
			name: "POST with _method=GET in a form body", base: "/admin", wantID: "method-override-body-form",
			gate: func(r *http.Request, body string) bool { return r.Method == "POST" && body == "_method=GET" },
		},
		{
			name: "POST with _method=GET in a JSON body", base: "/admin", wantID: "method-override-body-json",
			gate: func(r *http.Request, body string) bool { return r.Method == "POST" && body == `{"_method":"GET"}` },
		},
		{
			name: "capitalized GET verb", base: "/admin", wantID: "method-case-capitalized",
			gate: func(r *http.Request, _ string) bool { return r.Method == "Get" },
		},
	}

	// Each case gets its own server whose gate opens for one request shape.
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Read the body up front so gates can compare it.
				raw, _ := io.ReadAll(r.Body)
				if c.gate(r, string(raw)) {
					fmt.Fprint(w, adminConsole)
					return
				}
				// Every other request gets the same denial the baseline does,
				// except the homepage and a not-found page for unrelated paths.
				switch {
				case strings.Contains(r.RequestURI, "admin"):
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, "Forbidden")
				case r.RequestURI == "/":
					fmt.Fprint(w, acmeHome)
				default:
					fmt.Fprint(w, softNotFound)
				}
			}))
			defer srv.Close()

			res, err := Run(context.Background(), srv.URL+c.base, Options{Concurrency: 8})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !res.Baseline.Blocked {
				t.Fatal("baseline was not treated as blocked")
			}
			a := findAttempt(t, res, c.wantID)
			if !a.Bypassed {
				t.Fatalf("%s not bypassed: status=%d note=%q", c.wantID, a.StatusCode, a.Note)
			}
		})
	}
}

// TestNomore403TechniquesDoNotBypassAClosedHost checks the false-positive side:
// a host that denies everything it protects, and answers other paths with
// its homepage or not-found page, must yield no bypasses from the new families.
func TestNomore403TechniquesDoNotBypassAClosedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.RequestURI, "admin"):
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden")
		case r.RequestURI == "/":
			fmt.Fprint(w, acmeHome)
		default:
			fmt.Fprint(w, softNotFound)
		}
	}))
	defer srv.Close()

	// Run the closed-host check against both a top-level and a nested path.
	for _, base := range []string{"/admin", "/api/admin"} {
		res, err := Run(context.Background(), srv.URL+base, Options{Concurrency: 8})
		if err != nil {
			t.Fatalf("Run(%s): %v", base, err)
		}
		if res.BypassCount != 0 {
			for _, a := range res.Attempts {
				if a.Bypassed {
					t.Errorf("%s: %s counted as a bypass against a closed host", base, a.ID)
				}
			}
		}
	}
}
