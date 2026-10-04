package csrf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// tokenProbeFor returns a token probe aimed at srv's /transfer endpoint, with a
// body that carries the token field and an amount.
func tokenProbeFor(srv *httptest.Server) *TokenProbe {
	return &TokenProbe{
		URL:   srv.URL + "/transfer",
		Body:  "amount=10&csrf_token=good",
		Field: "csrf_token",
	}
}

// findingsOf returns the findings of the named module, or fails the test.
func findingsOf(t *testing.T, mods []ModuleResult, id string) []Finding {
	t.Helper()
	for _, m := range mods {
		if m.ID == id {
			return m.Findings
		}
	}
	t.Fatalf("module %q missing from result", id)
	return nil
}

// TestTokenValidationEnforcedIsNotReported checks that a server which rejects a
// missing, empty, or wrong token produces no finding.
func TestTokenValidationEnforcedIsNotReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("amount") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tok, present := r.PostForm["csrf_token"]
		if !present || len(tok) == 0 || tok[0] != "good" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "Forbidden")
			return
		}
		io.WriteString(w, "transfer saved")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 0 {
		t.Errorf("enforced token reported as not validated: %+v", mod.Findings)
	}
}

// TestTokenValidationIgnoredTokenIsReported checks the positive case: the server
// still needs its amount field, so it does inspect the request, but never checks
// the token. Every tampered variant is accepted, and the finding is likely.
func TestTokenValidationIgnoredTokenIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("amount") == "" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "missing amount")
			return
		}
		io.WriteString(w, "transfer saved")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(mod.Findings), mod.Findings)
	}
	f := mod.Findings[0]
	if f.Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want %q", f.Confidence, ConfidenceLikely)
	}
	for _, want := range []string{"removed", "empty", "wrong"} {
		if !strings.Contains(f.Label, want) {
			t.Errorf("label %q does not name accepted variant %q", f.Label, want)
		}
	}
	if f.Request == nil || !strings.Contains(f.Request.Body, "amount=10") {
		t.Errorf("finding does not capture the replayed request: %+v", f.Request)
	}
}

// TestTokenValidationAcceptAllControlIsInconclusive checks the control: a server
// that answers every request the same way, even an empty one, does not inspect
// its input, so accepting a missing token proves nothing and is not reported.
func TestTokenValidationAcceptAllControlIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 0 {
		t.Errorf("an endpoint that ignores its input was reported: %+v", mod.Findings)
	}
}

// TestTokenValidationSoftRejectionIsNotAccepted checks a 200 page that says the
// token was invalid. The status code alone would look accepted, but the rejection
// wording, absent from the baseline, marks each replay as refused.
func TestTokenValidationSoftRejectionIsNotAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("amount") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("csrf_token") != "good" {
			io.WriteString(w, "<html>Invalid CSRF token. Please reload the page.</html>")
			return
		}
		io.WriteString(w, "<html>transfer saved</html>")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 0 {
		t.Errorf("a 200 rejection page was read as accepted: %+v", mod.Findings)
	}
}

// TestTokenValidationRedirectTargetIsNotAccepted checks that a redirect to a
// different place counts as a rejection. Here the baseline 302 goes to /done
// and a tampered request's 302 goes to /login, so the same status code is not
// enough to call it accepted.
func TestTokenValidationRedirectTargetIsNotAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("amount") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("csrf_token") != "good" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/done", http.StatusFound)
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 0 {
		t.Errorf("a redirect to login was read as accepted: %+v", mod.Findings)
	}
}

// TestTokenValidationPartialEnforcementIsNamed checks that an endpoint which
// checks the token only when it is present is reported with just the accepted
// variant. The label names "removed" and not the rejected "wrong" and "empty".
func TestTokenValidationPartialEnforcementIsNamed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("amount") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Enforced only when the field is present. A missing field is accepted.
		if tok, present := r.PostForm["csrf_token"]; present && (len(tok) == 0 || tok[0] != "good") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		io.WriteString(w, "transfer saved")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(mod.Findings), mod.Findings)
	}
	label := mod.Findings[0].Label
	if !strings.Contains(label, "removed") || strings.Contains(label, "wrong") {
		t.Errorf("label %q should name only the accepted variant", label)
	}
}

// TestTokenValidationUnstableBaselineIsSkipped checks that a one-time token
// consumed by the baseline's first send makes the second send fail. The baseline
// is then unstable, so the check reports nothing rather than comparing against it.
func TestTokenValidationUnstableBaselineIsSkipped(t *testing.T) {
	var used atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("amount") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Accept the token once, then refuse it. Every later send is refused.
		if used.Swap(true) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		io.WriteString(w, "transfer saved")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), tokenProbeFor(srv), nil)
	if len(mod.Findings) != 0 {
		t.Errorf("unstable baseline produced findings: %+v", mod.Findings)
	}
}

// TestTokenValidationSkipsWhenFieldMissing checks that a probe whose body has no
// token field sends nothing at all. Without the field the tampered variants
// would equal the valid request and produce a false bypass.
func TestTokenValidationSkipsWhenFieldMissing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	mod := tokenValidationModule(context.Background(), &TokenProbe{
		URL: srv.URL + "/transfer", Body: "amount=10", Field: "csrf_token",
	}, nil)
	if len(mod.Findings) != 0 || hits.Load() != 0 {
		t.Errorf("probe with no token field sent %d request(s) and reported %d finding(s)", hits.Load(), len(mod.Findings))
	}
}

// TestTokenValidationNilProbeIsEmpty checks that a nil probe sends nothing and
// still returns the module with its (empty) findings list.
func TestTokenValidationNilProbeIsEmpty(t *testing.T) {
	mod := tokenValidationModule(context.Background(), nil, nil)
	if mod.ID != "token-validation" || mod.Findings == nil || len(mod.Findings) != 0 {
		t.Errorf("nil probe result = %+v, want empty module with a non-nil findings slice", mod)
	}
}

// TestContentTypeBypassAcceptedIsReported checks the positive case: a JSON
// endpoint that ignores Content-Type accepts both CORS-safelisted types with the
// same response, so the finding names both.
func TestContentTypeBypassAcceptedIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"saved"}`)
	}))
	defer srv.Close()

	mod := contentTypeBypassModule(context.Background(), Request{
		APIURL: srv.URL + "/api/profile", APIBody: `{"email":"a@b.test"}`,
	})
	if len(mod.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(mod.Findings))
	}
	if !strings.Contains(mod.Findings[0].Label, "text/plain") || !strings.Contains(mod.Findings[0].Label, "application/x-www-form-urlencoded") {
		t.Errorf("label %q does not name both accepted types", mod.Findings[0].Label)
	}
	if mod.Findings[0].Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want %q", mod.Findings[0].Confidence, ConfidenceLikely)
	}
}

// TestContentTypeBypassJSONOnlyIsNotReported checks an endpoint that refuses
// anything but application/json with a 415 is not reported.
func TestContentTypeBypassJSONOnlyIsNotReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		io.WriteString(w, `{"status":"saved"}`)
	}))
	defer srv.Close()

	mod := contentTypeBypassModule(context.Background(), Request{
		APIURL: srv.URL + "/api/profile", APIBody: `{"email":"a@b.test"}`,
	})
	if len(mod.Findings) != 0 {
		t.Errorf("JSON-only endpoint reported as bypassable: %+v", mod.Findings)
	}
}

// TestContentTypeBypassSoftRejectionIsNotReported checks a 200 page that refuses
// the wrong Content-Type. The status matches, but the refusal wording and the
// changed body length mark it as a rejection.
func TestContentTypeBypassSoftRejectionIsNotReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			io.WriteString(w, "Unsupported media type: expected JSON body, got a form.")
			return
		}
		io.WriteString(w, "saved")
	}))
	defer srv.Close()

	mod := contentTypeBypassModule(context.Background(), Request{
		APIURL: srv.URL + "/api/profile", APIBody: `{"email":"a@b.test"}`,
	})
	if len(mod.Findings) != 0 {
		t.Errorf("a 200 refusal was read as bypassable: %+v", mod.Findings)
	}
}

// TestOutcomeDiffersBaselineControlled checks outcomeDiffers on its own: small
// body noise is ignored, and a change in status, redirect target, or rejection
// wording counts as a different outcome.
func TestOutcomeDiffersBaselineControlled(t *testing.T) {
	base := &apiResult{StatusCode: 200, Body: strings.Repeat("a", 500)}
	cases := []struct {
		name string
		got  *apiResult
		want bool
	}{
		{"same", &apiResult{StatusCode: 200, Body: strings.Repeat("a", 500)}, false},
		{"small length noise", &apiResult{StatusCode: 200, Body: strings.Repeat("a", 520)}, false},
		{"error status", &apiResult{StatusCode: 500, Body: strings.Repeat("a", 500)}, true},
		{"status changed", &apiResult{StatusCode: 202, Body: strings.Repeat("a", 500)}, true},
		{"large length change", &apiResult{StatusCode: 200, Body: strings.Repeat("a", 900)}, true},
		{"rejection wording", &apiResult{StatusCode: 200, Body: strings.Repeat("a", 500) + " CSRF failed"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := outcomeDiffers(base, c.got)
			if got != c.want {
				t.Errorf("outcomeDiffers = %v, want %v", got, c.want)
			}
		})
	}
	// Rejection wording already present in the baseline is not a difference.
	withWord := &apiResult{StatusCode: 200, Body: "<form>csrf_token</form>"}
	if d, _ := outcomeDiffers(withWord, &apiResult{StatusCode: 200, Body: "<form>csrf_token</form>"}); d {
		t.Error("wording present in the baseline was treated as a rejection")
	}
}

// TestCookieSameSiteModuleJudgesOnlySameSite checks which cookies the SameSite
// module reports. Auth cookies with no SameSite are heuristic, SameSite=None is
// likely, and analytics cookies, non-auth cookies, and cookies with a strong
// SameSite are skipped.
func TestCookieSameSiteModuleJudgesOnlySameSite(t *testing.T) {
	cr := &crawlResult{Cookies: []discoveredCookie{
		{Name: "sessionid", RawValue: "sessionid=abc; Path=/", SeenOn: "http://site.test/"},
		{Name: "theme", RawValue: "theme=dark; Path=/", SeenOn: "http://site.test/"},
		{Name: "_ga", RawValue: "_ga=GA1.2; Path=/", SeenOn: "http://site.test/"},
		{Name: "tracker", RawValue: "tracker=1; SameSite=None; Secure", SeenOn: "http://site.test/"},
		{Name: "auth", RawValue: "auth=1; SameSite=Strict", SeenOn: "http://site.test/"},
	}}
	mod := cookieSameSiteModule(cr, scanprogress.Or(nil))

	byName := map[string]Finding{}
	for _, f := range mod.Findings {
		byName[f.Evidence] = f
	}
	if len(mod.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (sessionid, tracker): %+v", len(mod.Findings), mod.Findings)
	}
	if f, ok := byName["sessionid=abc; Path=/"]; !ok || f.Confidence != ConfidenceHeuristic {
		t.Errorf("sessionid without SameSite = %+v, want a heuristic finding", f)
	}
	if f, ok := byName["tracker=1; SameSite=None; Secure"]; !ok || f.Confidence != ConfidenceLikely {
		t.Errorf("SameSite=None cookie = %+v, want a likely finding", f)
	}
}

// TestCookieSameSiteModuleIgnoresFakeAttribute checks that a cookie whose value
// contains "samesite=lax" but has no real SameSite attribute is still reported.
// The old substring match wrongly read it as protected.
func TestCookieSameSiteModuleIgnoresFakeAttribute(t *testing.T) {
	cr := &crawlResult{Cookies: []discoveredCookie{
		{Name: "session", RawValue: "session=samesite=lax; Path=/", SeenOn: "http://site.test/"},
	}}
	mod := cookieSameSiteModule(cr, scanprogress.Or(nil))
	if len(mod.Findings) != 1 {
		t.Errorf("findings = %d, want 1: a value that only mentions samesite=lax is not protection", len(mod.Findings))
	}
}

// TestFormCSRFModuleGroupsRepeatedForms checks that the same missing-token form
// on several pages is one finding that names the page count, not one per page.
// A form that has a token on one page is not reported.
func TestFormCSRFModuleGroupsRepeatedForms(t *testing.T) {
	cr := &crawlResult{Forms: []discoveredForm{
		{PageURL: "http://site.test/a", Action: "http://site.test/logout", Method: "POST"},
		{PageURL: "http://site.test/b", Action: "http://site.test/logout", Method: "POST"},
		{PageURL: "http://site.test/c", Action: "http://site.test/logout", Method: "POST", HasToken: true},
		{PageURL: "http://site.test/a", Action: "http://site.test/delete", Method: "DELETE"},
	}}
	mod := formCSRFModule(cr, scanprogress.Or(nil))
	if len(mod.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (logout, delete): %+v", len(mod.Findings), mod.Findings)
	}
	logout := mod.Findings[0]
	if !strings.Contains(logout.Detail, "1 other page(s)") {
		t.Errorf("logout detail does not count the repeated pages: %q", logout.Detail)
	}
	if mod.Findings[1].Label != "DELETE form at http://site.test/delete has no CSRF-token-looking field" {
		t.Errorf("DELETE form not reported through its real method: %q", mod.Findings[1].Label)
	}
}

// TestFormCSRFModuleRaceFree runs the form judgement across many forms to make
// sure the per-index missing slice is safe to write from concurrent checks. Run
// under -race this exercises the parallel path.
func TestFormCSRFModuleRaceFree(t *testing.T) {
	var forms []discoveredForm
	for i := 0; i < 200; i++ {
		forms = append(forms, discoveredForm{PageURL: "http://site.test/p", Action: "http://site.test/f", Method: "POST"})
	}
	var mu sync.Mutex
	var checks int
	rep := countingReporter{mu: &mu, n: &checks}
	mod := formCSRFModule(&crawlResult{Forms: forms}, rep)
	if len(mod.Findings) != 1 {
		t.Errorf("findings = %d, want 1 grouped finding", len(mod.Findings))
	}
	if checks != 200 {
		t.Errorf("progress checks = %d, want 200", checks)
	}
}

// countingReporter is a scanprogress.Reporter that counts Done calls, so the
// race test can confirm every form was judged.
type countingReporter struct {
	mu *sync.Mutex
	n  *int
}

func (countingReporter) Plan(...scanprogress.Check) {}
func (countingReporter) Start(string)               {}
func (c countingReporter) Done(string, int, error) {
	c.mu.Lock()
	*c.n++
	c.mu.Unlock()
}
func (countingReporter) Phase(string) {}
