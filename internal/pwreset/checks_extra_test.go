package pwreset

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// clientFor returns the shared-style test client used by these checks.
func clientFor() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// targetOf parses srv's URL.
func targetOf(t *testing.T, srv *httptest.Server) *url.URL {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// formEmail returns the email field of a POSTed reset form, or "".
func formEmail(r *http.Request) string {
	_ = r.ParseForm()
	return r.PostForm.Get("email")
}

// TestEnumerationIgnoresIdentifierEcho checks the false-positive fix: a page that
// echoes the address it was asked about is longer for a longer address. Both
// identifiers get the same message, so the only size difference is the echo
// itself, which is not account state. The old check reported it as enumeration.
func TestEnumerationIgnoresIdentifierEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "If an account exists for %s, a reset link is on its way.", formEmail(r))
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, Method: "POST", ContentType: "form", IdentifierField: "email",
		KnownIdentifier: "al@x.test", UnknownIdentifier: "aperture-pwreset-long-unknown-identifier@aperture-scan.invalid"}
	findings := runEnumerationModule(context.Background(), clientFor(), targetOf(t, srv), req, req.unknownIdentifier(), nil)
	if len(findings) != 0 {
		t.Errorf("identifier echo reported as enumeration: %+v", findings)
	}
}

// TestEnumerationNoiseControlSuppressesSharedDifference checks the noise control.
// The known account and the fixed unknown identifier differ in size, but the
// fixed unknown identifier and a second, random unknown identifier also differ
// on the same measure. That makes the known/unknown difference page noise, not
// account state, so nothing is reported.
func TestEnumerationNoiseControlSuppressesSharedDifference(t *testing.T) {
	const fixedUnknown = "aperture-pwreset-fixed@aperture-scan.invalid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch formEmail(r) {
		case "alice@example.test":
			io.WriteString(w, strings.Repeat("x", 100))
		case fixedUnknown:
			io.WriteString(w, strings.Repeat("x", 300))
		default:
			// Every other unknown identifier, including the random control, gets a
			// third size, so it separates from the fixed one on the same measure.
			io.WriteString(w, strings.Repeat("x", 200))
		}
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, Method: "POST", ContentType: "form", IdentifierField: "email",
		KnownIdentifier: "alice@example.test", UnknownIdentifier: fixedUnknown}
	findings := runEnumerationModule(context.Background(), clientFor(), targetOf(t, srv), req, fixedUnknown, nil)
	if len(findings) != 0 {
		t.Errorf("difference that also separates two unknown identifiers was reported: %+v", findings)
	}
}

// TestEnumerationReportsRealDifferenceAgainstControl is the positive counterpart:
// the known account differs, while both unknown identifiers look the same, so the
// finding survives the noise control.
func TestEnumerationReportsRealDifferenceAgainstControl(t *testing.T) {
	const fixedUnknown = "aperture-pwreset-fixed@aperture-scan.invalid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if formEmail(r) == "alice@example.test" {
			io.WriteString(w, strings.Repeat("x", 100))
			return
		}
		io.WriteString(w, strings.Repeat("x", 300))
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, Method: "POST", ContentType: "form", IdentifierField: "email",
		KnownIdentifier: "alice@example.test", UnknownIdentifier: fixedUnknown}
	findings := runEnumerationModule(context.Background(), clientFor(), targetOf(t, srv), req, fixedUnknown, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want likely", findings[0].Confidence)
	}
}

// TestRateLimitUnansweredBurstIsNotReported checks the false-positive fix: an
// endpoint that errors on every request gave no answer about throttling, so
// "no throttling seen" would be a false claim and nothing is reported.
func TestRateLimitUnansweredBurstIsNotReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	findings := runRateLimitModule(context.Background(), clientFor(), targetOf(t, srv), resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 0 {
		t.Errorf("unanswered burst reported as unthrottled: %+v", findings)
	}
}

// TestRateLimitRetryAfterOn200CountsAsThrottled checks a limiter that answers
// 200 with a Retry-After header instead of a 429. The old check missed it and
// reported "no throttling".
func TestRateLimitRetryAfterOn200CountsAsThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	findings := runRateLimitModule(context.Background(), clientFor(), targetOf(t, srv), resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 0 {
		t.Errorf("Retry-After limiter reported as unthrottled: %+v", findings)
	}
}

// TestRateLimitCaptchaWordingCountsAsThrottled checks that a challenge page
// standing in for a limit is read as throttling, not as an unthrottled answer.
func TestRateLimitCaptchaWordingCountsAsThrottled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html>Please complete the captcha to continue.</html>")
	}))
	defer srv.Close()

	findings := runRateLimitModule(context.Background(), clientFor(), targetOf(t, srv), resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 0 {
		t.Errorf("captcha challenge reported as unthrottled: %+v", findings)
	}
}

// TestHostHeaderXHostReflectionIsFound checks the added host-trust technique: a
// server that builds its reset link from an X-Host header is reported under that
// name.
func TestHostHeaderXHostReflectionIsFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "reset link: https://%s/reset?x=1", r.Header.Get("X-Host"))
	}))
	defer srv.Close()

	findings := runHostHeaderModule(context.Background(), clientFor(), targetOf(t, srv), resetRequest(srv.URL), "nobody@example.test", nil)
	found := false
	for _, f := range findings {
		if f.Label == "X-Host header reflected back in the response" {
			found = true
		}
	}
	if !found {
		t.Errorf("X-Host reflection not reported: %+v", findings)
	}
}

// TestHostHeaderNoReflectionIsSilent is the negative case: an endpoint that never
// echoes any header value reports no host-trust finding.
func TestHostHeaderNoReflectionIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "If that account exists, an email was sent.")
	}))
	defer srv.Close()

	findings := runHostHeaderModule(context.Background(), clientFor(), targetOf(t, srv), resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 0 {
		t.Errorf("findings on a non-reflecting endpoint: %+v", findings)
	}
}

// TestSubmitHonorsHostOverrideHeader checks the transport fix: a Host passed in
// the request's headers reaches the server as the Host header.
func TestSubmitHonorsHostOverrideHeader(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
	}))
	defer srv.Close()

	_, err := submit(context.Background(), clientFor(), targetOf(t, srv), "POST", "form",
		map[string]string{"email": "a@b.test"}, map[string]string{"Host": "app.example.test"}, "")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if gotHost != "app.example.test" {
		t.Errorf("Host = %q, want app.example.test", gotHost)
	}
}

// TestLeakageIgnoresValueInUnknownResponse checks that a token-shaped value the
// unknown-account response also carries is page furniture, not a token minted for
// the known account, and is not reported.
func TestLeakageIgnoresValueInUnknownResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The same static asset-version value on every response.
		io.WriteString(w, `<a href="/static/app.js?token=STATICBUILD123">app</a>`)
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, Method: "POST", ContentType: "form", IdentifierField: "email",
		KnownIdentifier: "alice@example.test"}
	unknownID := "aperture-pwreset-unknown@aperture-scan.invalid"
	baseline, err := submit(context.Background(), clientFor(), targetOf(t, srv), "POST", "form",
		buildFields("email", unknownID, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	findings := runLeakageModule(context.Background(), clientFor(), targetOf(t, srv), req, unknownID, baseline)
	if len(findings) != 0 {
		t.Errorf("value shared with the unknown-account response reported as a leaked token: %+v", findings)
	}
}

// TestLeakageReportsTokenOnlyForKnownAccount checks the positive case: a token
// that appears only for the known account is reported, at likely confidence.
func TestLeakageReportsTokenOnlyForKnownAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if formEmail(r) == "alice@example.test" {
			io.WriteString(w, `{"reset_token": "9f8e7d6c5b4a39281706"}`)
			return
		}
		io.WriteString(w, `{"status": "ok"}`)
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, Method: "POST", ContentType: "form", IdentifierField: "email",
		KnownIdentifier: "alice@example.test"}
	unknownID := "aperture-pwreset-unknown@aperture-scan.invalid"
	baseline, err := submit(context.Background(), clientFor(), targetOf(t, srv), "POST", "form",
		buildFields("email", unknownID, nil), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	findings := runLeakageModule(context.Background(), clientFor(), targetOf(t, srv), req, unknownID, baseline)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want likely", findings[0].Confidence)
	}
}

// TestHasCSRFTokenJudgesFieldsByTypeAndName checks the token detection the
// password-reset CSRF module now uses: a hidden input with a token name, in
// either attribute order. A visible field or a generic *_token name is not a token.
func TestHasCSRFTokenJudgesFieldsByTypeAndName(t *testing.T) {
	cases := []struct {
		name, body string
		want       bool
	}{
		{"hidden csrf_token", `<form><input type="hidden" name="csrf_token" value="x"></form>`, true},
		{"hidden, value before name", `<form><input value="x" name="authenticity_token" type="hidden"></form>`, true},
		{"hidden _token", `<form><input type="hidden" name="_token" value="x"></form>`, true},
		{"visible csrf-named field", `<form><input type="text" name="csrf_note"></form>`, false},
		{"hidden access_token", `<form><input type="hidden" name="access_token" value="x"></form>`, false},
		{"token meta", `<head><meta name="csrf-token" content="abc"></head>`, true},
		{"csrf-param meta only", `<head><meta name="csrf-param" content="authenticity_token"></head>`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasCSRFToken(c.body); got != c.want {
				t.Errorf("hasCSRFToken = %v, want %v", got, c.want)
			}
		})
	}
}

// TestCSRFModuleAcceptsMetaTokenPage checks the false-positive fix: a SPA that
// keeps its CSRF token in a meta tag and sends it as a header has a token, and
// the form check must not report it as missing one.
func TestCSRFModuleAcceptsMetaTokenPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<html><head><meta name="csrf-token" content="abc123"></head><body><form action="/reset"></form></body></html>`)
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, FormURL: srv.URL + "/forgot"}
	if findings := runCSRFModule(context.Background(), clientFor(), targetOf(t, srv), req, "", nil); len(findings) != 0 {
		t.Errorf("meta-token page reported as missing a token: %+v", findings)
	}
}

// TestCSRFModuleSendsRequestHeaders checks the header fix on the form fetch: a
// token rendered only for a cookie-bearing visitor is found when the caller's
// Cookie header is sent, and reported as missing when it isn't.
func TestCSRFModuleSendsRequestHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			io.WriteString(w, `<form><input name="email"></form>`)
			return
		}
		io.WriteString(w, `<form><input type="hidden" name="csrf_token" value="x"></form>`)
	}))
	defer srv.Close()

	withCookie := Request{URL: srv.URL, FormURL: srv.URL + "/forgot", Headers: map[string]string{"Cookie": "sess=1"}}
	if findings := runCSRFModule(context.Background(), clientFor(), targetOf(t, srv), withCookie, "", nil); len(findings) != 0 {
		t.Errorf("token visible to the cookie-bearing visitor reported as missing: %+v", findings)
	}
	anonymous := Request{URL: srv.URL, FormURL: srv.URL + "/forgot"}
	if findings := runCSRFModule(context.Background(), clientFor(), targetOf(t, srv), anonymous, "", nil); len(findings) != 1 {
		t.Errorf("anonymous visitor sees no token, expected one finding, got %+v", findings)
	}
}

// TestFormSecurityCookieFlagsAreReadByAttribute checks the cookie-flag fix. A
// value containing the word "secure" must not count as the Secure flag, and a
// fully flagged cookie is not reported.
func TestFormSecurityCookieFlagsAreReadByAttribute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Set-Cookie", "flag=secure_mode; Path=/; HttpOnly; SameSite=Strict")
		w.Header().Add("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	}))
	defer srv.Close()

	req := Request{URL: srv.URL, FormURL: srv.URL + "/forgot"}
	findings := runFormSecurityModule(context.Background(), clientFor(), targetOf(t, srv), req, "", nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (the flag cookie missing Secure): %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Label, `"flag" is missing Secure`) {
		t.Errorf("label = %q, want the flag cookie reported as missing Secure", findings[0].Label)
	}
}

// TestFormSecurityNoStoreRequired checks that a page without no-store is flagged,
// and that the same page with it isn't.
func TestFormSecurityNoStoreRequired(t *testing.T) {
	for _, tc := range []struct {
		name, cacheControl string
		want               int
	}{
		{"missing no-store", "", 1},
		{"no-store present", "no-store, max-age=0", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.cacheControl != "" {
					w.Header().Set("Cache-Control", tc.cacheControl)
				}
				w.Header().Add("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
			}))
			defer srv.Close()
			req := Request{URL: srv.URL, FormURL: srv.URL + "/forgot"}
			findings := runFormSecurityModule(context.Background(), clientFor(), targetOf(t, srv), req, "", nil)
			if len(findings) != tc.want {
				t.Errorf("findings = %d, want %d: %+v", len(findings), tc.want, findings)
			}
		})
	}
}

// TestParseCookieFlags covers the attribute parser directly, including
// SameSite=None, which is not a protective value.
func TestParseCookieFlags(t *testing.T) {
	name, secure, httpOnly, sameSite := parseCookieFlags("sid=abc; Path=/; SameSite=None; Secure")
	if name != "sid" || !secure || httpOnly || sameSite != "none" {
		t.Errorf("parseCookieFlags = (%q, %v, %v, %q), want (sid, true, false, none)", name, secure, httpOnly, sameSite)
	}
	if _, secure, _, _ := parseCookieFlags("v=insecure; Path=/"); secure {
		t.Error("a value containing 'insecure' was read as the Secure flag")
	}
}
