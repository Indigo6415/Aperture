package jwtscan

import (
	"context"
	"fmt"
	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"net/http"
	"strings"
)

// ScanRequest is everything one JWT misconfiguration scan needs -- mirrors
// JWTear's CLI flags (-u/-t/-m/--cookie/--pubkey/--wordlist/-H) one for one.
type ScanRequest struct {
	URL    string
	Token  string
	Method string // defaults to GET
	// MaxRPS paces the scan's requests to the target, 0 leaves pacing off.
	MaxRPS       float64
	Cookie       string // empty sends the token as Authorization: Bearer instead
	ExtraHeaders map[string]string
	PubKeyPEM    string   // enables the RS256->HS256 confusion test
	ExtraSecrets []string // extends the built-in weak-secret wordlist
	// Progress, when set, receives one check per test as it runs. Nil means nobody is watching.
	Progress scanprogress.Reporter `json:"-"`
}

// Baseline records the two reference requests every test's hit/miss
// judgement is made against: the caller's real token, and a token that can
// never be valid.
type Baseline struct {
	ValidStatus   int `json:"validStatus"`
	ValidLength   int `json:"validLength"`
	InvalidStatus int `json:"invalidStatus"`
	InvalidLength int `json:"invalidLength"`
	// Identical is true when the valid and invalid baselines are
	// indistinguishable by status+length -- every test result then rests
	// entirely on the content-length heuristic and should be treated with
	// extra suspicion.
	Identical bool `json:"identical"`
}

// ScanResponse is the full result of one scan: the decoded source token
// plus every test's outcome, in a fixed, UI-friendly order.
type ScanResponse struct {
	Header        map[string]any `json:"header"`
	Payload       map[string]any `json:"payload"`
	Baseline      Baseline       `json:"baseline"`
	Results       []TestResult   `json:"results"`
	CrackedSecret string         `json:"crackedSecret,omitempty"`
	// SecretsTried is how many candidate secrets the weak-secret test
	// actually ran, after applying maxSecretAttempts -- shown in the UI so
	// a truncated custom wordlist isn't mistaken for a full run.
	SecretsTried int `json:"secretsTried"`
	// Advisories are judgments that need no request to make: unsigned algorithms,
	// missing or long expiry, client-controlled key references, and baselines
	// that the server answers inconsistently.
	Advisories []string `json:"advisories,omitempty"`
}

// RunScan parses req.Token, establishes baselines against req.URL, then
// runs every misconfiguration test against it, plus the kid-SSRF/jku/x5u
// tests in oob.go when oob names an operator-picked callback server (see
// OOBConfig -- the zero value just reports those three as skipped). Returns
// an error only when the scan itself can't proceed at all (bad token,
// unreachable target, or a token that the target doesn't even accept) --
// once running, every individual test failing to find anything is a normal
// ScanResponse result, not an error.
func RunScan(runCtx context.Context, req ScanRequest, oob OOBConfig) (*ScanResponse, error) {
	rep := scanprogress.Or(req.Progress)

	header, payload, _, err := ParseJWT(req.Token)
	if err != nil {
		return nil, fmt.Errorf("cannot parse JWT: %w", err)
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}
	client := newHTTPClient()
	client.Transport = netgov.WithPolicyRoundTripper(client.Transport, netgov.Policy{MaxRPS: req.MaxRPS})
	// Bound to ctx so a stop aborts the request in flight and every later one
	// fails at once, rather than the scan running on to completion.
	client.Transport = contextRoundTripper{ctx: runCtx, inner: client.Transport}

	okResp, okStatuses, err := sampleBaseline(client, req.URL, req.Token, method, req.Cookie, req.ExtraHeaders)
	if err != nil {
		return nil, fmt.Errorf("could not reach target with the provided token: %w", err)
	}
	if okResp.StatusCode >= 400 {
		return nil, fmt.Errorf(
			"the provided token was rejected (HTTP %d) -- make sure it grants access to this exact URL/method before scanning",
			okResp.StatusCode,
		)
	}

	failResp, failStatuses, err := sampleBaseline(client, req.URL, invalidBaselineToken, method, req.Cookie, req.ExtraHeaders)
	if err != nil {
		return nil, fmt.Errorf("baseline invalid-token request failed: %w", err)
	}
	// A baseline whose status changes between samples is not a stable yardstick,
	// so every verdict drawn from it is weaker and the response says so.
	var advisories []string
	if !allSame(okStatuses) || !allSame(failStatuses) {
		advisories = append(advisories, "The server answered the same request with different status codes across samples; treat every verdict as weaker.")
	}
	advisories = append(advisories, offlineAdvisories(header, payload)...)

	ctx := &scanCtx{
		client: client, url: req.URL, method: method, cookie: req.Cookie,
		headers: req.ExtraHeaders, header: header, payload: payload,
		ok: okResp, fail: failResp,
		rawToken: req.Token,
	}
	// Identity markers: values from the real token that the valid response
	// actually shows. Only those can tell an accepted forged token from a rejected one.
	ctx.markers = presentIn(okResp.Body, identityMarkers(payload))
	if len(ctx.markers) == 0 {
		advisories = append(advisories, "No identity claim (sub, email, username, ...) appears in the valid response, so forged-token acceptance cannot be verified and token-acceptance tests report nothing.")
	}

	secrets := make([]string, 0, len(weakSecrets)+len(req.ExtraSecrets))
	seen := make(map[string]struct{}, len(weakSecrets)+len(req.ExtraSecrets))
	for _, s := range weakSecrets {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		secrets = append(secrets, s)
	}
	for _, s := range req.ExtraSecrets {
		if len(secrets) >= maxSecretAttempts {
			break
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		secrets = append(secrets, s)
	}

	// Every test is one progress check. The three out-of-band tests run as one
	// batch, so they are planned together here and finished from their results.
	rep.Plan(
		scanprogress.Check{ID: "alg_none", Label: "alg=none"},
		scanprogress.Check{ID: "empty_sig", Label: "Empty signature"},
		scanprogress.Check{ID: "weak_secret", Label: "Weak signing secret"},
		scanprogress.Check{ID: "jwk_injection", Label: "jwk header injection"},
		scanprogress.Check{ID: "kid_injection", Label: "kid header injection"},
		scanprogress.Check{ID: "claim_tampering", Label: "Claim tampering"},
		scanprogress.Check{ID: "expired_token", Label: "Expired token acceptance"},
		scanprogress.Check{ID: "rs256_hs256", Label: "RS256 to HS256 confusion"},
		scanprogress.Check{ID: "kid_ssrf", Label: "kid Header SSRF"},
		scanprogress.Check{ID: "jku_injection", Label: "jku Header Injection"},
		scanprogress.Check{ID: "x5u_injection", Label: "x5u Header Injection"},
	)

	rep.Start("weak_secret")
	weakResult, cracked := ctx.testWeakSecret(secrets)
	rep.Done("weak_secret", vulnerableCount(weakResult), nil)

	// Auto-discovery only makes sense for an RSA-signed source token (there's
	// no RS256 public key to find otherwise) and never overrides a key the
	// caller explicitly provided -- see testRS256HS256.
	var discoveredKey []pemCandidate
	if strings.TrimSpace(req.PubKeyPEM) == "" {
		if alg, _ := header["alg"].(string); strings.HasPrefix(strings.ToUpper(alg), "RS") {
			discoveredKey = discoverPublicKeyPEM(client, req.URL, header)
		}
	}

	resp := &ScanResponse{
		Header:  header,
		Payload: payload,
		Baseline: Baseline{
			ValidStatus:   okResp.StatusCode,
			ValidLength:   okResp.Length,
			InvalidStatus: failResp.StatusCode,
			InvalidLength: failResp.Length,
			Identical:     okResp.StatusCode == failResp.StatusCode && okResp.Length == failResp.Length,
		},
		SecretsTried: len(secrets),
		Advisories:   advisories,
		Results: append([]TestResult{
			track(rep, "alg_none", ctx.testAlgNone),
			track(rep, "empty_sig", ctx.testEmptySig),
			weakResult,
			track(rep, "jwk_injection", ctx.testJWKInjection),
			track(rep, "kid_injection", ctx.testKidInjection),
			track(rep, "claim_tampering", func() TestResult { return ctx.testClaimTampering(cracked) }),
			track(rep, "expired_token", func() TestResult { return ctx.testExpiredToken(cracked) }),
			track(rep, "rs256_hs256", func() TestResult { return ctx.testRS256HS256(req.PubKeyPEM, discoveredKey) }),
		}, trackOOB(rep, ctx, oob)...),
	}
	if cracked != nil {
		resp.CrackedSecret = *cracked
	}
	return resp, nil
}

// contextRoundTripper binds every request it forwards to ctx. The JWT probes
// build some requests without a context of their own, so wrapping the client
// is the one place that covers all of them.
type contextRoundTripper struct {
	ctx   context.Context
	inner http.RoundTripper
}

// RoundTrip re-points the request at the scan's context, then forwards it.
// Once ctx is cancelled the inner transport aborts the request.
func (t contextRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.inner.RoundTrip(req.WithContext(t.ctx))
}

// track runs one test as a progress check: its square reads as testing while
// the test runs, and finishes counting a finding when the test reports the
// target vulnerable.
func track(rep scanprogress.Reporter, id string, run func() TestResult) TestResult {
	rep.Start(id)
	r := run()
	rep.Done(id, vulnerableCount(r), nil)
	return r
}

// trackOOB runs the out-of-band tests as one batch and finishes each of their
// checks from its own result.
func trackOOB(rep scanprogress.Reporter, ctx *scanCtx, oob OOBConfig) []TestResult {
	for _, id := range []string{"kid_ssrf", "jku_injection", "x5u_injection"} {
		rep.Start(id)
	}
	results := runOOBTests(ctx, oob)
	for _, r := range results {
		rep.Done(r.ID, vulnerableCount(r), nil)
	}
	return results
}

// vulnerableCount is 1 when a test reports the target vulnerable, 0 otherwise.
// It's the finding count a progress check reports for that test.
func vulnerableCount(r TestResult) int {
	if r.Status == StatusVulnerable {
		return 1
	}
	return 0
}
