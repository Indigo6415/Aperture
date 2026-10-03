package pwreset

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/netgov"
)

// enumerationLengthTolerance is how many bytes two responses may differ by in
// median size before the difference counts. Small gaps are incidental: a
// timestamp or a request id.
const enumerationLengthTolerance = 4

// enumerationTimingTolerance is the median response-time gap that counts as a
// real side channel. Anything smaller is ordinary network jitter.
const enumerationTimingTolerance = 300 * time.Millisecond

// Confidence levels for a Finding. Every check here reasons about responses it
// actually observed, so the strongest level is confirmed; the two checks that
// infer from a sample are likely.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
)

// --- Host-header / password-reset-poisoning module ---
// See https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning:
// an app that builds its emailed reset link from the request's own Host (or
// a proxy-forwarded-host header) instead of a hardcoded domain can be made
// to mail out a link pointing at an attacker's server instead. This engine
// can't read the operator's real inbox, so the signal it looks for is the
// nearest thing observable over HTTP alone: the attacker-controlled domain
// coming back reflected somewhere in the endpoint's own response (a debug
// field, an echoed Location, a templated confirmation page) -- a hit here is
// strong evidence the value is in play server-side and worth confirming
// against the actual email.
const poisonDomain = "aperture-poison-test.invalid"

// hostHeaderSpec is one way of getting an attacker-controlled domain in
// front of the app: either the Host header itself, or one of the several
// "trust the proxy" headers a reverse proxy setup commonly forwards
// verbatim.
type hostHeaderSpec struct {
	id, description string
	// overrideHost spoofs the literal Host header (submit's hostHeader
	// param) while still dialing the real target -- mirrors
	// bypass403.doAttempt's connectHost/hostHeader split. When false, the
	// attacker domain instead goes in the named proxy header below.
	overrideHost bool
	headerName   string
	// forwardedSyntax formats the value as RFC 7239's "host=..." directive
	// instead of a bare domain -- only the Forwarded header uses that shape.
	forwardedSyntax bool
}

var hostHeaderSpecs = []hostHeaderSpec{
	{id: "host-header", description: "Host header", overrideHost: true},
	{id: "x-forwarded-host", description: "X-Forwarded-Host header", headerName: "X-Forwarded-Host"},
	{id: "x-forwarded-server", description: "X-Forwarded-Server header", headerName: "X-Forwarded-Server"},
	{id: "x-original-host", description: "X-Original-Host header", headerName: "X-Original-Host"},
	{id: "forwarded", description: "Forwarded header", headerName: "Forwarded", forwardedSyntax: true},
}

var hostHeaderModule = moduleDef{
	id: "host-header", name: "Host header poisoning", severity: "high",
	run: runHostHeaderModule,
}

func runHostHeaderModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, _ *httpResult) []Finding {
	fields := buildFields(req.identifierField(), unknownID, req.ExtraFields)
	method, contentType := req.method(), req.contentType()

	type hit struct {
		idx     int
		finding Finding
	}
	results := make(chan hit, len(hostHeaderSpecs))
	// Every technique fires its own request concurrently -- there are only a
	// handful of them and each is judged independently, so there's no reason
	// to serialize them.
	for i, spec := range hostHeaderSpecs {
		go func(i int, spec hostHeaderSpec) {
			headers := map[string]string{}
			for k, v := range req.Headers {
				headers[k] = v
			}
			hostHeader := ""
			if spec.overrideHost {
				hostHeader = poisonDomain
			} else if spec.forwardedSyntax {
				headers[spec.headerName] = "host=" + poisonDomain
			} else {
				headers[spec.headerName] = poisonDomain
			}

			res, err := submit(ctx, client, target, method, contentType, fields, headers, hostHeader)
			if err != nil || !reflectsPoisonDomain(res) {
				results <- hit{idx: i}
				return
			}
			results <- hit{idx: i, finding: Finding{
				Label:      fmt.Sprintf("%s reflected back in the response", spec.description),
				Detail:     "The attacker-controlled domain sent in this header came back in the endpoint's own response, suggesting it's used server-side to build the reset link -- confirm by checking where the actual reset email points.",
				Evidence:   poisonDomain,
				Method:     method,
				StatusCode: res.StatusCode,
				Request:    &res.Request,
			}}
		}(i, spec)
	}

	found := make([]*Finding, len(hostHeaderSpecs))
	// Drain exactly one result per spec regardless of completion order, same
	// pattern as probescan.runPathChecks.
	for range hostHeaderSpecs {
		h := <-results
		if h.finding.Label != "" {
			f := h.finding
			found[h.idx] = &f
		}
	}

	var out []Finding
	for _, f := range found {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// reflectsPoisonDomain checks both the body and every response header value
// for the attacker domain -- a Location redirect or Set-Cookie domain can
// echo it back just as tellingly as the rendered body.
func reflectsPoisonDomain(res *httpResult) bool {
	if res == nil {
		return false
	}
	if strings.Contains(res.Body, poisonDomain) {
		return true
	}
	for _, values := range res.Header {
		for _, v := range values {
			if strings.Contains(v, poisonDomain) {
				return true
			}
		}
	}
	return false
}

// --- Response-leakage module ---
// Some implementations return the reset token/link directly in the request-
// reset endpoint's own JSON/HTML response -- often left over from a debug
// build, or because the frontend expects to render the link itself instead
// of only an email doing so. Either way, whoever can see that response (the
// requester -- who may not be the account owner) can reset the account
// without ever touching the inbox. See the vaadata/bughuntar writeups in
// this scanner's package-level references for real-world examples.
var leakageModule = moduleDef{
	id: "leakage", name: "Reset token leaked in response", severity: "critical",
	run: runLeakageModule,
}

// leakageQueryRe matches a token/code-shaped query parameter anywhere in the
// body -- covers a leaked absolute or relative reset link.
var leakageQueryRe = regexp.MustCompile(`(?i)[?&](token|code|otp|reset[_-]?token|reset[_-]?code|key)=([A-Za-z0-9_\-.]{6,})`)

// leakageJSONKeyRe matches a JSON string field whose key name reads as a
// token/reset/debug value -- covers a leaked token returned as its own
// field rather than embedded in a link.
var leakageJSONKeyRe = regexp.MustCompile(`(?i)"(token|resettoken|reset_token|reseturl|reset_url|resetlink|reset_link|debug|otp)"\s*:\s*"([^"]{3,})"`)

func runLeakageModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, baseline *httpResult) []Finding {
	res := baseline
	// A known-good identifier is more likely to trigger the app's real
	// "success" flow (as opposed to a generic "if this account exists…"
	// response an unknown identifier gets), so it's worth one extra request
	// specifically for this check when the operator supplied one.
	if req.KnownIdentifier != "" {
		fields := buildFields(req.identifierField(), req.KnownIdentifier, req.ExtraFields)
		if r, err := submit(ctx, client, target, req.method(), req.contentType(), fields, req.Headers, ""); err == nil {
			res = r
		}
	}
	if res == nil {
		return nil
	}

	var out []Finding
	seen := map[string]bool{}
	addMatch := func(field, value string) {
		key := field + value
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Finding{
			Label:      fmt.Sprintf("Response includes a %q value that looks like a reset token", field),
			Detail:     describeTokenShape(value),
			Evidence:   redactMiddle(value),
			Method:     req.method(),
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		})
	}

	for _, m := range leakageQueryRe.FindAllStringSubmatch(res.Body, -1) {
		addMatch(m[1], m[2])
	}
	for _, m := range leakageJSONKeyRe.FindAllStringSubmatch(res.Body, -1) {
		addMatch(m[1], m[2])
	}
	return out
}

// redactMiddle keeps a leaked value recognizable without shipping the whole
// thing back over the API -- the operator can always pull the real value
// from their own recorded traffic if they need it.
func redactMiddle(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// describeTokenShape gives a one-line, best-effort read on how guessable a
// single observed token looks -- short and/or numeric-only tokens are the
// two shapes cited across every source in this scanner's package doc as
// brute-forceable; anything else just can't be judged from one sample.
func describeTokenShape(value string) string {
	digitsOnly := true
	// A single pass to classify the token: numeric-only makes it brute-
	// forceable regardless of length, and separately its length alone
	// determines whether it's short enough to brute-force even with a full
	// alphanumeric charset.
	for _, r := range value {
		if r < '0' || r > '9' {
			digitsOnly = false
			break
		}
	}
	switch {
	case digitsOnly && len(value) <= 8:
		return "Numeric-only and short (" + fmt.Sprint(len(value)) + " digits) -- likely brute-forceable if there's no rate limiting on the reset-confirmation step too."
	case digitsOnly:
		return "Numeric-only -- worth checking whether it's sequential or timestamp-derived rather than a CSPRNG."
	case len(value) < 16:
		return "Shorter than the 16+ random characters typically considered safe for a bearer-style token."
	default:
		return "Long enough to not obviously guess from this one sample; still confirm it's actually CSPRNG-derived rather than time- or user-data-derived."
	}
}

// --- Rate-limiting module ---
// No rate limiting on the request-reset endpoint means an attacker can
// brute-force a short/weak token (paired with the leakage/enumeration
// modules above) or simply spam an account's inbox with reset emails.
var rateLimitModule = moduleDef{
	id: "rate-limit", name: "Rate limiting", severity: "medium",
	run: runRateLimitModule,
}

// rateLimitWaves are the request counts fired in turn. The check stops at the
// first wave that gets throttled, so a limiter that trips early costs little,
// and a limiter that never trips is measured over the largest sample.
var rateLimitWaves = []int{4, 8, 16}

// rateLimitBurst is the largest total the check sends. It is kept small enough
// to show a pattern without being a denial-of-service attempt on the target.
const rateLimitBurst = 4 + 8 + 16

var throttlePhrases = []string{
	"too many requests", "rate limit", "try again later", "temporarily blocked", "please wait before", "slow down",
}

// runRateLimitModule fires escalating concurrent waves at the reset endpoint.
// A throttled response in any wave means a limit exists, so nothing is
// reported. Otherwise the finding states the exact sample size: a burst this
// small cannot show the absence of a limit over a longer window, so the claim
// is only as strong as the sample.
func runRateLimitModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, _ *httpResult) []Finding {
	fields := buildFields(req.identifierField(), unknownID, req.ExtraFields)
	method, contentType := req.method(), req.contentType()

	sent := 0
	for _, wave := range rateLimitWaves {
		throttled := sendWave(ctx, client, target, method, contentType, fields, req.Headers, wave)
		sent += wave
		if throttled > 0 {
			return nil
		}
	}
	return []Finding{{
		Label:      fmt.Sprintf("No throttling seen across %d rapid requests", sent),
		Detail:     fmt.Sprintf("Every request in %d concurrent requests, sent in waves of %v, returned a normal (non-throttled) response. That is evidence of no limit at this rate, not proof: a limiter keyed on a longer window, or one that starts after a threshold above %d requests, would not show here.", sent, rateLimitWaves, sent),
		Method:     method,
		Confidence: ConfidenceLikely,
	}}
}

// sendWave fires n identical requests concurrently and returns how many were
// throttled. Concurrency is deliberate: a limiter keyed on requests per second
// would go undetected by a slow sequential burst.
func sendWave(ctx context.Context, client *http.Client, target *url.URL, method, contentType string, fields map[string]string, headers map[string]string, n int) int {
	throttled := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := submit(ctx, client, target, method, contentType, fields, headers, "")
			if err != nil {
				return
			}
			throttled[i] = res.StatusCode == http.StatusTooManyRequests || looksThrottled(res.Body)
		}(i)
	}
	wg.Wait()

	count := 0
	for _, t := range throttled {
		if t {
			count++
		}
	}
	return count
}

func looksThrottled(body string) bool {
	lower := strings.ToLower(body)
	// Checked against a fixed phrase list the same way bypass403.looksBlocked
	// flags a "soft" denial -- kept generic since this runs against whatever
	// framework/WAF an operator points it at.
	for _, p := range throttlePhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// --- User-enumeration module ---
// Only registered when Request.KnownIdentifier is set -- see
// registeredModules. Compares a known-registered identifier's response
// against an unknown one's, across several samples each to smooth over
// ordinary network jitter, looking for any difference (status code,
// response size, or response time) that would let an attacker tell which
// email addresses/usernames are actually registered.
var enumerationModule = moduleDef{
	id: "enumeration", name: "User enumeration", severity: "medium",
	run: runEnumerationModule,
}

// enumerationSamples is how many requests are sent per identifier. Ten per side
// makes an accidental complete separation of the two groups very unlikely
// (about one chance in 184,000), so a separation is strong evidence.
const enumerationSamples = 10

// enumSample is one timed request against one identifier.
type enumSample struct {
	status  int
	length  int
	latency time.Duration
	suspect bool
}

// runEnumerationModule compares a known identifier's responses with an unknown
// one's. Samples are interleaved (known, unknown, known, ...) so that drift in
// the network or in the target falls on both groups equally, instead of making
// one group look slower. A difference is reported only when the groups separate
// completely on that measure, which is what a real side channel looks like,
// and not the overlap that jitter produces. Timing is ignored when the governor
// has flagged the host as drifting, since throttling itself moves latency.
func runEnumerationModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, _ *httpResult) []Finding {
	if req.KnownIdentifier == "" || unknownID == "" {
		return nil
	}
	known, unknown := sampleInterleaved(ctx, client, target, req, req.KnownIdentifier, unknownID)
	if len(known) < enumerationSamples || len(unknown) < enumerationSamples {
		return nil
	}

	anySuspect := false
	for _, s := range append(append([]enumSample{}, known...), unknown...) {
		anySuspect = anySuspect || s.suspect
	}

	var reasons []string
	if k, u := uniformStatus(known), uniformStatus(unknown); k >= 0 && u >= 0 && k != u {
		reasons = append(reasons, fmt.Sprintf("status code differs on every sample (%d for the known account vs. %d for the unknown one)", k, u))
	}
	lengths := func(s []enumSample) []float64 {
		out := make([]float64, len(s))
		for i := range s {
			out[i] = float64(s[i].length)
		}
		return out
	}
	kl, ul := lengths(known), lengths(unknown)
	if separated(kl, ul) && math.Abs(median(kl)-median(ul)) > enumerationLengthTolerance {
		reasons = append(reasons, fmt.Sprintf("response size differs on every sample (median ~%.0f bytes for the known account vs. ~%.0f for the unknown one)", median(kl), median(ul)))
	}
	if !anySuspect {
		kt, ut := latencies(known), latencies(unknown)
		if separated(kt, ut) && math.Abs(median(kt)-median(ut)) > float64(enumerationTimingTolerance) {
			reasons = append(reasons, fmt.Sprintf("response time differs on every sample (median %v for the known account vs. %v for the unknown one)",
				time.Duration(median(kt)).Round(time.Millisecond), time.Duration(median(ut)).Round(time.Millisecond)))
		}
	}

	if len(reasons) == 0 {
		return nil
	}
	return []Finding{{
		Label:      "Known and unknown identifiers get distinguishable responses",
		Detail:     "The request-reset endpoint responds differently depending on whether the account exists: " + strings.Join(reasons, "; ") + ". An attacker can use this to enumerate registered accounts.",
		Method:     req.method(),
		StatusCode: known[0].status,
		Confidence: ConfidenceLikely,
	}}
}

// sampleInterleaved sends enumerationSamples requests for each identifier,
// alternating between them. Requests are sequential because they are timed; a
// concurrent burst would let the two identifiers contend for one connection.
func sampleInterleaved(ctx context.Context, client *http.Client, target *url.URL, req Request, known, unknown string) (knownSamples, unknownSamples []enumSample) {
	for i := 0; i < enumerationSamples; i++ {
		if s, ok := sampleOnce(ctx, client, target, req, known); ok {
			knownSamples = append(knownSamples, s)
		}
		if s, ok := sampleOnce(ctx, client, target, req, unknown); ok {
			unknownSamples = append(unknownSamples, s)
		}
	}
	return knownSamples, unknownSamples
}

// sampleOnce sends one request for identifier and records its timing.
func sampleOnce(ctx context.Context, client *http.Client, target *url.URL, req Request, identifier string) (enumSample, bool) {
	fields := buildFields(req.identifierField(), identifier, req.ExtraFields)
	res, err := submit(ctx, client, target, req.method(), req.contentType(), fields, req.Headers, "")
	if err != nil {
		return enumSample{}, false
	}
	return enumSample{
		status:  res.StatusCode,
		length:  len(res.Body),
		latency: res.Latency,
		suspect: res.Header.Get(netgov.SuspectHeader) != "",
	}, true
}

// uniformStatus returns the status shared by every sample, or -1 when the
// samples disagree with each other.
func uniformStatus(s []enumSample) int {
	if len(s) == 0 {
		return -1
	}
	for _, x := range s {
		if x.status != s[0].status {
			return -1
		}
	}
	return s[0].status
}

// separated reports whether two groups do not overlap at all: every value in
// one is above every value in the other, or the reverse.
func separated(a, b []float64) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	minA, maxA := minMax(a)
	minB, maxB := minMax(b)
	return minA > maxB || minB > maxA
}

// minMax returns the smallest and largest value of xs.
func minMax(xs []float64) (float64, float64) {
	lo, hi := xs[0], xs[0]
	for _, x := range xs[1:] {
		lo = math.Min(lo, x)
		hi = math.Max(hi, x)
	}
	return lo, hi
}

// median returns the middle value of xs, averaging the two middle values when
// the count is even.
func median(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// latencies returns the response times of samples, in nanoseconds as floats.
func latencies(s []enumSample) []float64 {
	out := make([]float64, len(s))
	for i := range s {
		out[i] = float64(s[i].latency)
	}
	return out
}

// --- CSRF module ---
// Only registered when Request.FormURL is set. A request-reset form with no
// anti-CSRF token lets an attacker force a victim (who has an active
// session on some other flow that relies on the same cookie -- e.g. a
// logged-in "change password" form on the same origin) to submit it, or, on
// forms that behave like the reset-confirmation step, set a password of the
// attacker's choosing.
var csrfModule = moduleDef{
	id: "csrf", name: "CSRF protection", severity: "medium",
	run: runCSRFModule,
}

// csrfFieldRe matches a hidden input whose name reads as a CSRF/authenticity
// token -- covers the field-name conventions of Rails, Django, and most
// hand-rolled implementations.
var csrfFieldRe = regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']*(?:csrf|_token|authenticity_token)[^"']*)["']`)

func runCSRFModule(ctx context.Context, client *http.Client, _ *url.URL, req Request, _ string, _ *httpResult) []Finding {
	res, err := fetchForm(ctx, client, req.FormURL)
	if err != nil {
		return nil
	}
	if csrfFieldRe.MatchString(res.Body) {
		return nil
	}
	return []Finding{{
		Label:      "No CSRF-token-looking field found on the reset form",
		Detail:     "Checked " + req.FormURL + " for a hidden input named like a CSRF/authenticity token and found none -- confirm the form isn't relying on a header-based token this static check can't see before treating this as confirmed.",
		Method:     "GET",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
	}}
}

// --- Form-security module ---
// Only registered when Request.FormURL is set. Checks the surrounding
// hygiene a sensitive, pre-authentication form should have: the page isn't
// cached (a shared/proxy cache serving someone else's reset-request page
// back is its own information leak), and any cookies it sets carry the
// Secure/HttpOnly/SameSite attributes that limit what a stolen or injected
// cookie can be used for.
var formSecurityModule = moduleDef{
	id: "form-security", name: "Form security headers", severity: "low",
	run: runFormSecurityModule,
}

var sameSiteRe = regexp.MustCompile(`(?i)samesite=([a-z]+)`)

func runFormSecurityModule(ctx context.Context, client *http.Client, _ *url.URL, req Request, _ string, _ *httpResult) []Finding {
	res, err := fetchForm(ctx, client, req.FormURL)
	if err != nil {
		return nil
	}

	var out []Finding
	cacheControl := strings.ToLower(res.Header.Get("Cache-Control"))
	if !strings.Contains(cacheControl, "no-store") {
		out = append(out, Finding{
			Label:      "Reset form isn't marked Cache-Control: no-store",
			Detail:     "A shared or proxy cache could serve this pre-authentication page back to a different visitor. Current value: " + orNone(res.Header.Get("Cache-Control")),
			Method:     "GET",
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		})
	}

	// Every Set-Cookie the form page issues gets checked independently --
	// one missing Secure/HttpOnly/SameSite is worth flagging on its own,
	// regardless of how many other cookies on the same page are fine.
	for _, cookie := range res.Header.Values("Set-Cookie") {
		lower := strings.ToLower(cookie)
		name := cookie
		if i := strings.Index(cookie, "="); i > 0 {
			name = cookie[:i]
		}
		var missing []string
		if !strings.Contains(lower, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(lower, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if m := sameSiteRe.FindStringSubmatch(lower); m == nil || m[1] == "none" {
			missing = append(missing, "SameSite=Lax/Strict")
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, Finding{
			Label:      fmt.Sprintf("Cookie %q is missing %s", name, strings.Join(missing, "/")),
			Method:     "GET",
			StatusCode: res.StatusCode,
			Request:    &res.Request,
		})
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
