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
// actually observed. The strongest level is confirmed, the checks that infer
// from a sample are likely, and a check that only matches a pattern in one
// response is heuristic.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceHeuristic = "heuristic"
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

// hostHeaderSpecs are the host-trust techniques tried. Besides the standard
// Host and forwarded-host headers, the list covers the non-standard names
// frameworks and proxies use for the same purpose (X-Host, X-Forwarded-Hostname,
// X-HTTP-Host-Override), since an app that trusts one of them often trusts the
// rest in the same way.
var hostHeaderSpecs = []hostHeaderSpec{
	{id: "host-header", description: "Host header", overrideHost: true},
	{id: "x-forwarded-host", description: "X-Forwarded-Host header", headerName: "X-Forwarded-Host"},
	{id: "x-forwarded-server", description: "X-Forwarded-Server header", headerName: "X-Forwarded-Server"},
	{id: "x-original-host", description: "X-Original-Host header", headerName: "X-Original-Host"},
	{id: "forwarded", description: "Forwarded header", headerName: "Forwarded", forwardedSyntax: true},
	{id: "x-host", description: "X-Host header", headerName: "X-Host"},
	{id: "x-forwarded-hostname", description: "X-Forwarded-Hostname header", headerName: "X-Forwarded-Hostname"},
	{id: "x-http-host-override", description: "X-HTTP-Host-Override header", headerName: "X-HTTP-Host-Override"},
}

var hostHeaderModule = moduleDef{
	id: "host-header", name: "Host header poisoning", severity: "high",
	run: runHostHeaderModule,
}

// runHostHeaderModule sends the reset request once per host-trust technique,
// each with the poison domain in that technique's header, and reports every
// technique whose domain comes back in the response.
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
			// Place the poison domain where this technique puts it: the Host
			// override, the RFC 7239 Forwarded syntax, or a plain proxy header.
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
				Confidence: ConfidenceLikely,
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
	// Each response header value is checked, since a Location or Set-Cookie
	// can carry the domain while the body does not.
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

// runLeakageModule scans the reset response for token-shaped values. When a
// known identifier is given, the scan reads the known account's response, and any
// value that also appears in the unknown account's response is dropped. Such a
// value is page furniture or a static value, not a token minted for that request.
func runLeakageModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, baseline *httpResult) []Finding {
	res := baseline
	known := false
	// A known-good identifier is more likely to trigger the app's real
	// "success" flow (as opposed to a generic "if this account exists…"
	// response an unknown identifier gets), so it's worth one extra request
	// specifically for this check when the operator supplied one.
	if req.KnownIdentifier != "" {
		fields := buildFields(req.identifierField(), req.KnownIdentifier, req.ExtraFields)
		if r, err := submit(ctx, client, target, req.method(), req.contentType(), fields, req.Headers, ""); err == nil {
			res = r
			known = true
		}
	}
	if res == nil {
		return nil
	}

	// ref is the unknown-account response to subtract from. Without a known
	// account there is nothing to subtract, so the finding is only heuristic.
	ref := ""
	confidence := ConfidenceHeuristic
	if known && baseline != nil {
		ref = baseline.Body
		confidence = ConfidenceLikely
	}

	var out []Finding
	seen := map[string]bool{}
	addMatch := func(field, value string) {
		// A value present in the unknown-account response is not specific to
		// the known account's request, so it is not reported as a leaked token.
		if ref != "" && strings.Contains(ref, value) {
			return
		}
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
			Confidence: confidence,
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

// throttlePhrases are wordings a limiter or bot-filter uses in a body. "captcha"
// and "too many failed" are the common ones on reset forms, where a limiter
// answers with a challenge rather than a 429.
var throttlePhrases = []string{
	"too many requests", "rate limit", "try again later", "temporarily blocked", "please wait before", "slow down",
	"too many attempts", "too many failed", "captcha",
}

// waveResult is what one concurrent wave of requests showed.
type waveResult struct {
	// throttled counts responses that signal a limit: 429, a Retry-After
	// header, a zeroed rate-limit header, or throttle wording.
	throttled int
	// answered counts responses that were a normal answer, meaning no transport
	// error and a status below 500.
	answered int
}

// runRateLimitModule fires escalating concurrent waves at the reset endpoint.
// A throttled response in any wave means a limit exists, so nothing is
// reported. Otherwise the finding states how many requests got a normal answer,
// so the claim is only as strong as the sample. If most of the burst failed,
// nothing is reported: a "no throttling" claim about a server that was erroring
// would be false.
func runRateLimitModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, _ *httpResult) []Finding {
	fields := buildFields(req.identifierField(), unknownID, req.ExtraFields)
	method, contentType := req.method(), req.contentType()

	sent, answered := 0, 0
	for _, wave := range rateLimitWaves {
		w := sendWave(ctx, client, target, method, contentType, fields, req.Headers, wave)
		sent += wave
		answered += w.answered
		if w.throttled > 0 {
			return nil
		}
	}
	// Require at least 90% of the burst to have been answered normally.
	if answered*10 < sent*9 {
		return nil
	}
	return []Finding{{
		Label:      fmt.Sprintf("No throttling seen across %d rapid requests", answered),
		Detail:     fmt.Sprintf("%d of %d concurrent requests, sent in waves of %v, returned a normal (non-throttled) response, with no throttle header or wording. That is evidence of no limit at this rate, not proof: a limiter keyed on a longer window, or one that starts after a threshold above %d requests, would not show here.", answered, sent, rateLimitWaves, sent),
		Method:     method,
		Confidence: ConfidenceLikely,
	}}
}

// sendWave fires n identical requests concurrently and reports how many were
// throttled and how many got a normal answer. Concurrency is deliberate: a
// limiter keyed on requests per second would go undetected by a slow
// sequential burst.
func sendWave(ctx context.Context, client *http.Client, target *url.URL, method, contentType string, fields map[string]string, headers map[string]string, n int) waveResult {
	// One slot per request, so each goroutine writes only its own element.
	type slot struct{ answered, throttled bool }
	slots := make([]slot, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := submit(ctx, client, target, method, contentType, fields, headers, "")
			// A transport error or a server error is not an answer about throttling.
			if err != nil || res.StatusCode >= 500 {
				return
			}
			slots[i] = slot{answered: true, throttled: looksThrottledResponse(res)}
		}(i)
	}
	wg.Wait()

	var out waveResult
	for _, s := range slots {
		if s.answered {
			out.answered++
		}
		if s.throttled {
			out.throttled++
		}
	}
	return out
}

// looksThrottledResponse reports whether one response signals a limit, by
// status, by the headers a limiter sets, or by throttle wording in the body.
func looksThrottledResponse(res *httpResult) bool {
	if res.StatusCode == http.StatusTooManyRequests {
		return true
	}
	// A limiter often answers 200 with these headers instead of a 429.
	if res.Header.Get("Retry-After") != "" {
		return true
	}
	if res.Header.Get("X-RateLimit-Remaining") == "0" || res.Header.Get("RateLimit-Remaining") == "0" {
		return true
	}
	return looksThrottled(res.Body)
}

// looksThrottled reports whether body contains a throttle phrase, case-insensitively.
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
//
// Two controls keep this from reporting noise:
//   - Echoes of the identifier are removed from each body before its length is
//     taken. A page that says "we sent a link to <address>" is longer for a longer
//     address, and that difference is the identifier itself, not account state.
//   - A second, fresh unknown identifier is sampled alongside. A difference that
//     also separates two identifiers that both don't exist is page or network
//     noise, so it is dropped.
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
	status int
	// length is the body length with identifier echoes removed (see
	// bodyLengthWithoutEchoes).
	length  int
	latency time.Duration
	suspect bool
}

// measureDiff is one way two sample groups differ: the measure it's about
// ("status", "length", or "timing") and a sentence describing the difference.
type measureDiff struct {
	measure string
	reason  string
}

// runEnumerationModule compares a known identifier's responses with an unknown
// one's, with a second unknown identifier as the noise control. Samples are
// interleaved (known, unknown, control, ...) so that drift in the network or the
// target falls on every group equally. A difference is reported only when the
// groups separate completely on that measure, which is what a real side channel
// looks like, and only when the same measure does not separate the two unknown
// identifiers. Timing is ignored when the governor has flagged the host as
// drifting, since throttling itself moves latency.
func runEnumerationModule(ctx context.Context, client *http.Client, target *url.URL, req Request, unknownID string, _ *httpResult) []Finding {
	if req.KnownIdentifier == "" || unknownID == "" {
		return nil
	}
	control := req.freshUnknownIdentifier()
	echoes := []string{req.KnownIdentifier, unknownID, control}
	known, unknown, ctl := sampleInterleaved(ctx, client, target, req, req.KnownIdentifier, unknownID, control, echoes)
	if len(known) < enumerationSamples || len(unknown) < enumerationSamples || len(ctl) < enumerationSamples {
		return nil
	}

	timing := !anySuspect(known, unknown, ctl)

	// Measures that also separate two unknown identifiers are noise, not
	// account state, so they are dropped from the report.
	noise := map[string]bool{}
	for _, d := range differingMeasures(unknown, ctl, "the unknown account", "a second unknown account", timing) {
		noise[d.measure] = true
	}
	var reasons []string
	for _, d := range differingMeasures(known, unknown, "the known account", "the unknown one", timing) {
		if noise[d.measure] {
			continue
		}
		reasons = append(reasons, d.reason)
	}

	if len(reasons) == 0 {
		return nil
	}
	return []Finding{{
		Label:      "Known and unknown identifiers get distinguishable responses",
		Detail:     "The request-reset endpoint responds differently depending on whether the account exists: " + strings.Join(reasons, "; ") + ". Two unknown identifiers were also sampled and did not differ on those measures, so the difference is not page or network noise. An attacker can use this to enumerate registered accounts.",
		Method:     req.method(),
		StatusCode: known[0].status,
		Confidence: ConfidenceLikely,
	}}
}

// differingMeasures lists every measure on which groups a and b separate
// completely: status (when each group is uniform and the two differ), length
// (beyond enumerationLengthTolerance), and, when timing is allowed, latency
// (beyond enumerationTimingTolerance). nameA and nameB label the groups in the
// reason text.
func differingMeasures(a, b []enumSample, nameA, nameB string, timing bool) []measureDiff {
	var out []measureDiff
	if x, y := uniformStatus(a), uniformStatus(b); x >= 0 && y >= 0 && x != y {
		out = append(out, measureDiff{"status", fmt.Sprintf("status code differs on every sample (%d for %s vs. %d for %s)", x, nameA, y, nameB)})
	}
	la, lb := lengthsOf(a), lengthsOf(b)
	if separated(la, lb) && math.Abs(median(la)-median(lb)) > enumerationLengthTolerance {
		out = append(out, measureDiff{"length", fmt.Sprintf("response size differs on every sample (median ~%.0f bytes for %s vs. ~%.0f for %s)", median(la), nameA, median(lb), nameB)})
	}
	if timing {
		ta, tb := latencies(a), latencies(b)
		if separated(ta, tb) && math.Abs(median(ta)-median(tb)) > float64(enumerationTimingTolerance) {
			out = append(out, measureDiff{"timing", fmt.Sprintf("response time differs on every sample (median %v for %s vs. %v for %s)",
				time.Duration(median(ta)).Round(time.Millisecond), nameA, time.Duration(median(tb)).Round(time.Millisecond), nameB)})
		}
	}
	return out
}

// anySuspect reports whether any sample in any group came back flagged by the
// governor as drifting, which makes its latency unreliable.
func anySuspect(groups ...[]enumSample) bool {
	for _, g := range groups {
		for _, s := range g {
			if s.suspect {
				return true
			}
		}
	}
	return false
}

// sampleInterleaved sends enumerationSamples requests for each of the three
// identifiers, cycling through them in turn. Requests are sequential because
// they are timed; a concurrent burst would let the identifiers contend for one
// connection.
func sampleInterleaved(ctx context.Context, client *http.Client, target *url.URL, req Request, known, unknown, control string, echoes []string) (knownSamples, unknownSamples, controlSamples []enumSample) {
	// Each pass sends one request per identifier, in a fixed order, so drift
	// during the run lands on all three groups alike.
	for i := 0; i < enumerationSamples; i++ {
		if s, ok := sampleOnce(ctx, client, target, req, known, echoes); ok {
			knownSamples = append(knownSamples, s)
		}
		if s, ok := sampleOnce(ctx, client, target, req, unknown, echoes); ok {
			unknownSamples = append(unknownSamples, s)
		}
		if s, ok := sampleOnce(ctx, client, target, req, control, echoes); ok {
			controlSamples = append(controlSamples, s)
		}
	}
	return knownSamples, unknownSamples, controlSamples
}

// sampleOnce sends one request for identifier and records its timing and its
// echo-free body length.
func sampleOnce(ctx context.Context, client *http.Client, target *url.URL, req Request, identifier string, echoes []string) (enumSample, bool) {
	fields := buildFields(req.identifierField(), identifier, req.ExtraFields)
	res, err := submit(ctx, client, target, req.method(), req.contentType(), fields, req.Headers, "")
	if err != nil {
		return enumSample{}, false
	}
	return enumSample{
		status:  res.StatusCode,
		length:  bodyLengthWithoutEchoes(res.Body, echoes),
		latency: res.Latency,
		suspect: res.Header.Get(netgov.SuspectHeader) != "",
	}, true
}

// bodyLengthWithoutEchoes returns the length of body after removing every
// occurrence of the given identifiers, both as sent and URL-escaped. The escaped
// form matters because a form-encoded echo is escaped (@ becomes %40).
func bodyLengthWithoutEchoes(body string, identifiers []string) int {
	// Strip each identifier in both its literal and escaped spelling.
	for _, id := range identifiers {
		if id == "" {
			continue
		}
		body = strings.ReplaceAll(body, id, "")
		body = strings.ReplaceAll(body, url.QueryEscape(id), "")
	}
	return len(body)
}

// lengthsOf returns the echo-free body lengths of samples as floats.
func lengthsOf(s []enumSample) []float64 {
	out := make([]float64, len(s))
	for i := range s {
		out[i] = float64(s[i].length)
	}
	return out
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

// Patterns for hasCSRFToken. Tags are found first, then their attributes are
// checked on their own, so attribute order does not matter.
var (
	inputTagRe       = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	metaTagRe        = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	hiddenTypeRe     = regexp.MustCompile(`(?i)\btype\s*=\s*["']?hidden\b`)
	tokenInputNameRe = regexp.MustCompile(`(?i)\bname\s*=\s*["']?(?:[^"'\s>]*(?:csrf|xsrf|authenticity[_-]?token|requestverificationtoken|antiforgery)[^"'\s>]*|_token)(?:["'\s>/]|$)`)
	tokenMetaNameRe  = regexp.MustCompile(`(?i)\bname\s*=\s*["']?[^"'\s>]*(?:csrf|xsrf)[^"'\s>]*`)
)

// hasCSRFToken reports whether a page carries an anti-CSRF token a form could
// submit: a hidden input with a token-like name, or a token <meta> that a script
// reads and sends as a header. A visible input named "csrf_note", or a hidden
// access_token, is not a token. csrf-param and csrf-header metas name the field
// or header, not the token, so they are ignored.
func hasCSRFToken(body string) bool {
	// A hidden input is a token only if its name reads as one.
	for _, tag := range inputTagRe.FindAllString(body, -1) {
		if hiddenTypeRe.MatchString(tag) && tokenInputNameRe.MatchString(tag) {
			return true
		}
	}
	// A token meta counts only when its name is a token and not a param or header.
	for _, tag := range metaTagRe.FindAllString(body, -1) {
		lower := strings.ToLower(tag)
		if tokenMetaNameRe.MatchString(tag) && !strings.Contains(lower, "param") && !strings.Contains(lower, "header") {
			return true
		}
	}
	return false
}

func runCSRFModule(ctx context.Context, client *http.Client, _ *url.URL, req Request, _ string, _ *httpResult) []Finding {
	res, err := fetchForm(ctx, client, req.FormURL, req.Headers)
	if err != nil {
		return nil
	}
	if hasCSRFToken(res.Body) {
		return nil
	}
	return []Finding{{
		Label:      "No CSRF-token-looking field found on the reset form",
		Detail:     "Checked " + req.FormURL + " for a hidden input named like a CSRF/authenticity token, and for a token meta tag, and found neither -- confirm the form isn't relying on a header-based token this static check can't see before treating this as confirmed.",
		Method:     "GET",
		StatusCode: res.StatusCode,
		Request:    &res.Request,
		Confidence: ConfidenceHeuristic,
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

// parseCookieFlags reads the name and the Secure, HttpOnly, and SameSite
// attributes of one Set-Cookie header. Each attribute is matched by name in the
// ";"-separated list, so a cookie value that contains the word "secure" is not
// read as the flag.
func parseCookieFlags(raw string) (name string, secure, httpOnly bool, sameSite string) {
	parts := strings.Split(raw, ";")
	name = parts[0]
	if i := strings.Index(name, "="); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	// Each segment after the first is an attribute; read its name and value.
	for _, p := range parts[1:] {
		key, val := p, ""
		if i := strings.Index(p, "="); i >= 0 {
			key, val = p[:i], p[i+1:]
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "secure":
			secure = true
		case "httponly":
			httpOnly = true
		case "samesite":
			sameSite = strings.ToLower(strings.TrimSpace(val))
		}
	}
	return name, secure, httpOnly, sameSite
}

func runFormSecurityModule(ctx context.Context, client *http.Client, _ *url.URL, req Request, _ string, _ *httpResult) []Finding {
	res, err := fetchForm(ctx, client, req.FormURL, req.Headers)
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
			Confidence: ConfidenceLikely,
		})
	}

	// Every Set-Cookie the form page issues gets checked independently --
	// one missing Secure/HttpOnly/SameSite is worth flagging on its own,
	// regardless of how many other cookies on the same page are fine.
	for _, cookie := range res.Header.Values("Set-Cookie") {
		name, secure, httpOnly, sameSite := parseCookieFlags(cookie)
		var missing []string
		if !secure {
			missing = append(missing, "Secure")
		}
		if !httpOnly {
			missing = append(missing, "HttpOnly")
		}
		// SameSite=None sends the cookie cross-site, the same as no attribute at
		// all, so only lax and strict count.
		if sameSite != "lax" && sameSite != "strict" {
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
			Confidence: ConfidenceLikely,
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
