// Package netgov is the single HTTP path every scanner uses. It is a
// http.RoundTripper that keeps one shared connection pool and one adaptive
// budget per host, so ten scanners aimed at the same target cannot each
// assume they own the whole host.
//
// The budget adapts to what the target does:
//   - Block signals (429, 503 with Retry-After, WAF/challenge markers on 403
//     or 503) halve the host's concurrency, pause the host, and retry
//     idempotent requests once the pause ends.
//   - Repeated blocks trip a circuit breaker that pauses the host for longer,
//     and repeated trips stop the host entirely for a cooldown, so modules
//     fail fast instead of hammering a target that is refusing them.
//   - Clean responses grow concurrency back toward the policy ceiling.
//   - Drift: a random-path canary is re-requested periodically. If its
//     fingerprint changes (the host started serving a challenge or decoy
//     page), the host is marked suspect, throttled to one request at a time,
//     and responses are tagged with X-Aperture-Suspect so findings from that
//     window can be recognized later.
package netgov

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Indigo6415/Aperture/internal/fingerprint"
)

// DefaultConcurrency is the per-host in-flight ceiling when a request's
// context carries no Policy. It is deliberately above any single scanner's
// own worker count, so the shared cap only bites when scanners overlap.
const DefaultConcurrency = 32

// SuspectHeader is set on responses served while a host is marked suspect.
const SuspectHeader = "X-Aperture-Suspect"

// ErrHostBlocked is returned when a host has been blocked repeatedly and is in
// its cooldown. Callers treat it like any transport error (no finding).
var ErrHostBlocked = errors.New("netgov: host is blocking requests; cooling down")

// Policy is per-scan tuning carried on the request context. The zero value
// means defaults everywhere.
type Policy struct {
	// MaxConcurrency caps in-flight requests to one host (0 = DefaultConcurrency).
	MaxConcurrency int
	// MaxRPS paces one host at this rate when it is fully open (0 = unpaced).
	MaxRPS float64
	// Scope limits which hosts the request may reach (nil = unrestricted). A
	// request outside it fails with ErrOutOfScope before anything is sent.
	Scope *Scope
}

type policyKey struct{}

// WithPolicy returns a context whose requests use p.
func WithPolicy(ctx context.Context, p Policy) context.Context {
	return context.WithValue(ctx, policyKey{}, p)
}

// policyFrom returns the policy on ctx, or the zero Policy.
func policyFrom(ctx context.Context) Policy {
	p, _ := ctx.Value(policyKey{}).(Policy)
	return p
}

// tuning holds the adaptive-control constants. Tests shrink the durations.
type tuning struct {
	breakerThreshold  int           // consecutive blocks that trip the breaker
	hostBlockTrips    int           // breaker trips before the host cools down entirely
	baseBackoff       time.Duration // first pause after a block
	maxBackoff        time.Duration // ceiling for exponential pause growth
	maxRetryAfter     time.Duration // Retry-After longer than this is not waited on
	breakerBase       time.Duration // first breaker open duration
	breakerMax        time.Duration // ceiling for breaker open duration
	hostCooldown      time.Duration // full cooldown after repeated trips
	driftEvery        int           // governed responses between canary checks
	driftPause        time.Duration // pause applied when drift is detected
	growAfterClean    int           // clean responses before concurrency grows by one
	maxBlockRetries   int           // retries of an idempotent request after a block
	canaryTimeout     time.Duration // bound on one canary request
	errorBackoffAfter int           // consecutive transport errors before backing off
	rebaselineAfter   int           // consecutive drifted canaries before adopting the new one as baseline
}

// defaultTuning returns the production constants.
func defaultTuning() tuning {
	return tuning{
		breakerThreshold:  3,
		hostBlockTrips:    3,
		baseBackoff:       2 * time.Second,
		maxBackoff:        60 * time.Second,
		maxRetryAfter:     60 * time.Second,
		breakerBase:       5 * time.Second,
		breakerMax:        2 * time.Minute,
		hostCooldown:      10 * time.Minute,
		driftEvery:        150,
		driftPause:        15 * time.Second,
		growAfterClean:    25,
		maxBlockRetries:   2,
		canaryTimeout:     8 * time.Second,
		errorBackoffAfter: 5,
		rebaselineAfter:   3,
	}
}

// Event is one notable change in a host's state, delivered to the event hook.
type Event struct {
	Host   string    `json:"host"`
	Kind   string    `json:"kind"`   // throttled | breaker-open | host-blocked | drift | rebaselined | recovered
	Detail string    `json:"detail"` // human-readable reason
	At     time.Time `json:"at"`
}

// HostStatus is a point-in-time view of one host's governor state.
type HostStatus struct {
	Host         string    `json:"host"`
	Limit        int       `json:"limit"`
	Inflight     int       `json:"inflight"`
	BlockStreak  int       `json:"blockStreak"`
	Trips        int       `json:"trips"`
	Suspect      bool      `json:"suspect"`
	PauseUntil   time.Time `json:"pauseUntil,omitzero"`
	BlockedUntil time.Time `json:"blockedUntil,omitzero"`
}

// hostState is the governor's mutable state for one host:port.
type hostState struct {
	limit        int       // current in-flight ceiling (AIMD-controlled)
	ceiling      int       // policy maximum for limit
	inflight     int       // requests currently holding a slot
	cleanRun     int       // consecutive clean responses
	blockStreak  int       // consecutive blocked responses
	errStreak    int       // consecutive transport errors
	trips        int       // breaker trips since the last long clean run
	pauseUntil   time.Time // no new request starts before this
	blockedUntil time.Time // host-wide cooldown, requests fail fast before this
	nextSlot     time.Time // pacing reservation
	wake         chan struct{}
	canaryReady  chan struct{}
	canaryStart  bool
	canary       *fingerprint.Observation
	governed     int // governed responses since the last canary check
	driftStreak  int // consecutive canary checks that drifted
	suspect      bool
}

// Transport is the adaptive RoundTripper. Use Shared for production; New is
// for tests that need an injected inner transport.
type Transport struct {
	inner http.RoundTripper
	tune  tuning
	now   func() time.Time

	mu    sync.Mutex
	hosts map[string]*hostState
}

// Shared is the process-wide transport every scanner client uses, so the
// per-host budget is global across scanners.
var Shared = New(newInnerTransport())

// newInnerTransport builds the TLS-tolerant pool. Aperture targets routinely
// include self-signed lab, CTF, and internal hosts, so verification is off
// everywhere, matching the posture every scanner already had.
func newInnerTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // deliberate: authorized testing against lab/CTF/self-signed targets
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
}

// New returns a Transport that forwards to inner under the default tuning.
func New(inner http.RoundTripper) *Transport {
	return &Transport{
		inner: inner,
		tune:  defaultTuning(),
		now:   time.Now,
		hosts: map[string]*hostState{},
	}
}

// ApplyHeaders copies headers onto req. Go's net/http never sends a Host
// entry from req.Header (it uses req.Host), so a Host header set the usual way
// is silently dropped. Every scanner that forwards saved-credential or
// user-supplied headers should go through here.
func ApplyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
}

// NewClient returns an *http.Client routed through Shared. followRedirects
// controls whether 3xx responses are followed; when false the 3xx is returned
// as-is, which several scanners rely on to judge a single hop.
func NewClient(timeout time.Duration, followRedirects bool) *http.Client {
	c := &http.Client{Timeout: timeout, Transport: Shared}
	// CheckRedirect runs before each followed hop, which is where the hop is
	// linked to the 3xx that led to it. Following is still the client's own
	// decision; this only adds the link and reproduces net/http's default limit.
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		// net/http's default cap when no CheckRedirect is set.
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		linkRedirect(req, via[len(via)-1])
		return nil
	}
	return c
}

// eventHook receives state-change events. The default logs them.
var (
	eventMu   sync.RWMutex
	eventHook = func(e Event) {
		log.Printf("netgov: %s %s: %s", e.Host, e.Kind, e.Detail)
	}
)

// SetEventHook replaces the function that receives state-change events, or
// restores logging when fn is nil.
func SetEventHook(fn func(Event)) {
	eventMu.Lock()
	defer eventMu.Unlock()
	if fn == nil {
		fn = func(e Event) { log.Printf("netgov: %s %s: %s", e.Host, e.Kind, e.Detail) }
	}
	eventHook = fn
}

// emit delivers an event to the current hook.
func (t *Transport) emit(host, kind, detail string) {
	eventMu.RLock()
	fn := eventHook
	eventMu.RUnlock()
	fn(Event{Host: host, Kind: kind, Detail: detail, At: t.now()})
}

// Snapshot returns the governor state of every host seen so far.
func (t *Transport) Snapshot() []HostStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]HostStatus, 0, len(t.hosts))
	for host, st := range t.hosts {
		out = append(out, HostStatus{
			Host:         host,
			Limit:        st.limit,
			Inflight:     st.inflight,
			BlockStreak:  st.blockStreak,
			Trips:        st.trips,
			Suspect:      st.suspect,
			PauseUntil:   zeroIfPast(st.pauseUntil, t.now()),
			BlockedUntil: zeroIfPast(st.blockedUntil, t.now()),
		})
	}
	return out
}

// zeroIfPast returns the zero time when at is already in the past, so the
// JSON form omits expired pauses.
func zeroIfPast(at, now time.Time) time.Time {
	if at.After(now) {
		return at
	}
	return time.Time{}
}

// state returns the host's state, creating it on first contact. Caller must
// hold t.mu.
func (t *Transport) stateLocked(host string) *hostState {
	st, ok := t.hosts[host]
	if !ok {
		st = &hostState{wake: make(chan struct{}), canaryReady: make(chan struct{})}
		t.hosts[host] = st
	}
	return st
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	ctx := req.Context()
	pol := policyFrom(ctx)

	// Scope is checked first, so an out-of-scope host never gets a canary
	// probe, a connection, or a log entry that looks like traffic.
	if !pol.Scope.Allows(host) {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, host)
	}

	t.mu.Lock()
	st := t.stateLocked(host)
	t.mu.Unlock()

	// The first request to a host establishes its canary fingerprint before
	// any real traffic, so drift is measured against a known baseline.
	if err := t.ensureCanary(ctx, req, st); err != nil {
		return nil, err
	}

	for retries := 0; ; retries++ {
		// Checked on every attempt, so a retry cannot slip through after the
		// breaker trips during the previous attempt.
		if err := t.refused(host, st); err != nil {
			return nil, err
		}
		release, err := t.acquire(ctx, host, st, pol)
		if err != nil {
			return nil, err
		}
		sent := time.Now()
		resp, err := t.inner.RoundTrip(req)
		release()
		if err != nil {
			t.recordError(host, st, ctx.Err() == nil)
			// The request went out, so it belongs in a scan's request log even
			// though no response came back.
			recordFailure(req, sent, err)
			return nil, err
		}

		// Time to headers is taken before classify, which may read part of the
		// body and would otherwise inflate it.
		ttfb := time.Since(sent)
		v := classify(resp)
		t.record(host, st, v)
		// Wrapped after classify so the recorded body includes the bytes it
		// peeked at. Every attempt is recorded, including blocked ones that
		// get retried below.
		observeResponse(req, resp, sent, ttfb)

		// Blocked idempotent requests are retried after the host's pause ends.
		// The retry only happens when the pause is short enough to wait for.
		if v.blocked && retries < t.tune.maxBlockRetries && retryable(req) && t.pauseWithin(st, t.tune.maxRetryAfter) {
			drain(resp)
			continue
		}

		t.maybeCheckDrift(ctx, req, host, st)
		t.mu.Lock()
		suspect := st.suspect
		t.mu.Unlock()
		if suspect {
			resp.Header.Set(SuspectHeader, "drift")
		}
		return resp, nil
	}
}

// refused returns ErrHostBlocked while the host is in its cooldown, so every
// module fails fast instead of queueing requests against a host that is
// refusing them.
func (t *Transport) refused(host string, st *hostState) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.now().Before(st.blockedUntil) {
		return fmt.Errorf("%w (%s)", ErrHostBlocked, host)
	}
	return nil
}

// acquire waits until the host has a free slot and pacing allows a request,
// then returns the function that releases the slot. Waiting respects ctx.
func (t *Transport) acquire(ctx context.Context, host string, st *hostState, pol Policy) (func(), error) {
	ceiling := pol.MaxConcurrency
	if ceiling <= 0 {
		ceiling = DefaultConcurrency
	}

	for {
		t.mu.Lock()
		st.ceiling = ceiling
		if st.limit == 0 || st.limit > ceiling {
			st.limit = ceiling
		}
		now := t.now()
		// A pause blocks new starts for the whole host.
		if now.Before(st.pauseUntil) {
			wait := st.pauseUntil.Sub(now)
			wake := st.wake
			t.mu.Unlock()
			if err := waitFor(ctx, wait, wake); err != nil {
				return nil, err
			}
			continue
		}
		if st.inflight < st.limit {
			st.inflight++
			// Pacing happens while holding the slot so the reservation and
			// the request stay paired.
			wait := t.paceLocked(st, pol, now)
			t.mu.Unlock()
			if wait > 0 {
				if err := waitFor(ctx, wait, nil); err != nil {
					t.release(st)
					return nil, err
				}
			}
			return func() { t.release(st) }, nil
		}
		wake := st.wake
		t.mu.Unlock()
		if err := waitFor(ctx, 0, wake); err != nil {
			return nil, err
		}
	}
}

// release frees one slot and wakes anything waiting for capacity.
func (t *Transport) release(st *hostState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st.inflight--
	signalLocked(st)
}

// paceLocked reserves the next start slot for the host and returns how long
// the caller must wait before sending. Pacing scales with the current
// concurrency limit, so a host under pressure is also paced more slowly.
func (t *Transport) paceLocked(st *hostState, pol Policy, now time.Time) time.Duration {
	if pol.MaxRPS <= 0 {
		return 0
	}
	effective := pol.MaxRPS * float64(st.limit) / float64(st.ceiling)
	if effective <= 0 {
		effective = pol.MaxRPS
	}
	interval := time.Duration(float64(time.Second) / effective)
	slot := now
	if st.nextSlot.After(now) {
		slot = st.nextSlot
	}
	st.nextSlot = slot.Add(interval)
	return slot.Sub(now)
}

// classify decides whether a response is a block signal. Body markers are
// only read on error statuses, so the common success path costs nothing.
func classify(resp *http.Response) verdict {
	return classifyFields(resp.StatusCode, resp.Header, func() []byte { return peekBody(resp) })
}

// classifyFields is the shared classification rule. peek is called lazily,
// only for the statuses where a body marker can change the verdict.
func classifyFields(status int, header http.Header, peek func() []byte) verdict {
	retryAfter := parseRetryAfter(header.Get("Retry-After"))

	// Cloudflare sets this header when it intercepts a request.
	if strings.EqualFold(header.Get("Cf-Mitigated"), "challenge") {
		return verdict{blocked: true, reason: "cloudflare challenge", retryAfter: retryAfter}
	}
	if status == http.StatusTooManyRequests {
		return verdict{blocked: true, reason: "429 too many requests", retryAfter: retryAfter}
	}
	// 403 and 503 are normal for many resources, so they only count as a
	// block when the body carries a WAF/challenge marker.
	if status == http.StatusForbidden || status == http.StatusServiceUnavailable {
		if marker := wafMarker(peek()); marker != "" {
			return verdict{blocked: true, reason: fmt.Sprintf("%d with %q", status, marker), retryAfter: retryAfter}
		}
		// 503 with Retry-After is an explicit back-off request.
		if status == http.StatusServiceUnavailable && retryAfter > 0 {
			return verdict{blocked: true, reason: "503 with Retry-After", retryAfter: retryAfter}
		}
	}
	return verdict{}
}

// verdict is the outcome of classify.
type verdict struct {
	blocked    bool
	reason     string
	retryAfter time.Duration
}

// wafMarkers are case-insensitive substrings that identify WAF, bot-management,
// and challenge pages. They are specific enough that an ordinary 403 page
// does not match.
var wafMarkers = []string{
	"cf-chl-",
	"challenge-platform",
	"cf_chl_opt",
	"just a moment...",
	"incapsula incident",
	"request unsuccessful. incapsula",
	"reference #18.",
	"perimeterx",
	"px-captcha",
	"datadome",
	"g-recaptcha",
	"h-captcha",
}

// wafMarker returns the first WAF marker found in the peeked body, or "".
func wafMarker(peek []byte) string {
	lower := strings.ToLower(string(peek))
	for _, m := range wafMarkers {
		if strings.Contains(lower, m) {
			return m
		}
	}
	return ""
}

// peekBody reads up to 16 KiB of the response body and reattaches it so the
// caller still sees the full body. The read is bounded so a large error page
// cannot stall classification.
func peekBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	resp.Body = &replayBody{Reader: io.MultiReader(strings.NewReader(string(buf)), resp.Body), closer: resp.Body}
	return buf
}

// replayBody is an io.ReadCloser that replays peeked bytes before the rest of
// the original body and closes the original on Close.
type replayBody struct {
	io.Reader
	closer io.Closer
}

// Close closes the underlying body.
func (r *replayBody) Close() error { return r.closer.Close() }

// parseRetryAfter reads a Retry-After header as seconds or an HTTP date.
// Unparseable or past values return zero.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := time.Until(at); d > 0 {
			return d
		}
	}
	return 0
}

// record applies a classified response to the host's adaptive state.
func (t *Transport) record(host string, st *hostState, v verdict) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()

	if !v.blocked {
		st.blockStreak = 0
		st.errStreak = 0
		st.cleanRun++
		// Grow concurrency back slowly after sustained clean traffic.
		if st.cleanRun >= t.tune.growAfterClean && st.limit < st.ceiling {
			st.limit++
			st.cleanRun = 0
			signalLocked(st)
		}
		// A long clean run forgives earlier breaker trips.
		if st.cleanRun >= 100 {
			st.trips = 0
		}
		return
	}

	st.cleanRun = 0
	st.blockStreak++
	// Halve concurrency on every block so pressure drops immediately.
	st.limit = max(1, st.limit/2)

	// Pause before the next start. Retry-After wins when present, capped so
	// one hostile header cannot stall a scan for hours.
	pause := backoff(t.tune.baseBackoff, t.tune.maxBackoff, st.blockStreak)
	if v.retryAfter > 0 {
		pause = min(v.retryAfter, 5*time.Minute)
	}
	if until := now.Add(pause); until.After(st.pauseUntil) {
		st.pauseUntil = until
	}
	signalLocked(st)

	if st.blockStreak == 1 {
		t.emit(host, "throttled", fmt.Sprintf("%s; concurrency now %d, pausing %s", v.reason, st.limit, pause.Round(time.Millisecond)))
	}

	// Repeated blocks trip the breaker: a longer pause, and after enough trips
	// a host-wide cooldown.
	if st.blockStreak >= t.tune.breakerThreshold {
		st.trips++
		open := backoff(t.tune.breakerBase, t.tune.breakerMax, st.trips)
		if until := now.Add(open); until.After(st.pauseUntil) {
			st.pauseUntil = until
		}
		t.emit(host, "breaker-open", fmt.Sprintf("%d consecutive blocks; trip %d, pausing %s", st.blockStreak, st.trips, open.Round(time.Second)))
		st.blockStreak = 0
		if st.trips >= t.tune.hostBlockTrips {
			st.blockedUntil = now.Add(t.tune.hostCooldown)
			st.trips = 0
			t.emit(host, "host-blocked", fmt.Sprintf("cooling down for %s; requests fail fast until then", t.tune.hostCooldown))
		}
	}
}

// Admit takes one request slot for host on behalf of code that cannot use an
// http.Client, such as the raw-socket probes in bypass403. It honors the same
// per-host ceiling, pacing, pauses, and cooldown as RoundTrip. The returned
// release function must always be called; a non-nil error means the request
// must not be sent.
func Admit(ctx context.Context, host string) (func(), error) {
	t := Shared
	t.mu.Lock()
	st := t.stateLocked(host)
	t.mu.Unlock()
	if err := t.refused(host, st); err != nil {
		return nil, err
	}
	return t.acquire(ctx, host, st, policyFrom(ctx))
}

// Report feeds the outcome of a request sent after Admit into the host's
// adaptive state, so raw-socket traffic and http.Client traffic share one
// picture of how the host is reacting.
func Report(host string, status int, header http.Header, body []byte) {
	t := Shared
	v := classifyFields(status, header, func() []byte { return body })
	t.mu.Lock()
	st := t.stateLocked(host)
	t.mu.Unlock()
	t.record(host, st, v)
}

// recordError handles a transport failure. Failures caused by the caller's
// own cancellation are ignored; real timeouts and resets back off gently
// after a run of them.
func (t *Transport) recordError(host string, st *hostState, real bool) {
	if !real {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st.errStreak++
	if st.errStreak >= t.tune.errorBackoffAfter {
		st.errStreak = 0
		st.limit = max(1, st.limit/2)
		st.pauseUntil = t.now().Add(t.tune.baseBackoff)
		signalLocked(st)
		t.emit(host, "throttled", "repeated timeouts or connection resets; halving concurrency")
	}
}

// ensureCanary fetches the host's canary fingerprint exactly once. Concurrent
// first requests wait on the one that does the work.
func (t *Transport) ensureCanary(ctx context.Context, req *http.Request, st *hostState) error {
	t.mu.Lock()
	if st.canaryStart {
		ready := st.canaryReady
		t.mu.Unlock()
		select {
		case <-ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	st.canaryStart = true
	t.mu.Unlock()

	obs, err := t.probeCanary(ctx, req)
	t.mu.Lock()
	if err == nil {
		st.canary = &obs
	}
	close(st.canaryReady)
	t.mu.Unlock()
	return nil
}

// canaryURL is a random path at the host root that cannot exist. Its response
// describes what the host returns for anything unknown right now.
func canaryURL(req *http.Request) string {
	u := url.URL{Scheme: req.URL.Scheme, Host: req.URL.Host, Path: "/aperture-canary-" + randomToken()}
	return u.String()
}

// probeCanary requests the canary through the inner transport, bypassing the
// governor so canary traffic does not count against the host's budget.
func (t *Transport) probeCanary(ctx context.Context, req *http.Request) (fingerprint.Observation, error) {
	cctx, cancel := context.WithTimeout(ctx, t.tune.canaryTimeout)
	defer cancel()
	creq, err := http.NewRequestWithContext(cctx, http.MethodGet, canaryURL(req), nil)
	if err != nil {
		return fingerprint.Observation{}, err
	}
	creq.Header = req.Header.Clone()
	creq.Header.Del("Content-Length")
	resp, err := t.inner.RoundTrip(creq)
	if err != nil {
		return fingerprint.Observation{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return fingerprint.Observe(resp.StatusCode, resp.Header.Get("Content-Type"), body), nil
}

// maybeCheckDrift re-requests the canary every driftEvery governed responses
// and compares it with the baseline. A change marks the host suspect and
// throttles it; a sustained change becomes the new baseline so a legitimate
// site redesign does not stay suspect forever.
func (t *Transport) maybeCheckDrift(ctx context.Context, req *http.Request, host string, st *hostState) {
	t.mu.Lock()
	st.governed++
	due := st.governed >= t.tune.driftEvery && st.canary != nil
	if due {
		st.governed = 0
	}
	baseline := st.canary
	t.mu.Unlock()
	if !due {
		return
	}

	obs, err := t.probeCanary(ctx, req)
	if err != nil {
		// An unreachable canary says nothing about content; try again later.
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if fingerprint.Similar(*baseline, obs) {
		// The host matches its baseline again, so any earlier drift is over.
		if st.suspect {
			st.suspect = false
			st.driftStreak = 0
			st.limit = max(st.limit, 1)
			t.emit(host, "recovered", "canary matches baseline again; suspect flag cleared")
		}
		return
	}

	st.driftStreak++
	if !st.suspect {
		st.suspect = true
		st.limit = 1
		st.pauseUntil = t.now().Add(t.tune.driftPause)
		signalLocked(st)
		t.emit(host, "drift", fmt.Sprintf("canary changed (status %d -> %d, length %d -> %d); throttling to one request at a time", baseline.Status, obs.Status, baseline.Length, obs.Length))
	}
	if st.driftStreak >= t.tune.rebaselineAfter {
		st.canary = &obs
		st.suspect = false
		st.driftStreak = 0
		t.emit(host, "rebaselined", "drift persisted across checks; adopting the new canary as baseline")
	}
}

// pauseWithin reports whether the host's current pause ends within max.
func (t *Transport) pauseWithin(st *hostState, max time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return st.pauseUntil.Sub(t.now()) <= max
}

// retryable reports whether req can be sent again without consuming its body.
func retryable(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// drain discards and closes a response body so its connection is reusable.
func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// backoff returns base * 2^(n-1), capped at limit. n below 1 is treated as 1.
func backoff(base, limit time.Duration, n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	if d > limit {
		return limit
	}
	return d
}

// signalLocked wakes everything waiting on this host's state and installs a
// fresh channel for the next wait. Caller must hold t.mu.
func signalLocked(st *hostState) {
	close(st.wake)
	st.wake = make(chan struct{})
}

// waitFor blocks until d elapses, wake is closed, or ctx ends. A zero d with a
// nil wake returns immediately.
func waitFor(ctx context.Context, d time.Duration, wake <-chan struct{}) error {
	if d <= 0 && wake == nil {
		return ctx.Err()
	}
	var timer <-chan time.Time
	if d > 0 {
		tm := time.NewTimer(d)
		defer tm.Stop()
		timer = tm.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer:
		return nil
	case <-wake:
		return nil
	}
}

// randomToken returns a short unguessable token for canary paths. Falls back
// to a time-based value only if the system entropy source is broken, which
// would already break TLS.
func randomToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// WithPolicyRoundTripper wraps inner so every request it forwards carries p
// on its context. It serves callers that build requests without a context
// of their own, so their per-scan rate still reaches the shared transport.
func WithPolicyRoundTripper(inner http.RoundTripper, p Policy) http.RoundTripper {
	return policyRoundTripper{inner: inner, pol: p}
}

// policyRoundTripper is the RoundTripper behind WithPolicyRoundTripper.
type policyRoundTripper struct {
	inner http.RoundTripper
	pol   Policy
}

// RoundTrip stamps the wrapped policy onto the request's context and forwards
// it to the inner transport.
func (t policyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.inner.RoundTrip(req.WithContext(WithPolicy(req.Context(), t.pol)))
}
