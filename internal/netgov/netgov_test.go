package netgov

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fastTuning returns production constants with every pause shrunk so tests
// finish in milliseconds.
func fastTuning() tuning {
	tn := defaultTuning()
	tn.baseBackoff = 10 * time.Millisecond
	tn.maxBackoff = 20 * time.Millisecond
	tn.breakerBase = 10 * time.Millisecond
	tn.breakerMax = 20 * time.Millisecond
	tn.driftPause = 5 * time.Millisecond
	tn.hostCooldown = 200 * time.Millisecond
	return tn
}

// newTestClient returns a client routed through an isolated transport so
// tests never share state with Shared or with each other.
func newTestClient(tn tuning) (*http.Client, *Transport) {
	tr := New(http.DefaultTransport)
	tr.tune = tn
	return &http.Client{Transport: tr}, tr
}

// captureEvents installs an event hook for the test and returns a reader.
func captureEvents(t *testing.T) func() []Event {
	t.Helper()
	var mu sync.Mutex
	var events []Event
	SetEventHook(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	})
	t.Cleanup(func() { SetEventHook(nil) })
	return func() []Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]Event(nil), events...)
	}
}

// TestBlockedGETIsRetriedAndRecovers checks that a 429 on an idempotent
// request is retried after the host pauses, and that the host's concurrency
// was reduced by the block.
func TestBlockedGETIsRetriedAndRecovers(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The canary path is always a plain 404 so it never counts as a block.
		if strings.HasPrefix(r.URL.Path, "/aperture-canary-") {
			http.NotFound(w, r)
			return
		}
		// The first two real requests are rate limited, the third succeeds.
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client, tr := newTestClient(fastTuning())
	resp, err := client.Get(srv.URL + "/page")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retries", resp.StatusCode)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("real requests = %d, want 3 (two blocked + one success)", got)
	}
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Limit >= DefaultConcurrency {
		t.Errorf("limit after blocks = %+v, want reduced below %d", snap, DefaultConcurrency)
	}
}

// TestNonIdempotentBlockIsNotRetried checks that a POST hit by a 429 is
// returned to the caller once, never resent.
func TestNonIdempotentBlockIsNotRetried(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/aperture-canary-") {
			http.NotFound(w, r)
			return
		}
		posts.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, _ := newTestClient(fastTuning())
	resp, err := client.Post(srv.URL+"/submit", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 returned unchanged", resp.StatusCode)
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("POST sent %d times, want exactly 1", got)
	}
}

// TestRepeatedBlocksTripBreakerThenCoolDown checks the escalation ladder:
// repeated blocks open the breaker, further trips cool the host down, and
// requests during the cooldown fail fast without touching the network.
func TestRepeatedBlocksTripBreakerThenCoolDown(t *testing.T) {
	events := captureEvents(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/aperture-canary-") {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	tn := fastTuning()
	tn.breakerThreshold = 2
	tn.hostBlockTrips = 1
	client, _ := newTestClient(tn)

	// Keep requesting until the host refuses outright.
	var sawBlockedHost bool
	for i := 0; i < 20 && !sawBlockedHost; i++ {
		resp, err := client.Get(srv.URL + "/x")
		if err != nil {
			if errors.Is(err, ErrHostBlocked) {
				sawBlockedHost = true
			}
			continue
		}
		resp.Body.Close()
	}
	if !sawBlockedHost {
		t.Fatal("host was never put into cooldown")
	}

	// During cooldown, no request should reach the server.
	before := hits.Load()
	if _, err := client.Get(srv.URL + "/y"); !errors.Is(err, ErrHostBlocked) {
		t.Errorf("request during cooldown error = %v, want ErrHostBlocked", err)
	}
	if hits.Load() != before {
		t.Errorf("server saw %d requests during cooldown, want 0", hits.Load()-before)
	}

	kinds := map[string]bool{}
	for _, e := range events() {
		kinds[e.Kind] = true
	}
	for _, want := range []string{"throttled", "breaker-open", "host-blocked"} {
		if !kinds[want] {
			t.Errorf("missing %q event; got %v", want, kinds)
		}
	}
}

// TestPolicyCapsConcurrencyPerHost checks that the per-host ceiling from the
// request context is never exceeded, even with many concurrent requests.
func TestPolicyCapsConcurrencyPerHost(t *testing.T) {
	var inFlight, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/aperture-canary-") {
			http.NotFound(w, r)
			return
		}
		now := inFlight.Add(1)
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		inFlight.Add(-1)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client, _ := newTestClient(fastTuning())
	ctx := WithPolicy(context.Background(), Policy{MaxConcurrency: 2})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/c", nil)
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if got := peak.Load(); got > 2 {
		t.Errorf("peak concurrency = %d, want <= 2", got)
	}
}

// TestDriftFlagsResponsesAsSuspect checks that when the host starts serving a
// different page for the canary (a challenge or decoy), responses are tagged
// with the suspect header and a drift event is emitted.
func TestDriftFlagsResponsesAsSuspect(t *testing.T) {
	events := captureEvents(t)
	var canaryHits atomic.Int32
	var changed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/aperture-canary-") {
			// The first canary is a 404; after the switch every canary is a
			// different 200 page, as a decoy or challenge would serve.
			canaryHits.Add(1)
			if !changed.Load() {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, "<html><title>Decoy</title>a completely different page body here</html>")
			return
		}
		io.WriteString(w, "normal page content")
	}))
	defer srv.Close()

	tn := fastTuning()
	tn.driftEvery = 2
	tn.rebaselineAfter = 100 // keep the baseline fixed so the flag persists
	client, _ := newTestClient(tn)

	// Establish the baseline and a few governed responses before the change.
	for i := 0; i < 2; i++ {
		resp, err := client.Get(srv.URL + "/a")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	changed.Store(true)
	// Enough governed responses to hit the next canary check.
	var suspect bool
	for i := 0; i < 6 && !suspect; i++ {
		resp, err := client.Get(srv.URL + "/a")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		suspect = resp.Header.Get(SuspectHeader) == "drift"
	}
	if !suspect {
		t.Fatal("responses were never tagged as suspect after the canary changed")
	}
	found := false
	for _, e := range events() {
		if e.Kind == "drift" {
			found = true
		}
	}
	if !found {
		t.Error("no drift event emitted")
	}
}

// TestWAFClassification checks that only pages with WAF or challenge markers
// count as blocks, and that ordinary 403 pages do not.
func TestWAFClassification(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		blocked bool
	}{
		{"plain 403 is not a block", http.StatusForbidden, "Forbidden", false},
		{"403 challenge page is a block", http.StatusForbidden, "<title>Just a moment...</title>", true},
		{"429 is always a block", http.StatusTooManyRequests, "slow down", true},
		{"503 with captcha is a block", http.StatusServiceUnavailable, "please solve the g-recaptcha", true},
		{"200 is never a block", http.StatusOK, "Just a moment...", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.status,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(tc.body)),
			}
			if got := classify(resp).blocked; got != tc.blocked {
				t.Errorf("blocked = %v, want %v", got, tc.blocked)
			}
			// The body must still be fully readable after classification.
			got, _ := io.ReadAll(resp.Body)
			if string(got) != tc.body {
				t.Errorf("body after classify = %q, want %q", got, tc.body)
			}
		})
	}
}

// TestParseRetryAfter checks seconds, dates, and rejects garbage.
func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("7"); got != 7*time.Second {
		t.Errorf("seconds form = %v, want 7s", got)
	}
	if got := parseRetryAfter("-3"); got != 0 {
		t.Errorf("negative = %v, want 0", got)
	}
	if got := parseRetryAfter("not a value"); got != 0 {
		t.Errorf("garbage = %v, want 0", got)
	}
	future := time.Now().Add(time.Minute).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 || got > time.Minute+time.Second {
		t.Errorf("date form = %v, want about 1m", got)
	}
}
