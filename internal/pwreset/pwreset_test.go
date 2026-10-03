package pwreset

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// resetRequest is a minimal POST form request for the reset endpoint at url.
func resetRequest(url string) Request {
	return Request{URL: url, Method: "POST", ContentType: "form", IdentifierField: "email", KnownIdentifier: "alice@example.test"}
}

// TestRateLimitRecordsSampleSize checks that an endpoint with no throttling
// produces a finding that states how many requests it actually sent, so the
// claim is only as strong as the sample.
func TestRateLimitRecordsSampleSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "If that account exists, an email was sent.")
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)
	findings := runRateLimitModule(context.Background(), &http.Client{Timeout: 5 * time.Second}, target, resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	want := fmt.Sprintf("No throttling seen across %d rapid requests", rateLimitBurst)
	if findings[0].Label != want {
		t.Errorf("label = %q, want %q", findings[0].Label, want)
	}
	if findings[0].Confidence != ConfidenceLikely {
		t.Errorf("confidence = %q, want likely", findings[0].Confidence)
	}
}

// TestRateLimitStopsAtFirstThrottle checks that a limiter that trips is reported
// as a control, not as a missing one, and that the waves stop early.
func TestRateLimitStopsAtFirstThrottle(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) > 5 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)
	findings := runRateLimitModule(context.Background(), &http.Client{Timeout: 5 * time.Second}, target, resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 0 {
		t.Errorf("throttled endpoint reported as unthrottled: %+v", findings)
	}
	if got := n.Load(); int(got) >= rateLimitBurst {
		t.Errorf("sent %d requests; the first throttled wave should have stopped the run early", got)
	}
}

// TestEnumerationReportsCompleteSeparation checks that a real, consistent
// difference between known and unknown accounts is reported.
func TestEnumerationReportsCompleteSeparation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "alice") {
			fmt.Fprint(w, "An email was sent to the address on file for this account, please check your inbox.")
			return
		}
		fmt.Fprint(w, "No account matches that address.")
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)
	findings := runEnumerationModule(context.Background(), &http.Client{Timeout: 5 * time.Second}, target, resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one enumeration finding", findings)
	}
	if !strings.Contains(findings[0].Detail, "size differs") {
		t.Errorf("detail does not name the size difference: %s", findings[0].Detail)
	}
}

// TestEnumerationIgnoresOverlappingNoise checks the false-positive case: when
// the two groups overlap, which is what ordinary jitter looks like, nothing is
// reported. The sizes here do not depend on which identifier was sent.
func TestEnumerationIgnoresOverlappingNoise(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Alternating sizes independent of the identifier: an unrelated page
		// that varies on each request.
		size := 100 + int(n.Add(1)%7)*10
		fmt.Fprint(w, strings.Repeat("x", size))
	}))
	defer srv.Close()

	target, _ := url.Parse(srv.URL)
	findings := runEnumerationModule(context.Background(), &http.Client{Timeout: 5 * time.Second}, target, resetRequest(srv.URL), "nobody@example.test", nil)
	if len(findings) != 0 {
		t.Errorf("overlapping noise reported as enumeration: %+v", findings)
	}
}

// TestSeparatedAndMedian checks the statistics the enumeration check relies on.
func TestSeparatedAndMedian(t *testing.T) {
	if !separated([]float64{5, 6, 7}, []float64{1, 2, 3}) {
		t.Error("disjoint groups were not separated")
	}
	if separated([]float64{1, 5, 9}, []float64{4, 6}) {
		t.Error("overlapping groups were reported as separated")
	}
	if got := median([]float64{3, 1, 2}); got != 2 {
		t.Errorf("median odd = %v, want 2", got)
	}
	if got := median([]float64{1, 2, 3, 4}); got != 2.5 {
		t.Errorf("median even = %v, want 2.5", got)
	}
}
