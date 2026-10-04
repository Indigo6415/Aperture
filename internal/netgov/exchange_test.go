package netgov

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// collectExchanges returns a recorder plus a reader for what it captured.
func collectExchanges() (Recorder, func() []Exchange) {
	var mu sync.Mutex
	var got []Exchange
	rec := RecorderFunc(func(e Exchange) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, e)
	})
	return rec, func() []Exchange {
		mu.Lock()
		defer mu.Unlock()
		return append([]Exchange(nil), got...)
	}
}

// TestRecorderCapturesRequestAndResponse checks that a completed request is
// reported once the caller closes the body, with the bytes it actually read
// and the request and response rendered as the wire would show them.
func TestRecorderCapturesRequestAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		io.WriteString(w, "hello body")
	}))
	defer srv.Close()

	client, _ := newTestClient(fastTuning())
	rec, read := collectExchanges()
	req, _ := http.NewRequestWithContext(WithRecorder(context.Background(), rec), http.MethodGet, srv.URL+"/some/path?q=1", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello body" {
		t.Fatalf("caller body = %q, want the unmodified response", body)
	}

	got := read()
	if len(got) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(got))
	}
	ex := got[0]
	if ex.Method != http.MethodGet || ex.Status != http.StatusOK || ex.Size != int64(len("hello body")) {
		t.Errorf("exchange = method %q status %d size %d; want GET 200 %d", ex.Method, ex.Status, ex.Size, len("hello body"))
	}
	if !strings.HasPrefix(ex.RequestRaw, "GET /some/path?q=1 HTTP/1.1\n") {
		t.Errorf("RequestRaw missing request line:\n%s", ex.RequestRaw)
	}
	// net/http adds these on the wire without the caller setting them; the log
	// should show them too, or it doesn't match what was actually sent.
	if !strings.Contains(ex.RequestRaw, "User-Agent: Go-http-client/1.1\n") || !strings.Contains(ex.RequestRaw, "Accept-Encoding: gzip\n") {
		t.Errorf("RequestRaw missing transport-added headers:\n%s", ex.RequestRaw)
	}
	if !strings.Contains(ex.ResponseRaw, "X-Test: yes") || !strings.HasSuffix(ex.ResponseRaw, "hello body") {
		t.Errorf("ResponseRaw missing header or body:\n%s", ex.ResponseRaw)
	}
}

// TestRecorderCapturesFailedRequest checks that a request which was sent but
// never got a response is still logged, with its error and no status.
func TestRecorderCapturesFailedRequest(t *testing.T) {
	// Closing the listener before the request means nothing is accepting, so
	// the dial fails without the test depending on any external host.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	client, _ := newTestClient(fastTuning())
	rec, read := collectExchanges()
	req, _ := http.NewRequestWithContext(WithRecorder(context.Background(), rec), http.MethodGet, url, nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected the request to fail")
	}

	got := read()
	if len(got) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(got))
	}
	if got[0].Status != 0 || got[0].Error == "" {
		t.Errorf("failed exchange = status %d error %q; want status 0 with an error", got[0].Status, got[0].Error)
	}
}

// TestRecorderCapsCapturedBody checks that a body larger than the capture
// limit is cut off with a marker, while Size still reports the full length.
func TestRecorderCapsCapturedBody(t *testing.T) {
	big := strings.Repeat("a", maxCapturedBody+1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, big)
	}))
	defer srv.Close()

	client, _ := newTestClient(fastTuning())
	rec, read := collectExchanges()
	req, _ := http.NewRequestWithContext(WithRecorder(context.Background(), rec), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	ex := read()[0]
	if ex.Size != int64(len(big)) {
		t.Errorf("Size = %d, want full length %d", ex.Size, len(big))
	}
	if !strings.Contains(ex.ResponseRaw, "[... body truncated ...]") {
		t.Errorf("ResponseRaw should be marked truncated")
	}
	if len(ex.ResponseRaw) > maxCapturedBody+200 {
		t.Errorf("ResponseRaw is %d bytes, expected it capped near %d", len(ex.ResponseRaw), maxCapturedBody)
	}
}

// TestNoRecorderLeavesResponseAlone checks that a request on a plain context
// is not wrapped or recorded, so scans that don't ask for a log pay nothing.
func TestNoRecorderLeavesResponseAlone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "plain")
	}))
	defer srv.Close()

	client, _ := newTestClient(fastTuning())
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if _, ok := resp.Body.(*captureBody); ok {
		t.Fatal("response body was wrapped even though no recorder was set")
	}
}

// TestLimitRecorderForwardsOnlyTheCap checks that LimitRecorder passes exactly
// limit exchanges on, even when they arrive concurrently, and drops the rest.
func TestLimitRecorderForwardsOnlyTheCap(t *testing.T) {
	rec, read := collectExchanges()
	limited := LimitRecorder(rec, 10)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limited.Record(Exchange{Method: http.MethodGet})
		}()
	}
	wg.Wait()

	if got := len(read()); got != 10 {
		t.Errorf("forwarded %d exchanges, want exactly the cap of 10", got)
	}
}
