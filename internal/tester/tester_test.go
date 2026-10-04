package tester

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSendEchoesRequestAndReturnsResponse drives Send against a local server
// that reports back the method, a custom header, and the body it received, so
// the test checks what actually went over the wire.
func TestSendEchoesRequestAndReturnsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Got-Method", r.Method)
		w.Header().Set("X-Got-Token", r.Header.Get("X-Token"))
		w.WriteHeader(http.StatusTeapot)
		w.Write(body)
	}))
	defer srv.Close()

	resp := Send(context.Background(), Request{
		Method:  "post",
		URL:     srv.URL + "/echo",
		Headers: map[string]string{"X-Token": "abc123"},
		Body:    "hello body",
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
	if resp.Headers["X-Got-Method"] != "POST" {
		t.Errorf("method on the wire = %q, want POST (lower-case input must be upper-cased)", resp.Headers["X-Got-Method"])
	}
	if resp.Headers["X-Got-Token"] != "abc123" {
		t.Errorf("custom header not sent: got %q", resp.Headers["X-Got-Token"])
	}
	if resp.Body != "hello body" {
		t.Errorf("Body = %q, want the request body echoed back", resp.Body)
	}
}

// TestSendReportsTransportFailure checks that a request that never completes
// comes back as Error text on the response rather than as a Go error or panic.
func TestSendReportsTransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens on this port any more

	resp := Send(context.Background(), Request{Method: "GET", URL: url})
	if resp.Error == "" {
		t.Fatal("expected Error to be set for a refused connection")
	}
}
