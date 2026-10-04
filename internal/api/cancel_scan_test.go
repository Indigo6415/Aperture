package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// TestCancelScanStopsRunningScan starts a streamed scan that blocks until its
// context ends, stops it through the cancel route, and checks the scan's
// terminal event reports it as stopped with no result.
func TestCancelScanStopsRunningScan(t *testing.T) {
	s := &Server{hub: newHub(), scanCancels: map[string]context.CancelFunc{}}
	const scanID = "scan-stop-test"

	events := s.hub.subscribe(scanID)
	defer s.hub.unsubscribe(scanID, events)

	// started is closed from inside run, which only runs after the scan has been
	// registered for cancellation, so the stop below can't race the registration.
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runStreamedScan(scanID, streamedScan{
			timeout: time.Minute,
			run: func(ctx context.Context, _ scanprogress.Reporter) (scanOutcome, error) {
				close(started)
				<-ctx.Done()
				return scanOutcome{}, ctx.Err()
			},
		})
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("scan never started")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scans/"+scanID+"/cancel", nil)
	req.SetPathValue("id", scanID)
	s.handleCancelScan(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cancel status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not return after cancel")
	}

	final := waitForDone(t, events)
	if final.Status != engine.StatusCancelled {
		t.Fatalf("done status = %q, want %q", final.Status, engine.StatusCancelled)
	}
	if final.Result != nil {
		t.Fatalf("stopped scan carried a result: %s", final.Result)
	}
}

// waitForDone reads events until the scan's terminal "done" event arrives and
// returns it. It fails the test if none arrives in time.
func waitForDone(t *testing.T, events <-chan RunEvent) RunEvent {
	t.Helper()
	// Each pass takes one event off the channel; a "done" event ends the wait.
	for {
		select {
		case ev := <-events:
			if ev.Type == "done" {
				return ev
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no done event arrived")
		}
	}
}

// TestCancelScanUnknownIDIsNoOp checks that stopping a scan that isn't running
// still answers 204, so the client can call it without checking first.
func TestCancelScanUnknownIDIsNoOp(t *testing.T) {
	s := &Server{scanCancels: map[string]context.CancelFunc{}}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/scans/nope/cancel", nil)
	req.SetPathValue("id", "nope")
	s.handleCancelScan(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cancel status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}
