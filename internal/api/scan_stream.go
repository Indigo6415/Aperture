package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
)

// streamedScanClaimTimeout bounds how long a registered-but-unclaimed scan
// (see queueScan/handleWatchScan) sits in pendingScans -- same reasoning as
// probeScanClaimTimeout: a frontend that never opens the WebSocket shouldn't
// leak its entry for the life of the process.
const streamedScanClaimTimeout = 30 * time.Second

// streamedScan is one registered scan waiting for its WebSocket subscriber.
// run does the actual work: it reports progress through the Reporter it's
// handed (see internal/scanprogress) and returns the outcome the browser's
// done event carries. tool/target/caseID drive the case-scan record saved
// once the run finishes, same as the synchronous handlers this replaces.
type streamedScan struct {
	caseID  string
	target  string
	tool    string
	timeout time.Duration
	run     func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error)
}

// scanOutcome is what a finished streamed scan hands back: the full result
// the browser receives on its done event, plus the severity/summary pair
// saveCaseScan persists alongside it.
type scanOutcome struct {
	result   any
	severity string
	summary  string
}

// scanStartResult is the immediate response to starting any streamed scan:
// the ID the client subscribes to over GET /ws/scans/{id}.
type scanStartResult struct {
	ScanID string `json:"scanId"`
}

// queueScan registers scan and immediately responds with its scan ID -- the
// scan itself doesn't start until the client subscribes (see
// handleWatchScan), for the same reason handleProbeScan defers its start:
// a fast scan could otherwise finish, and every progress event with it,
// before the WebSocket handshake completes.
func (s *Server) queueScan(w http.ResponseWriter, scan streamedScan) {
	scanID := newID()
	s.streamMu.Lock()
	s.pendingScans[scanID] = scan
	s.streamMu.Unlock()
	time.AfterFunc(streamedScanClaimTimeout, func() {
		s.streamMu.Lock()
		delete(s.pendingScans, scanID)
		s.streamMu.Unlock()
	})
	writeJSON(w, http.StatusAccepted, scanStartResult{ScanID: scanID})
}

// handleWatchScan claims a scan registered by queueScan (if it hasn't
// already been claimed or timed out) and starts it once this connection is
// subscribed, so every progress event reaches the client.
func (s *Server) handleWatchScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.streamMu.Lock()
	scan, ok := s.pendingScans[id]
	if ok {
		delete(s.pendingScans, id)
	}
	s.streamMu.Unlock()
	if !ok {
		http.Error(w, "unknown or already-claimed scan id", http.StatusNotFound)
		return
	}

	s.watchWithStart(w, r, id, func() { go s.runStreamedScan(id, scan) })
}

// runStreamedScan runs a claimed scan to completion, publishing every
// progress event to scanID's hub channel and then a terminal "done" event
// carrying the full result (or the failure). The run is detached from the
// WebSocket's own lifetime on purpose: a tab closed mid-scan doesn't throw
// away a run that's already spent its requests, and the result still lands
// in the case's saved scans.
func (s *Server) runStreamedScan(scanID string, scan streamedScan) {
	ctx, cancel := context.WithTimeout(context.Background(), scan.timeout)
	defer cancel()

	out, err := scan.run(ctx, hubReporter{hub: s.hub, scanID: scanID})
	if err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusFailed, Message: err.Error()})
		return
	}

	data, err := json.Marshal(out.result)
	if err != nil {
		s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusFailed, Message: err.Error()})
		return
	}
	s.hub.publish(scanID, RunEvent{Type: "done", Status: engine.StatusSucceeded, Result: data})
	s.saveCaseScan(scan.caseID, scan.target, scan.tool, out.severity, out.summary, data)
}

// hubReporter adapts scanprogress.Reporter onto one scan's hub channel: each
// call becomes one RunEvent the frontend's progress reducer understands
// ("plan", "checkStart", "checkDone", "phase").
type hubReporter struct {
	hub    *hub
	scanID string
}

// Plan publishes the checks a scan has just registered. An empty call is
// dropped rather than sent as a no-op event.
func (r hubReporter) Plan(checks ...scanprogress.Check) {
	if len(checks) == 0 {
		return
	}
	r.hub.publish(r.scanID, RunEvent{Type: "plan", Checks: checks})
}

// Start publishes that the check with id has begun running.
func (r hubReporter) Start(id string) {
	r.hub.publish(r.scanID, RunEvent{Type: "checkStart", CheckID: id})
}

// Done publishes that the check with id has finished, with its finding count
// and -- when the check itself errored -- the error text as Message.
func (r hubReporter) Done(id string, findings int, err error) {
	ev := RunEvent{Type: "checkDone", CheckID: id, Findings: findings}
	if err != nil {
		ev.Message = err.Error()
	}
	r.hub.publish(r.scanID, ev)
}

// Phase publishes a scan-wide status line.
func (r hubReporter) Phase(message string) {
	r.hub.publish(r.scanID, RunEvent{Type: "phase", Message: message})
}
