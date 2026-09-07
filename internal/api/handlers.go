package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/model"
	"github.com/Indigo6415/Aperture/internal/store"
)

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// executeRun drives one flow to completion, streaming findings/status over
// the run's hub channel and persisting the final status. Called for every
// scanner a scan starts (content discovery, subdomain bruteforce, vhost
// bruteforce) -- see runScan and handleScanContentDiscovery in
// handlers_scan.go, which build the flow and create the run row before
// calling this.
func (s *Server) executeRun(flow engine.Flow, runID string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.trackRunCancel(runID, cancel)
	defer func() {
		s.untrackRunCancel(runID)
		cancel()
	}()

	onResult := func(nodeID string, f model.Finding) {
		f.RunID = runID
		if err := s.store.SaveFinding(runID, nodeID, f); err != nil {
			// The run continues even if a single write fails; the finding
			// is still delivered live over the websocket.
			s.hub.publish(runID, RunEvent{Type: "status", NodeID: nodeID, Status: engine.StatusRunning, Message: "warning: failed to persist finding: " + err.Error()})
		}
		s.hub.publish(runID, RunEvent{Type: "finding", NodeID: nodeID, Finding: &f})
	}
	onStatus := func(nodeID string, status engine.NodeStatus, message string) {
		s.hub.publish(runID, RunEvent{Type: "status", NodeID: nodeID, Status: status, Message: message})
	}
	onProgress := func(nodeID string, done, total int) {
		s.hub.publish(runID, RunEvent{Type: "progress", NodeID: nodeID, Done: done, Total: total})
	}

	err := s.engine.Execute(ctx, flow, runID, onResult, onStatus, onProgress)

	final := store.RunSucceeded
	errMsg := ""
	if err != nil {
		if errors.Is(err, context.Canceled) {
			final = store.RunCancelled
		} else {
			final = store.RunFailed
			errMsg = err.Error()
		}
	}
	_ = s.store.FinishRun(runID, final, errMsg)
	s.hub.publish(runID, RunEvent{Type: "done", Status: engine.NodeStatus(final), Message: errMsg})

	if final == store.RunSucceeded {
		// A content-discovery run finishing successfully is the trigger for
		// an auto-kicked vuln-scan against its hits -- see maybeChainVulnScan
		// (handlers_scan.go), which no-ops for every other scanner kind.
		s.maybeChainVulnScan(runID)
		// Likewise, a port-scan run finishing is the trigger for an
		// auto-kicked service-profile (nmap -sV) run against the ports it
		// found open -- see maybeChainServiceProfile, which no-ops for
		// every other scanner kind.
		s.maybeChainServiceProfile(runID)
	}
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.store.GetRun(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("nodeId")
	findings, err := s.store.ListFindings(r.PathValue("id"), nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, findings)
}
