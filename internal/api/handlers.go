package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

// executeToolJob drives one flow to completion, streaming findings/status
// over the job's hub channel and persisting the final status on both the
// run row (FinishRun, unchanged from before) and the job row (FinishJob,
// so ListCaseJobs' status reads correctly even without its LEFT JOIN).
// Called for every engine-backed job (feroxbuster/ffuf-subdomain/
// ffuf-vhost) -- see handleStartJob in handlers_jobs.go, which builds the
// flow and creates the job+run rows before calling this. Cancellation and
// event delivery are keyed by jobID, not runID, so the client only ever
// needs to know one ID per job. caseID is only used to log the job's
// completion to the case's activity timeline.
func (s *Server) executeToolJob(caseID string, flow engine.Flow, jobID, runID string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.trackJobCancel(jobID, cancel)
	defer func() {
		s.untrackJobCancel(jobID)
		cancel()
	}()

	onResult := func(nodeID string, f model.Finding) {
		f.RunID = runID
		if err := s.store.SaveFinding(runID, nodeID, f); err != nil {
			// The job continues even if a single write fails; the finding
			// is still delivered live over the websocket.
			s.hub.publish(jobID, RunEvent{Type: "status", NodeID: nodeID, Status: engine.StatusRunning, Message: "warning: failed to persist finding: " + err.Error()})
		}
		s.hub.publish(jobID, RunEvent{Type: "finding", NodeID: nodeID, Finding: &f})
	}
	onStatus := func(nodeID string, status engine.NodeStatus, message string) {
		s.hub.publish(jobID, RunEvent{Type: "status", NodeID: nodeID, Status: status, Message: message})
	}
	onProgress := func(nodeID string, done, total int) {
		s.hub.publish(jobID, RunEvent{Type: "progress", NodeID: nodeID, Done: done, Total: total})
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
	_ = s.store.FinishJob(jobID, final, errMsg)
	_ = s.store.LogActivity(caseID, "job_finished", fmt.Sprintf("Job %s finished: %s", jobID, final))
	s.hub.publish(jobID, RunEvent{Type: "done", Status: engine.NodeStatus(final), Message: errMsg})
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
