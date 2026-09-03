package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

func (s *Server) handleListFlows(w http.ResponseWriter, r *http.Request) {
	flows, err := s.store.ListFlows()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, flows)
}

func (s *Server) handleCreateFlow(w http.ResponseWriter, r *http.Request) {
	var f engine.Flow
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if f.ID == "" {
		f.ID = newID()
	}
	if f.Name == "" {
		f.Name = "Untitled flow"
	}
	if err := s.store.SaveFlow(f); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

func (s *Server) handleGetFlow(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.GetFlow(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) handleUpdateFlow(w http.ResponseWriter, r *http.Request) {
	var f engine.Flow
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f.ID = r.PathValue("id")
	if err := s.store.SaveFlow(f); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) handleDeleteFlow(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteFlow(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRunFlow starts a flow running in the background and returns
// immediately with the new run's id; clients stream progress over
// /ws/runs/{id} and/or poll /api/runs/{id}/findings.
func (s *Server) handleRunFlow(w http.ResponseWriter, r *http.Request) {
	flowID := r.PathValue("id")
	flow, err := s.store.GetFlow(flowID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	runID := newID()
	if err := s.store.CreateRun(runID, flowID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	go s.executeRun(flow, runID)

	writeJSON(w, http.StatusAccepted, map[string]string{"runId": runID})
}

func (s *Server) executeRun(flow engine.Flow, runID string) {
	ctx := context.Background()

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

	err := s.engine.Execute(ctx, flow, runID, onResult, onStatus)

	final := store.RunSucceeded
	errMsg := ""
	if err != nil {
		final = store.RunFailed
		errMsg = err.Error()
	}
	_ = s.store.FinishRun(runID, final, errMsg)
	s.hub.publish(runID, RunEvent{Type: "done", Status: engine.NodeStatus(final), Message: errMsg})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListRuns(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
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
