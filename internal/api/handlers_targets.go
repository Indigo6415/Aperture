package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/store"
)

type addTargetRequest struct {
	Value string `json:"value"`
	Kind  string `json:"kind,omitempty"`
	Notes string `json:"notes,omitempty"`
}

func (s *Server) handleAddTarget(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req addTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, errors.New("target: value is required"))
		return
	}

	if err := s.store.AddTarget(store.Target{ID: newID(), CaseID: caseID, Value: req.Value, Kind: req.Kind, Notes: req.Notes}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	t, err := s.store.GetTargetByValue(caseID, req.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.LogActivity(caseID, "target_added", fmt.Sprintf("Added target %q", req.Value))
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.ListTargets(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

type promoteTargetsRequest struct {
	JobID  string   `json:"jobId"`
	Values []string `json:"values"`
}

// handlePromoteTargets is how a tool's results become case targets: given a
// job that belongs to this case and a set of values derived from its
// selected result rows (client-side -- see ResultsTable's selection
// column), it records each one as a target tagged with the job's tool as
// its source. AddTarget's UNIQUE(case_id, value) + INSERT OR IGNORE makes
// re-promoting an already-known value a harmless no-op rather than a
// duplicate row, so the client doesn't need to track what's already been
// promoted.
func (s *Server) handlePromoteTargets(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var req promoteTargetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Values) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("target: at least one value is required"))
		return
	}

	job, err := s.store.GetJob(req.JobID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if job.CaseID != caseID {
		writeError(w, http.StatusBadRequest, errors.New("target: job does not belong to this case"))
		return
	}

	out := make([]store.Target, 0, len(req.Values))
	for _, value := range req.Values {
		if value == "" {
			continue
		}
		if err := s.store.AddTarget(store.Target{
			ID: newID(), CaseID: caseID, Value: value, SourceTool: job.Tool, SourceJobID: job.ID,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		t, err := s.store.GetTargetByValue(caseID, value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, t)
	}

	if len(out) > 0 {
		_ = s.store.LogActivity(caseID, "target_promoted", fmt.Sprintf("Promoted %d target(s) from job %s (%s)", len(out), job.ID, job.Tool))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// Fetched first (rather than just DELETE-ing blind, like most other
	// delete handlers) purely so the activity log entry can name the
	// case/value -- the route itself only carries the target's own id.
	t, err := s.store.GetTargetByID(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.DeleteTarget(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.LogActivity(t.CaseID, "target_removed", fmt.Sprintf("Removed target %q", t.Value))
	w.WriteHeader(http.StatusNoContent)
}
