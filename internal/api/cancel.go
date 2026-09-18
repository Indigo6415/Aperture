package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/store"
)

// trackJobCancel/untrackJobCancel register the cancel func for one job (an
// engine-backed job's executeToolJob, or an identify job's runIdentifyJob)
// so handleCancelJob can stop it on demand.
func (s *Server) trackJobCancel(jobID string, cancel context.CancelFunc) {
	s.cancelMu.Lock()
	s.jobCancels[jobID] = cancel
	s.cancelMu.Unlock()
}

func (s *Server) untrackJobCancel(jobID string) {
	s.cancelMu.Lock()
	delete(s.jobCancels, jobID)
	s.cancelMu.Unlock()
}

// handleCancelJob stops one running job. Cancelling an engine-backed job
// kills its subprocess (ffuf/feroxbuster run via exec.CommandContext) and it
// ends up recorded as store.RunCancelled -- see executeToolJob; cancelling
// an identify job stops recon.Scan between checks -- see runIdentifyJob. A
// job that isn't running is a no-op rather than an error, so the client can
// call this freely without first checking status.
func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	if _, err := s.store.GetJob(jobID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.cancelMu.Lock()
	cancel, ok := s.jobCancels[jobID]
	s.cancelMu.Unlock()
	if ok {
		cancel()
	}

	w.WriteHeader(http.StatusNoContent)
}
