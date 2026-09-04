package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/store"
)

// trackScanCancel/untrackScanCancel register the cancel func for a scan's
// apex recon phase (see runScan in handlers_scan.go) so handleCancelScan can
// stop it on demand. Only one recon phase is ever in flight per scan at a
// time, so the latest registration simply replaces any earlier one.
func (s *Server) trackScanCancel(scanID string, cancel context.CancelFunc) {
	s.cancelMu.Lock()
	s.scanCancels[scanID] = cancel
	s.cancelMu.Unlock()
}

func (s *Server) untrackScanCancel(scanID string) {
	s.cancelMu.Lock()
	delete(s.scanCancels, scanID)
	s.cancelMu.Unlock()
}

// trackRunCancel/untrackRunCancel do the same for one scanner run (see
// executeRun in handlers.go).
func (s *Server) trackRunCancel(runID string, cancel context.CancelFunc) {
	s.cancelMu.Lock()
	s.runCancels[runID] = cancel
	s.cancelMu.Unlock()
}

func (s *Server) untrackRunCancel(runID string) {
	s.cancelMu.Lock()
	delete(s.runCancels, runID)
	s.cancelMu.Unlock()
}

// handleCancelScan stops a scan in progress: it cancels the apex recon
// phase if it's still running, then cancels every one of the scan's scanner
// runs (content discovery, subdomain bruteforce, vhost bruteforce) that
// hasn't finished yet. Cancelling a run kills its subprocess (ffuf/
// feroxbuster run via exec.CommandContext) and the run/scanner ends up
// recorded as store.RunCancelled -- see executeRun. A scan with nothing
// running is a no-op rather than an error, so the client can call this
// freely without first checking status.
func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	if _, err := s.store.GetScan(scanID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.cancelMu.Lock()
	if cancel, ok := s.scanCancels[scanID]; ok {
		cancel()
	}
	s.cancelMu.Unlock()

	runs, err := s.store.ListScanRuns(scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.cancelMu.Lock()
	for _, run := range runs {
		if cancel, ok := s.runCancels[run.RunID]; ok {
			cancel()
		}
	}
	s.cancelMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}
