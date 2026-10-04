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

// trackScanCancel/untrackScanCancel register the cancel func for one streamed
// scan (any scanner whose run reports progress over /ws/scans, /ws/probe,
// /ws/domainscan or /ws/apienum) so handleCancelScan can stop it on demand.
// Scan IDs are their own namespace, separate from job IDs in jobCancels.
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

// handleCancelScan stops one running streamed scan. The run's context is
// cancelled, so its in-flight requests are aborted and the run publishes a
// "done" event with status cancelled (see publishScanStopped) rather than a
// result. Like handleCancelJob, a scan that isn't running is a no-op, so the
// client can call this without checking whether the scan is still going.
func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	s.cancelMu.Lock()
	cancel, ok := s.scanCancels[scanID]
	s.cancelMu.Unlock()
	if ok {
		cancel()
	} else {
		// Not running yet: its start request was answered but its WebSocket hasn't
		// claimed it. Dropping the pending entry keeps the claim from starting it.
		s.dropPendingScan(scanID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// dropPendingScan removes a scan that was registered but never claimed, from
// whichever of the per-scanner pending registries holds it. Each registry has
// its own lock, so each is checked separately.
func (s *Server) dropPendingScan(scanID string) {
	s.streamMu.Lock()
	delete(s.pendingScans, scanID)
	s.streamMu.Unlock()

	s.probeMu.Lock()
	delete(s.pendingProbeScans, scanID)
	s.probeMu.Unlock()

	s.domainScanMu.Lock()
	delete(s.pendingDomainScans, scanID)
	s.domainScanMu.Unlock()

	s.apiEnumMu.Lock()
	delete(s.pendingApiEnumScans, scanID)
	s.apiEnumMu.Unlock()
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
