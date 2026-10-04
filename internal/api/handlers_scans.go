package api

import (
	"log"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/store"
)

// severityRank orders the info/low/medium/high/critical scale probescan's
// modules already use (see probescan.ModuleResult.Severity) so callers can
// compare two severities without a switch of their own. Anything
// unrecognized ranks as "info" -- the lowest, never-hides-a-worse-finding
// default.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// maxSeverity returns whichever of a/b ranks higher under severityRank.
func maxSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// handleListCaseScans returns every scan tool run persisted for a case (see
// store.SaveCaseScan), most recent first -- without each row's full raw
// result, matching store.ListCaseScans' own doc comment. An optional
// ?tool= query param narrows it to one tool's history, e.g. for a tab that
// only wants its own past runs.
func (s *Server) handleListCaseScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListCaseScans(r.PathValue("id"), r.URL.Query().Get("tool"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// handleGetCaseScan returns one persisted scan's full record, including its
// raw result payload -- used to restore a tool tab's results on reload and
// to open a past run from its "Scans" history tab (see store.GetCaseScan).
func (s *Server) handleGetCaseScan(w http.ResponseWriter, r *http.Request) {
	scan, err := s.store.GetCaseScan(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

// saveCaseScan is the shared tail end of handleProbeScan/handleJWTScan/
// handleSecretScan's persistence: best-effort, like screenshot capture and
// CVE lookup elsewhere in this package -- a scan the user explicitly ran
// already succeeded and has already been returned to them, so a failure to
// persist it for the case is logged nowhere but never turns into an error
// response for a request that's already done its job.
// id is the scan's own ID. Reusing it keeps the saved row and the request log
// (see withScanRecorder) under one identity, so a restored past scan can open
// its requests the same way a live one does.
func (s *Server) saveCaseScan(id, caseID, target, tool, severity, summary string, data []byte) {
	// Hits are recorded before the case check: a scan with no case still has a
	// request log, and its findings should still mark the requests behind them.
	if err := s.store.RecordHits(id, directScanNodeID, scanResultHits(data)); err != nil {
		log.Printf("api: record scan hits: %v", err)
	}
	if caseID == "" {
		return
	}
	cs := store.CaseScan{
		ID: id, CaseID: caseID, Target: target, Tool: tool,
		Severity: severity, Summary: summary, Data: string(data),
	}
	if err := s.store.SaveCaseScan(cs); err != nil {
		return
	}
}
