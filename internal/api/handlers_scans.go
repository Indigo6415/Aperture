package api

import (
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

// handleListCaseScans returns every Probe/JWT/Secret Scanner run persisted
// for a case (see store.SaveCaseScan), most recent first -- without each
// row's full raw result, matching store.ListCaseScans' own doc comment.
func (s *Server) handleListCaseScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListCaseScans(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// saveCaseScan is the shared tail end of handleProbeScan/handleJWTScan/
// handleSecretScan's persistence: best-effort, like screenshot capture and
// CVE lookup elsewhere in this package -- a scan the user explicitly ran
// already succeeded and has already been returned to them, so a failure to
// persist it for the case is logged nowhere but never turns into an error
// response for a request that's already done its job.
func (s *Server) saveCaseScan(caseID, target, tool, severity, summary string, data []byte) {
	if caseID == "" {
		return
	}
	cs := store.CaseScan{
		ID: newID(), CaseID: caseID, Target: target, Tool: tool,
		Severity: severity, Summary: summary, Data: string(data),
	}
	if err := s.store.SaveCaseScan(cs); err != nil {
		return
	}
	_ = s.store.LogActivity(caseID, "scan_saved", tool+" scan of "+target+": "+summary)
}
