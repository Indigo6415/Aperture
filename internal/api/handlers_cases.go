package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Indigo6415/Aperture/internal/store"
)

type startCaseRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// handleStartCase creates a new, empty case -- just a name and description.
// Nothing runs as a result: targets are added and jobs launched as
// separate, explicit actions.
func (s *Server) handleStartCase(w http.ResponseWriter, r *http.Request) {
	var req startCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("case: name is required"))
		return
	}

	caseID := newID()
	if err := s.store.CreateCase(caseID, req.Name, req.Description); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"caseId": caseID})
}

// caseSummary is GET /api/cases's per-row response shape: the case record
// plus lightweight aggregates the case list uses to show more than a name
// and a timestamp.
type caseSummary struct {
	store.Case
	TargetCount  int  `json:"targetCount"`
	JobCount     int  `json:"jobCount"`
	FindingCount int  `json:"findingCount"`
	Running      bool `json:"running"`
}

func (s *Server) summarize(c store.Case) (caseSummary, error) {
	out := caseSummary{Case: c}

	targetCount, err := s.store.CaseTargetCount(c.ID)
	if err != nil {
		return out, err
	}
	out.TargetCount = targetCount

	jobCount, err := s.store.CaseJobCount(c.ID)
	if err != nil {
		return out, err
	}
	out.JobCount = jobCount

	findingCount, err := s.store.CaseFindingCount(c.ID)
	if err != nil {
		return out, err
	}
	out.FindingCount = findingCount

	running, err := s.store.CaseRunning(c.ID)
	if err != nil {
		return out, err
	}
	out.Running = running

	return out, nil
}

func (s *Server) handleListCases(w http.ResponseWriter, r *http.Request) {
	cases, err := s.store.ListCases()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]caseSummary, 0, len(cases))
	for _, c := range cases {
		summary, err := s.summarize(c)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		out = append(out, summary)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetCase(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetCase(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleDeleteCase(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteCase(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListCaseChecks returns every identify-job check recorded for a
// case, so a client reloading it (or one that missed some live events) can
// reconstruct the Identify tab.
func (s *Server) handleListCaseChecks(w http.ResponseWriter, r *http.Request) {
	checks, err := s.store.ListCaseChecks(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, checks)
}
