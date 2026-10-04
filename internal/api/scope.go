package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Indigo6415/Aperture/internal/netgov"
	"github.com/Indigo6415/Aperture/internal/store"
)

// scopeFor loads and compiles caseID's scope rules for a run. A blank caseID or
// a case with no rules returns a nil Scope, which allows everything. A store or
// parse error is returned instead, so callers fail closed rather than run
// unscoped.
func (s *Server) scopeFor(caseID string) (*netgov.Scope, error) {
	if caseID == "" {
		return nil, nil
	}
	patterns, err := s.store.GetCaseScope(caseID)
	if err != nil {
		return nil, fmt.Errorf("load case scope: %w", err)
	}
	scope, err := netgov.NewScope(patterns)
	if err != nil {
		return nil, fmt.Errorf("saved case scope is invalid: %w", err)
	}
	return scope, nil
}

// targetHost extracts the host a target points at, so it can be checked before
// anything is started. It accepts a full URL, a bare host or host:port, or a
// path-bearing form. Anything containing whitespace or "@" (an email address,
// say) is not a host and returns "", meaning there is nothing to check here.
// netgov still enforces scope on every real request, so this is only an early,
// clearer refusal.
func targetHost(target string) string {
	t := strings.TrimSpace(target)
	if t == "" || strings.ContainsAny(t, " \t@") {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "//" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	return u.Host
}

// checkTargetsInScope returns an error naming the first target whose host is
// outside scope. A nil scope accepts everything.
func checkTargetsInScope(scope *netgov.Scope, targets ...string) error {
	for _, t := range targets {
		h := targetHost(t)
		if h != "" && !scope.Allows(h) {
			return fmt.Errorf("%s is outside this case's scope", h)
		}
	}
	return nil
}

// caseScopeBody is the wire shape for GET and PUT /api/cases/{id}/scope.
type caseScopeBody struct {
	Patterns []string `json:"patterns"`
}

// handleGetCaseScope returns the scope rules saved for a case. An empty list
// means the case is unrestricted.
func (s *Server) handleGetCaseScope(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, fmt.Errorf("case %s not found", caseID))
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	patterns, err := s.store.GetCaseScope(caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, caseScopeBody{Patterns: patterns})
}

// handleSetCaseScope replaces a case's scope rules. Every pattern is validated
// through netgov.NewScope first, so a typo is rejected here rather than
// silently allowing or blocking traffic later. Sending an empty list clears
// the scope.
func (s *Server) handleSetCaseScope(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	var body caseScopeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := netgov.NewScope(body.Patterns); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, fmt.Errorf("case %s not found", caseID))
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.SetCaseScope(caseID, body.Patterns); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	patterns, err := s.store.GetCaseScope(caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, caseScopeBody{Patterns: patterns})
}
