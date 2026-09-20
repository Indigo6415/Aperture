package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Indigo6415/Aperture/internal/store"
)

// addCredentialRequest is the request body for POST /api/cases/{id}/credentials.
type addCredentialRequest struct {
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookie  string            `json:"cookie,omitempty"`
	Notes   string            `json:"notes,omitempty"`
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListCredentials(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("id")
	if _, err := s.store.GetCase(caseID); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var req addCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}

	cred := store.Credential{ID: newID(), CaseID: caseID, Name: req.Name, Headers: req.Headers, Cookie: req.Cookie, Notes: req.Notes}
	if err := s.store.SaveCredential(cred); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	saved, err := s.store.GetCredential(cred.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.LogActivity(caseID, "credential_added", fmt.Sprintf("Saved credential %q", req.Name))
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cred, err := s.store.GetCredential(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.DeleteCredential(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.store.LogActivity(cred.CaseID, "credential_removed", fmt.Sprintf("Removed credential %q", cred.Name))
	w.WriteHeader(http.StatusNoContent)
}

// mergedCredentialHeaders returns a new headers map combining cred's saved
// headers (and its Cookie, folded in as a "Cookie" header) with existing --
// existing's values always win, so an explicit per-request header/cookie
// the caller typed overrides the vault rather than being silently replaced
// by it. existing may be nil.
func mergedCredentialHeaders(cred store.Credential, existing map[string]string) map[string]string {
	merged := map[string]string{}
	for k, v := range cred.Headers {
		merged[k] = v
	}
	if cred.Cookie != "" {
		merged["Cookie"] = cred.Cookie
	}
	for k, v := range existing {
		merged[k] = v
	}
	return merged
}
