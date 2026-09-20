package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/repeater"
	"github.com/Indigo6415/Aperture/internal/store"
)

// repeaterSendRequest is the request body for POST /api/repeater/send --
// one field per part of the request the frontend's editor lets the user
// change (method/URL/headers/body), plus the redirect-following toggle.
type repeaterSendRequest struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	FollowRedirects bool              `json:"followRedirects,omitempty"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) merged into Headers -- an explicit header
	// the caller already typed wins over the vault's value for the same
	// name.
	CredentialID string `json:"credentialId,omitempty"`
	// CaseID optionally scopes this send to a case: when set, the request
	// and its response are recorded to that case's Repeater history (see
	// store.SaveRepeaterEntry) instead of existing only in the sender's own
	// browser tab.
	CaseID string `json:"caseId,omitempty"`
}

// repeaterTimeout bounds the one request this handler sends -- see
// repeater.requestTimeout's own doc comment for why it's generous relative
// to the automated scanners' per-probe timeouts.
const repeaterTimeout = 35 * time.Second

// handleRepeaterSend sends exactly one caller-specified HTTP request and
// returns the raw response (or a network-level failure as a Response.Error
// field, not an HTTP error -- see repeater.Send's doc comment). Synchronous,
// like handleJWTScan/handleSecretScan: it's one request, not a running job.
func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	var req repeaterSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
	}
	parsed, err := url.ParseRequestURI(req.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url must be an absolute http(s) URL"))
		return
	}

	if req.CredentialID != "" {
		cred, err := s.store.GetCredential(req.CredentialID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("credential %s not found", req.CredentialID))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		req.Headers = mergedCredentialHeaders(cred, req.Headers)
	}

	ctx, cancel := context.WithTimeout(r.Context(), repeaterTimeout)
	defer cancel()

	resp := repeater.Send(ctx, repeater.Request{
		Method:          req.Method,
		URL:             req.URL,
		Headers:         req.Headers,
		Body:            req.Body,
		FollowRedirects: req.FollowRedirects,
	})

	if req.CaseID != "" {
		if data, err := json.Marshal(resp); err == nil {
			entry := store.RepeaterEntry{
				ID: newID(), CaseID: req.CaseID, Method: req.Method, URL: req.URL,
				RequestHeaders: req.Headers, RequestBody: req.Body, Response: string(data),
			}
			if req.Method == "" {
				entry.Method = "GET"
			}
			_ = s.store.SaveRepeaterEntry(entry)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// repeaterEntryResponse is store.RepeaterEntry reshaped for the wire:
// Response is embedded as raw JSON rather than store.RepeaterEntry's own
// opaque string field -- same reasoning as handlers_templates.go's
// jobTemplateResponse.
type repeaterEntryResponse struct {
	ID             string            `json:"id"`
	CaseID         string            `json:"caseId"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	RequestHeaders map[string]string `json:"requestHeaders,omitempty"`
	RequestBody    string            `json:"requestBody,omitempty"`
	Response       json.RawMessage   `json:"response"`
	CreatedAt      time.Time         `json:"createdAt"`
}

// handleListRepeaterHistory returns a case's Repeater history, most recent
// first (see store.ListRepeaterHistory).
func (s *Server) handleListRepeaterHistory(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListRepeaterHistory(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resp := make([]repeaterEntryResponse, len(entries))
	for i, e := range entries {
		resp[i] = repeaterEntryResponse{
			ID: e.ID, CaseID: e.CaseID, Method: e.Method, URL: e.URL,
			RequestHeaders: e.RequestHeaders, RequestBody: e.RequestBody,
			Response: json.RawMessage(e.Response), CreatedAt: e.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteRepeaterHistoryEntry(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRepeaterEntry(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
