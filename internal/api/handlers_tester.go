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

	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/tester"
)

// testerSendRequest is the request body for POST /api/tester/send -- one
// field per part of the request the frontend's editor lets the user change
// (method/URL/headers/body), plus the redirect-following toggle.
type testerSendRequest struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	FollowRedirects bool              `json:"followRedirects,omitempty"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) merged into Headers -- an explicit header the
	// caller already typed wins over the vault's value for the same name.
	CredentialID string `json:"credentialId,omitempty"`
	// CaseID optionally scopes this send to a case: when set, the request
	// and its response are recorded to that case's scan history under tool
	// "tester" (see store.SaveCaseScan/ListCaseScans), the same generic
	// history every other scan tool persists to -- so a case's past Tester
	// sends show up in its "Scans" tab like any other tool's runs.
	CaseID string `json:"caseId,omitempty"`
}

// testerTimeout bounds the one request this handler sends -- see
// tester.requestTimeout's own doc comment for why it's generous relative to
// the automated scanners' per-probe timeouts.
const testerTimeout = 35 * time.Second

// testerScan is what's persisted to a case's scan history (store.CaseScan's
// Data payload) for one Tester send -- the request alongside the response,
// so reopening it from the "Scans" tab restores the whole exchange, not
// just the response.
type testerScan struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	Response *tester.Response  `json:"response"`
}

// handleTesterSend sends exactly one caller-specified HTTP request and
// returns the raw response (or a network-level failure as a
// tester.Response.Error field, not an HTTP error -- see tester.Send's doc
// comment). Synchronous, like handleJWTScan/handleSecretScan: it's one
// request, not a running job.
func (s *Server) handleTesterSend(w http.ResponseWriter, r *http.Request) {
	var req testerSendRequest
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
	req.Headers = s.applyDomainCookie(req.CaseID, req.URL, req.Headers)

	ctx, cancel := context.WithTimeout(r.Context(), testerTimeout)
	defer cancel()

	resp := tester.Send(ctx, tester.Request{
		Method:          req.Method,
		URL:             req.URL,
		Headers:         req.Headers,
		Body:            req.Body,
		FollowRedirects: req.FollowRedirects,
	})

	if req.CaseID != "" {
		method := req.Method
		if method == "" {
			method = http.MethodGet
		}
		severity := "info"
		summary := fmt.Sprintf("%s -- request failed: %s", method, resp.Error)
		if resp.Error == "" {
			severity = severityForStatus(resp.StatusCode)
			summary = fmt.Sprintf("%s -> HTTP %d", method, resp.StatusCode)
		}
		scan := testerScan{Method: method, URL: req.URL, Headers: req.Headers, Body: req.Body, Response: resp}
		if data, err := json.Marshal(scan); err == nil {
			s.saveCaseScan(req.CaseID, req.URL, "tester", severity, summary, data)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// severityForStatus gives a Tester send's persisted history entry a
// severity consistent with the info/low/medium/high/critical scale every
// other scan tool's history uses -- a manual send isn't itself a
// vulnerability finding, so this is deliberately mild: it only ever ranks
// "low", just enough for a 4xx/5xx response to stand out from a clean 2xx/
// 3xx one in the case-wide scan list, never as loud as an actual scanner's
// own severity judgment.
func severityForStatus(code int) string {
	if code >= 400 {
		return "low"
	}
	return "info"
}
