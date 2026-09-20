package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Indigo6415/Aperture/internal/jwtscan"
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// jwtScanRequest is the request body for POST /api/jwt/scan -- one field
// per input JWTear's CLI takes as a flag. Wordlist and ExtraSecrets are
// both optional and additive: Wordlist names an existing project wordlist
// (see internal/wordlists) to draw candidate secrets from, ExtraSecrets is
// a newline-delimited list pasted directly into the form.
type jwtScanRequest struct {
	URL          string            `json:"url"`
	Token        string            `json:"token"`
	Method       string            `json:"method,omitempty"`
	Cookie       string            `json:"cookie,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	PubKeyPEM    string            `json:"pubKeyPem,omitempty"`
	Wordlist     string            `json:"wordlist,omitempty"`
	ExtraSecrets string            `json:"extraSecrets,omitempty"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go): its headers are merged into Headers, and
	// its cookie fills Cookie when that's left empty.
	CredentialID string `json:"credentialId,omitempty"`
	// CaseID optionally scopes this scan to a case -- see
	// probeScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// handleJWTScan runs a full JWT misconfiguration scan (jwtscan.RunScan)
// against req.URL using req.Token, synchronously, and returns every test's
// result in one response -- unlike the engine-backed jobs this is fast
// enough (a bounded number of sequential HTTP requests) that streaming
// progress over the job hub would be more machinery than the feature needs.
func (s *Server) handleJWTScan(w http.ResponseWriter, r *http.Request) {
	var req jwtScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	req.Token = strings.TrimSpace(req.Token)
	if req.URL == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url and token are required"))
		return
	}

	// Note: req.Cookie names the cookie the token under test rides in
	// (see jwtscan.probe), not a raw cookie header value -- so a vault
	// credential's Cookie value is only meaningful merged into Headers
	// (e.g. a session cookie needed just to reach the endpoint), never
	// into req.Cookie itself.
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

	var extraSecrets []string
	if req.Wordlist != "" {
		lines, err := wordlists.ReadLines(s.wordlistsDir, req.Wordlist)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		extraSecrets = append(extraSecrets, lines...)
	}
	for _, line := range strings.Split(req.ExtraSecrets, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			extraSecrets = append(extraSecrets, line)
		}
	}

	resp, err := jwtscan.RunScan(jwtscan.ScanRequest{
		URL: req.URL, Token: req.Token, Method: req.Method, Cookie: req.Cookie,
		ExtraHeaders: req.Headers, PubKeyPEM: req.PubKeyPEM, ExtraSecrets: extraSecrets,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	if req.CaseID != "" {
		vulnerable := 0
		for _, t := range resp.Results {
			if t.Status == jwtscan.StatusVulnerable {
				vulnerable++
			}
		}
		severity := "info"
		if vulnerable > 0 {
			severity = "critical"
		}
		summary := fmt.Sprintf("%d/%d test(s) vulnerable", vulnerable, len(resp.Results))
		if data, err := json.Marshal(resp); err == nil {
			s.saveCaseScan(req.CaseID, req.URL, "jwt", severity, summary, data)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
