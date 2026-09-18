package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Indigo6415/Aperture/internal/jwtscan"
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
	writeJSON(w, http.StatusOK, resp)
}
