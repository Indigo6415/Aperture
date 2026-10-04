package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/corsscan"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// corsScanRequest is the request body for POST /api/corsscan/scan -- mirrors
// corsscan.Request field-for-field plus the credential/case wiring every
// other tool's request carries (see pwResetRequest).
type corsScanRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	Method            string            `json:"method,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	CaseID            string            `json:"caseId,omitempty"`
}

// corsScanTimeout bounds a full run: seven modules, all but one firing a
// small handful of requests each, all running concurrently -- generous
// mainly to absorb a slow target, not because any module is itself slow.
const corsScanTimeout = 45 * time.Second

// handleCORSScan runs internal/corsscan.Run against req.URL synchronously
// and returns the full result in one response -- same posture as
// handlePwReset.
func (s *Server) handleCORSScan(w http.ResponseWriter, r *http.Request) {
	var req corsScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	rps, err := scanRate(req.RequestsPerSecond)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
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

	s.queueScan(w, streamedScan{
		rps:     rps,
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "corsscan",
		timeout: corsScanTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := corsscan.Run(ctx, corsscan.Request{Progress: rep, URL: req.URL, Method: req.Method, Headers: req.Headers})
			if err != nil {
				return scanOutcome{}, err
			}

			severity := "info"
			total := 0
			for _, m := range resp.Modules {
				total += len(m.Findings)
				if len(m.Findings) > 0 {
					severity = maxSeverity(severity, m.Severity)
				}
			}
			summary := "no issues found"
			if total > 0 {
				summary = fmt.Sprintf("%d issue(s) found across %d check(s)", total, len(resp.Modules))
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
