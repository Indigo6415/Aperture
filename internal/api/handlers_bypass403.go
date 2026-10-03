package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/bypass403"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// bypass403Request is the request body for POST /api/bypass403/run.
type bypass403Request struct {
	URL string `json:"url"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) merged into Headers -- same shape as every
	// other tool's request.
	CredentialID string            `json:"credentialId,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	// CaseID optionally scopes this run to a case -- see
	// secretScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// bypass403Timeout bounds a full run: one baseline request plus ~30
// concurrent technique attempts against a single host, some of which (the
// HTTP/1.0 attempt, a slow WAF) can take the full per-request timeout on
// their own.
const bypass403Timeout = 60 * time.Second

// handleBypass403 runs internal/bypass403.Run against req.URL synchronously
// and returns the full result in one response -- there's no streaming here
// (unlike Probe): a run is one host, finishes in well under bypass403Timeout
// in practice, and every attempt is independent, so there's no meaningful
// "module finished" progress to report along the way.
func (s *Server) handleBypass403(w http.ResponseWriter, r *http.Request) {
	var req bypass403Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "bypass403",
		timeout: bypass403Timeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := bypass403.Run(ctx, req.URL, bypass403.Options{Headers: req.Headers, Progress: rep})
			if err != nil {
				return scanOutcome{}, err
			}

			severity := "info"
			bypassed := 0
			for _, a := range resp.Attempts {
				if a.Bypassed {
					bypassed++
					severity = "high"
				}
			}
			summary := fmt.Sprintf("%d bypass(es) found across %d attempt(s)", bypassed, len(resp.Attempts))
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
