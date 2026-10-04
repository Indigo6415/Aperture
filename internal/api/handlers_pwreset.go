package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/pwreset"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// pwResetRequest is the request body for POST /api/pwreset/scan. It mirrors
// pwreset.Request field-for-field, plus the credential/case wiring every
// other tool's request carries (see bypass403Request).
type pwResetRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	Method            string            `json:"method,omitempty"`
	ContentType       string            `json:"contentType,omitempty"`
	IdentifierField   string            `json:"identifierField,omitempty"`
	KnownIdentifier   string            `json:"knownIdentifier,omitempty"`
	UnknownIdentifier string            `json:"unknownIdentifier,omitempty"`
	ExtraFields       map[string]string `json:"extraFields,omitempty"`
	FormURL           string            `json:"formUrl,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	CaseID            string            `json:"caseId,omitempty"`
}

// pwResetTimeout bounds a full run: one baseline request plus several check
// modules' own request batches (the rate-limit burst and the host-header
// techniques both fire concurrently, but the sequential enumeration samples
// are the slowest single path) against one endpoint.
const pwResetTimeout = 60 * time.Second

// handlePwReset runs internal/pwreset.Run against req.URL synchronously and
// returns the full result in one response -- same posture as
// handleBypass403: one endpoint, finishes well under pwResetTimeout in
// practice, no meaningful "module finished" progress worth streaming.
func (s *Server) handlePwReset(w http.ResponseWriter, r *http.Request) {
	var req pwResetRequest
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
		tool:    "pwreset",
		timeout: pwResetTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := pwreset.Run(ctx, pwreset.Request{Progress: rep,
				URL: req.URL, Method: req.Method, ContentType: req.ContentType,
				IdentifierField: req.IdentifierField, KnownIdentifier: req.KnownIdentifier, UnknownIdentifier: req.UnknownIdentifier,
				ExtraFields: req.ExtraFields, FormURL: req.FormURL, Headers: req.Headers,
			})
			if err != nil {
				return scanOutcome{}, err
			}

			severity := "info"
			total := 0
			// A module's severity only counts toward the case-scan summary when
			// it actually found something -- an empty "checked, nothing found"
			// module shouldn't drag a clean scan's badge up to its category's
			// worst-case severity.
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
