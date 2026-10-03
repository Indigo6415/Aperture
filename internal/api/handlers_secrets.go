package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/secretscan"
	"github.com/Indigo6415/Aperture/internal/store"
)

// secretScanRequest is the request body for POST /api/secrets/scan.
type secretScanRequest struct {
	URL                string            `json:"url"`
	RecursionDepth     int               `json:"recursionDepth,omitempty"`
	Entropy            bool              `json:"entropy,omitempty"`
	SecretFinderEngine bool              `json:"secretFinderEngine,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	// CredentialID optionally names a saved case credential (see
	// handlers_credentials.go) merged into Headers.
	CredentialID string `json:"credentialId,omitempty"`
	// CaseID optionally scopes this scan to a case -- see
	// probeScanRequest.CaseID's doc comment.
	CaseID string `json:"caseId,omitempty"`
}

// maxSecretScanRecursionDepth bounds how far a crawl can follow same-origin
// links -- secretscan.Run also caps total pages fetched regardless, but
// this keeps the depth parameter itself from being set to something absurd.
const maxSecretScanRecursionDepth = 3

// secretScanTimeout bounds one full crawl (every page and script it fetches
// combined) so an unresponsive target can't hang the request indefinitely --
// generous relative to jwtscan/probescan's own per-request timeouts since
// this handler can issue dozens of requests in sequence.
const secretScanTimeout = 45 * time.Second

// handleSecretScan runs a full Snitch-style secret scan (secretscan.Run)
// against req.URL synchronously and returns every match in one response --
// like handleJWTScan, this is fast enough (a bounded crawl) that streaming
// progress over the job hub would be more machinery than the feature needs.
func (s *Server) handleSecretScan(w http.ResponseWriter, r *http.Request) {
	var req secretScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
	}
	if req.RecursionDepth < 0 {
		req.RecursionDepth = 0
	}
	if req.RecursionDepth > maxSecretScanRecursionDepth {
		req.RecursionDepth = maxSecretScanRecursionDepth
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
		tool:    "secrets",
		timeout: secretScanTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := secretscan.Run(ctx, secretscan.Request{Progress: rep,
				URL:                req.URL,
				RecursionDepth:     req.RecursionDepth,
				Entropy:            req.Entropy,
				SecretFinderEngine: req.SecretFinderEngine,
				Headers:            req.Headers,
			})
			if err != nil {
				return scanOutcome{}, err
			}

			// Any matched secret is inherently a high-severity finding (a live
			// credential/key, not a theoretical weakness) -- unlike probe's
			// per-module severities, secretscan has no graded scale of its own
			// to roll up.
			severity := "info"
			if len(resp.Matches) > 0 {
				severity = "high"
			}
			summary := fmt.Sprintf("%d secret(s) across %d page(s)", len(resp.Matches), len(resp.PagesScanned))
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
