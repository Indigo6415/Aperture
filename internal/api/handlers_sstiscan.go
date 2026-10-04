package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/sstiscan"
	"github.com/Indigo6415/Aperture/internal/store"
)

// sstiScanRequest is the request body for POST /api/sstiscan/scan -- mirrors
// sstiscan.Request field-for-field plus the credential/case wiring every
// other tool's request carries (see pwResetRequest).
type sstiScanRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	Params            []string          `json:"params,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	CaseID            string            `json:"caseId,omitempty"`
	RecursionDepth    int               `json:"recursionDepth,omitempty"`
	MaxPages          int               `json:"maxPages,omitempty"`
	// Callback optionally names a callback server the operator picked from
	// their own Callback picker (see collaborator.Ref) -- when set, the
	// out-of-band RCE module points every injection point at that one
	// shared, long-lived server (with a per-point Identifier) instead of
	// minting a fresh throwaway token per point.
	Callback *collaborator.Ref `json:"callback,omitempty"`
}

// sstiScanTimeout is generous for the same reason csrfScanTimeout/
// ssrfTimeout are: the crawl itself fetches pages sequentially (up to
// crawlMaxPagesCap of them), and each of the three check modules then fans
// out several payloads per discovered point, with the OOB module adding its
// own fixed grace period on top of that.
const sstiScanTimeout = 150 * time.Second

// handleSSTIScan runs internal/sstiscan.Run against req.URL synchronously
// and returns the full result in one response -- same posture as
// handleSSRF/handleCSRF. The OOB RCE module is wired to this server's own
// collaborator listener (see handlers_collaborator.go) so a fully blind
// SSTI still gets confirmed even when nothing shows up in the target's own
// HTTP response.
func (s *Server) handleSSTIScan(w http.ResponseWriter, r *http.Request) {
	var req sstiScanRequest
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

	oob := sstiscan.OOBConfig{
		Registry:        s.collab,
		CallbackBaseURL: s.collabCallbackBase(r),
	}
	if req.Callback != nil {
		oob.SharedToken = req.Callback.Token
		oob.SharedProvider = req.Callback.Provider
	}

	s.queueScan(w, streamedScan{
		rps:     rps,
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "sstiscan",
		timeout: sstiScanTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := sstiscan.Run(ctx, sstiscan.Request{Progress: rep,
				URL: req.URL, Params: req.Params, Headers: req.Headers,
				RecursionDepth: req.RecursionDepth, MaxPages: req.MaxPages,
			}, oob)
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
				summary = fmt.Sprintf("%d issue(s) found across %d check(s) (%d page(s), %d point(s) tested)", total, len(resp.Modules), len(resp.PagesScanned), resp.PointsTested)
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
