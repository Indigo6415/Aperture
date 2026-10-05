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
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/xss"
)

// xssScanRequest is the request body for POST /api/xss/scan -- mirrors
// xss.Request field-for-field plus the credential/case wiring every other
// tool's request carries (see pwResetRequest/sstiScanRequest).
type xssScanRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	Params            []string          `json:"params,omitempty"`
	MineParams        bool              `json:"mineParams,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	CaseID            string            `json:"caseId,omitempty"`
	RecursionDepth    int               `json:"recursionDepth,omitempty"`
	MaxPages          int               `json:"maxPages,omitempty"`
	// PayloadBudget caps how many payloads each injection point is tried with; zero means xss's default.
	PayloadBudget int `json:"payloadBudget,omitempty"`
	// Callback optionally names a callback server the operator picked from their
	// Callback picker (see collaborator.Ref). Blind XSS uses it; without it the
	// blind module mints a token per point on this instance's collaborator.
	Callback *collaborator.Ref `json:"callback,omitempty"`
}

// xssScanTimeout mirrors sstiScanTimeout's own reasoning: the crawl itself
// fetches pages sequentially (up to crawlMaxPagesCap of them), and then every
// discovered point is probed and tried with up to its payload budget.
const xssScanTimeout = 150 * time.Second

// handleXSSScan runs internal/xss.Run against req.URL synchronously and
// returns the full result in one response -- same posture as
// handlePwReset/handleSSRF/handleOpenRedirect.
func (s *Server) handleXSSScan(w http.ResponseWriter, r *http.Request) {
	var req xssScanRequest
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

	oob := xss.OOBConfig{
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
		tool:    "xss",
		timeout: xssScanTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := xss.Run(ctx, xss.Request{Progress: rep,
				URL: req.URL, Params: req.Params, MineParams: req.MineParams, Headers: req.Headers,
				RecursionDepth: req.RecursionDepth, MaxPages: req.MaxPages, PayloadBudget: req.PayloadBudget,
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
