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
	"github.com/Indigo6415/Aperture/internal/pathtraversal"
	"github.com/Indigo6415/Aperture/internal/scanprogress"
	"github.com/Indigo6415/Aperture/internal/store"
)

// pathTraversalRequest is the request body for POST /api/pathtraversal/scan.
// It mirrors pathtraversal.Request field-for-field, plus the credential and
// case wiring every other tool's request carries (see pwResetRequest).
type pathTraversalRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64 `json:"requestsPerSecond,omitempty"`
	URL               string  `json:"url"`
	// Method is GET or POST. Empty means POST when Body is set, GET otherwise.
	Method string `json:"method,omitempty"`
	// Body is an optional request body, tested per JSON string leaf or per
	// form-encoded field. See pathtraversal.Request.Body.
	Body           string            `json:"body,omitempty"`
	ContentType    string            `json:"contentType,omitempty"`
	Params         []string          `json:"params,omitempty"`
	CredentialID   string            `json:"credentialId,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	CaseID         string            `json:"caseId,omitempty"`
	RecursionDepth int               `json:"recursionDepth,omitempty"`
	MaxPages       int               `json:"maxPages,omitempty"`
	// Callback optionally names a callback server the operator picked from
	// their own Callback picker (see collaborator.Ref). When set, the callback
	// module points every probe at that one shared server, with a per-point
	// identifier, instead of minting a fresh token per point.
	Callback *collaborator.Ref `json:"callback,omitempty"`
}

// pathTraversalTimeout bounds a full run. Each point runs every module, and a
// module stops at its first read, so a large app with many points takes time
// even at the default rate.
const pathTraversalTimeout = 10 * time.Minute

// handlePathTraversal runs internal/pathtraversal.Run against req.URL and
// streams progress as a queued scan, the same as the other crawl-based scanners.
// The callback module is wired to this server's collaborator listener, as in
// SSRF and XXE, so a path the app fetches as a URL is confirmed even when
// nothing shows up in the response.
func (s *Server) handlePathTraversal(w http.ResponseWriter, r *http.Request) {
	var req pathTraversalRequest
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

	cfg := s.loadCollaboratorConfig()
	oob := pathtraversal.OOBConfig{
		Registry:        s.collab,
		CallbackBaseURL: s.collabCallbackBase(r),
		DNSDomain:       cfg.Domain,
	}
	if req.Callback != nil {
		oob.SharedToken = req.Callback.Token
		oob.SharedProvider = req.Callback.Provider
	}

	s.queueScan(w, streamedScan{
		rps:     rps,
		caseID:  req.CaseID,
		target:  req.URL,
		tool:    "pathtraversal",
		timeout: pathTraversalTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := pathtraversal.Run(ctx, pathtraversal.Request{
				Progress:       rep,
				URL:            req.URL,
				Method:         req.Method,
				Body:           req.Body,
				ContentType:    req.ContentType,
				Params:         req.Params,
				Headers:        req.Headers,
				RecursionDepth: req.RecursionDepth,
				MaxPages:       req.MaxPages,
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
				summary = fmt.Sprintf("%d file read(s) found across %d check(s) (%d page(s), %d point(s) tested)", total, len(resp.Modules), len(resp.PagesScanned), resp.PointsTested)
			}
			// Say when the callback module was skipped, so an empty result
			// isn't read as a clean one.
			if !resp.OOBEnabled {
				summary += "; URL-fetch callback not tested (no callback listener)"
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
