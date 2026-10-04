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
	"github.com/Indigo6415/Aperture/internal/xxe"
)

// xxeRequest is the request body for POST /api/xxe/scan. It mirrors
// xxe.Request field-for-field, plus the credential and case wiring every
// other tool's request carries (see pwResetRequest).
type xxeRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64 `json:"requestsPerSecond,omitempty"`
	URL               string  `json:"url"`
	// Method is POST or PUT. Empty means POST.
	Method string `json:"method,omitempty"`
	// Body is an optional XML part whose every text value is tested. Empty
	// means a built-in probe document is used. See xxe.Request.Body.
	Body         string            `json:"body,omitempty"`
	ContentType  string            `json:"contentType,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	CredentialID string            `json:"credentialId,omitempty"`
	CaseID       string            `json:"caseId,omitempty"`
	// AutoDiscover/RecursionDepth/MaxPages mirror xxe.Request's own fields of
	// the same names -- see that type's doc comments.
	AutoDiscover   bool `json:"autoDiscover,omitempty"`
	RecursionDepth int  `json:"recursionDepth,omitempty"`
	MaxPages       int  `json:"maxPages,omitempty"`
	// Callback optionally names a callback server the operator picked from
	// their own Callback picker (see collaborator.Ref). When set, the blind
	// module points every probe at that one shared server, with a per-probe
	// identifier, instead of minting a fresh token per point.
	Callback *collaborator.Ref `json:"callback,omitempty"`
}

// xxeTimeout bounds a full run. Auto mode first crawls and probes the origin,
// then runs every module against each XML endpoint it finds, and each blind
// check waits out its own callback window, so it gets the same ceiling as
// path traversal's multi-endpoint runs.
const xxeTimeout = 10 * time.Minute

// handleXXE validates the request, then registers an XXE run and returns its
// scan ID. The run starts once the client subscribes to /ws/scans/{id}. The
// blind module is wired to this server's collaborator listener (see
// handlers_collaborator.go), the same as SSRF, so a blind XXE is confirmed
// even when nothing comes back in the response. A callback the operator picked
// replaces that listener's per-point tokens with one shared server.
func (s *Server) handleXXE(w http.ResponseWriter, r *http.Request) {
	var req xxeRequest
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
	oob := xxe.OOBConfig{
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
		tool:    "xxe",
		timeout: xxeTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := xxe.Run(ctx, xxe.Request{
				Progress:       rep,
				URL:            req.URL,
				Method:         req.Method,
				Body:           req.Body,
				ContentType:    req.ContentType,
				Headers:        req.Headers,
				AutoDiscover:   req.AutoDiscover,
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
			summary := xxeSummary(resp, total)
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}

// xxeSummary is the one-line result shown in scan history. It says when auto
// mode found nothing to test, and when the blind module was skipped, so an
// empty result isn't read as a clean one.
func xxeSummary(resp *xxe.Result, total int) string {
	if len(resp.Endpoints) == 0 {
		return "no XML-capable endpoints found"
	}
	summary := "no issues found"
	if total > 0 {
		summary = fmt.Sprintf("%d XXE issue(s) found across %d endpoint(s) (%d point(s) tested)", total, len(resp.Endpoints), resp.PointsTested)
	}
	if !resp.OOBEnabled {
		summary += "; blind XXE not tested (no callback listener)"
	}
	return summary
}
