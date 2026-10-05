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
	"github.com/Indigo6415/Aperture/internal/ssrf"
	"github.com/Indigo6415/Aperture/internal/store"
)

// ssrfRequest is the request body for POST /api/ssrf/scan -- mirrors
// ssrf.Request field-for-field plus the credential/case wiring every other
// tool's request carries (see pwResetRequest).
type ssrfRequest struct {
	// RequestsPerSecond is the scan speed the Slow/Normal/Fast/Custom control sends; zero means scanRate's default.
	RequestsPerSecond float64           `json:"requestsPerSecond,omitempty"`
	URL               string            `json:"url"`
	Params            []string          `json:"params,omitempty"`
	MineParams        bool              `json:"mineParams,omitempty"`
	CredentialID      string            `json:"credentialId,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	CaseID            string            `json:"caseId,omitempty"`
	// AutoDiscover/RecursionDepth/MaxPages mirror ssrf.Request's own fields
	// of the same names -- see that type's doc comments.
	// NoKnownEndpoints turns off the product-specific endpoint probes; see
	// ssrf.Request.NoKnownEndpoints. They run by default.
	NoKnownEndpoints bool `json:"noKnownEndpoints,omitempty"`
	AutoDiscover     bool `json:"autoDiscover,omitempty"`
	RecursionDepth   int  `json:"recursionDepth,omitempty"`
	MaxPages         int  `json:"maxPages,omitempty"`
	// Callback optionally names a callback server the operator picked from
	// their own Callback picker (see collaborator.Ref) -- when set, the
	// OOB-callback module points every parameter at that one shared,
	// long-lived server (with a per-parameter Identifier) instead of
	// minting a fresh throwaway token per parameter.
	Callback *collaborator.Ref `json:"callback,omitempty"`
}

// ssrfTimeout bounds a full run: the cloud-metadata and internal-network
// modules each fire a burst of concurrent requests (bounded by
// requestTimeout per request), and the OOB-callback module adds its own
// fixed grace period on top of that -- see internal/ssrf's own constants.
// Padded beyond that base cost to also cover an AutoDiscover crawl, which
// (like internal/csrf's own crawler) fetches pages sequentially rather than
// concurrently, up to crawlMaxPagesCap of them.
const ssrfTimeout = 120 * time.Second

// handleSSRF validates the request, then registers an SSRF run and returns
// its scan ID -- the run itself starts once the client subscribes to
// /ws/scans/{id} and streams one check per (module, parameter) as it goes.
// The OOB-callback module is wired to this server's own collaborator
// listener (see handlers_collaborator.go) so a blind SSRF still gets
// confirmed even when nothing shows up in the target's own HTTP response.
func (s *Server) handleSSRF(w http.ResponseWriter, r *http.Request) {
	var req ssrfRequest
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
	oob := ssrf.OOBConfig{
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
		tool:    "ssrf",
		timeout: ssrfTimeout,
		run: func(ctx context.Context, rep scanprogress.Reporter) (scanOutcome, error) {
			resp, err := ssrf.Run(ctx, ssrf.Request{
				URL: req.URL, Params: req.Params, Headers: req.Headers,
				AutoDiscover: req.AutoDiscover, RecursionDepth: req.RecursionDepth, MaxPages: req.MaxPages,
				MineParams: req.MineParams, NoKnownEndpoints: req.NoKnownEndpoints,
				Progress: rep,
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
				summary = fmt.Sprintf("%d issue(s) found across %d check(s)", total, len(resp.Modules))
			}
			return scanOutcome{result: resp, severity: severity, summary: summary}, nil
		},
	})
}
